// GnuTLS networking, with a buffer and a separate sending thread
//
// Written by: Test_User <hax@andrewyu.org>
//
// This is free and unencumbered software released into the public
// domain.
//
// Anyone is free to copy, modify, publish, use, compile, sell, or
// distribute this software, either in source code form or as a compiled
// binary, for any purpose, commercial or non-commercial, and by any
// means.
//
// In jurisdictions that recognize copyright laws, the author or authors
// of this software dedicate any and all copyright interest in the
// software to the public domain. We make this dedication for the benefit
// of the public at large and to the detriment of our heirs and
// successors. We intend this dedication to be an overt act of
// relinquishment in perpetuity of all present and future rights to this
// software under copyright law.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
// OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <gnutls/gnutls.h>
#include <poll.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>

#include "../config.h"
#include "../general_network.h"
#include "../main.h"
#include "../mutex.h"
#include "gnutls_buffered.h"

struct gnutls_buffered_handle {
	gnutls_session_t session;
	MUTEX_TYPE mutex;
	int fd;
	char valid;
};

gnutls_certificate_credentials_t gnutls_buffered_cert_creds;

int init_gnutls_buffered_network(void) {
	if (gnutls_global_init() < 0)
		return 1;

	if (gnutls_certificate_allocate_credentials(&gnutls_buffered_cert_creds) != GNUTLS_E_SUCCESS)
		return 2;

	if (GNUTLS_USE_SYSTEM_TRUST && (gnutls_certificate_set_x509_system_trust(gnutls_buffered_cert_creds) < 0))
		return 3;

	if (GNUTLS_KEY_PATH && GNUTLS_CERT_PATH && gnutls_certificate_set_x509_key_file(gnutls_buffered_cert_creds, GNUTLS_CERT_PATH, GNUTLS_KEY_PATH, GNUTLS_X509_FMT_PEM) < 0)
		return 4;

	return 0;
}

int gnutls_buffered_send(void *handle, struct string msg) {
	if (msg.len == 0)
		return 0;

	struct gnutls_buffered_handle *gnutls_handle = handle;

	mutex_lock(&(gnutls_handle->mutex));

	if (!gnutls_handle->valid)
		goto gnutls_send_error_unlock;

	struct pollfd pollfd = {
		.fd = gnutls_handle->fd,
	};
	do {
		ssize_t gnutls_res;
		int poll_res;
		gnutls_res = gnutls_record_send(gnutls_handle->session, msg.data, msg.len);
		if (gnutls_res <= 0) {
			if (gnutls_res == GNUTLS_E_INTERRUPTED) {
				continue;
			} else if (gnutls_res == GNUTLS_E_AGAIN) {
				pollfd.events = POLLIN | POLLOUT;
				do {
					poll_res = poll(&pollfd, 1, 0);
				} while (poll_res < 0 && errno == EINTR);
				if (poll_res < 0)
					goto gnutls_send_error_unlock;

				if ((pollfd.revents & (POLLIN | POLLOUT)) == (POLLIN | POLLOUT))
					continue;
				else if (pollfd.revents & (~(POLLIN | POLLOUT)))
					goto gnutls_send_error_unlock;
				else
					pollfd.events = (pollfd.revents & (POLLIN | POLLOUT)) ^ (POLLIN | POLLOUT);
			} else {
				goto gnutls_send_error_unlock;
			}
		} else {
			break;
		}

		do {
			poll_res = poll(&pollfd, 1, PING_INTERVAL*1000);
		} while (poll_res < 0 && errno == EINTR);
		if (poll_res < 0)
			goto gnutls_send_error_unlock;
		if (poll_res == 0) // Timed out
			goto gnutls_send_error_unlock;
		if ((pollfd.revents & (POLLIN | POLLOUT)) == 0)
			goto gnutls_send_error_unlock;
	} while (1);

	mutex_unlock(&(gnutls_handle->mutex));
	return 0;

	gnutls_send_error_unlock:
	if (gnutls_handle->valid) {
		mutex_unlock(&(gnutls_handle->mutex));
		gnutls_buffered_shutdown(gnutls_handle);
	} else {
		mutex_unlock(&(gnutls_handle->mutex));
	}
	return 1;
}

size_t gnutls_buffered_recv(void *handle, char *data, size_t len, char *err) {
	struct gnutls_buffered_handle *gnutls_handle = handle;

	struct pollfd pollfd = {
		.fd = gnutls_handle->fd,
	};
	ssize_t gnutls_res;
	do {
		int poll_res;
		mutex_lock(&(gnutls_handle->mutex));
		if (!gnutls_handle->valid) {
			mutex_unlock(&(gnutls_handle->mutex));
			*err = 3;
			return 0;
		}
		do {
			gnutls_res = gnutls_record_recv(gnutls_handle->session, data, len);
		} while (gnutls_res == GNUTLS_E_INTERRUPTED);
		mutex_unlock(&(gnutls_handle->mutex));
		if (gnutls_res < 0) {
			if (gnutls_res == GNUTLS_E_AGAIN) {
				pollfd.events = POLLIN | POLLOUT;
				do {
					poll_res = poll(&pollfd, 1, 0);
				} while (poll_res < 0 && errno == EINTR);
				if (poll_res < 0) {
					*err = 3;
					return 0;
				}

				if ((pollfd.revents & (POLLIN | POLLOUT)) == (POLLIN | POLLOUT))
					continue;
				else
					pollfd.events = (pollfd.revents & (POLLIN | POLLOUT)) ^ (POLLIN | POLLOUT);
			} else {
				*err = 3;
				return 0;
			}
		} else if (gnutls_res == 0) {
			*err = 2;
			return 0;
		} else {
			break;
		}

		do {
			poll_res = poll(&pollfd, 1, PING_INTERVAL*1000);
		} while (poll_res < 0 && errno == EINTR);
		if (poll_res < 0) {
			*err = 3;
			return 0;
		} if (poll_res == 0) { // Timed out
			*err = 1;
			return 0;
		} if ((pollfd.revents & (POLLIN | POLLOUT)) == 0) {
			*err = 3;
			return 0;
		}
	} while (1);

	*err = 0;

	return (size_t)gnutls_res;
}

int gnutls_buffered_connect(void **handle, struct string address, struct string port, struct string *addr_out) {
	struct gnutls_buffered_handle *gnutls_handle;
	gnutls_handle = malloc(sizeof(*gnutls_handle));
	if (!gnutls_handle)
		return -1;

	*handle = gnutls_handle;

	mutex_init(&(gnutls_handle->mutex));

	struct sockaddr_storage sockaddr;
	socklen_t sockaddr_len;
	int family;
	if (resolve(address, port, (struct sockaddr*)&sockaddr, &sockaddr_len, &family) != 0)
		goto gnutls_connect_destroy_mutex;

	int fd = socket(family, SOCK_STREAM, IPPROTO_TCP);
	if (fd == -1)
		goto gnutls_connect_destroy_mutex;

	gnutls_handle->fd = fd;
	gnutls_handle->valid = 1;

	int res;
	do {
		res = connect(fd, (struct sockaddr*)&sockaddr, sockaddr_len);
	} while (res < 0 && errno == EINTR);
	if (res < 0)
		goto gnutls_connect_close;

	int flags = fcntl(fd, F_GETFL);
	if (flags == -1)
		goto gnutls_connect_close;
	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
		goto gnutls_connect_close;

	if (gnutls_init(&(gnutls_handle->session), GNUTLS_CLIENT | GNUTLS_NONBLOCK) != GNUTLS_E_SUCCESS)
		goto gnutls_connect_close;

	if (gnutls_server_name_set(gnutls_handle->session, GNUTLS_NAME_DNS, address.data, address.len) != GNUTLS_E_SUCCESS)
		goto gnutls_connect_deinit_session;

	if (gnutls_credentials_set(gnutls_handle->session, GNUTLS_CRD_CERTIFICATE, gnutls_buffered_cert_creds) != GNUTLS_E_SUCCESS)
		goto gnutls_connect_deinit_session;

	if (gnutls_set_default_priority(gnutls_handle->session) != GNUTLS_E_SUCCESS)
		goto gnutls_connect_deinit_session;

	gnutls_transport_set_int(gnutls_handle->session, fd);

	struct pollfd pollfd = {
		.fd = fd,
	};
	ssize_t gnutls_res;
	do {
		int poll_res;
		do {
			gnutls_res = gnutls_handshake(gnutls_handle->session);
		} while (res == GNUTLS_E_INTERRUPTED);
		if (gnutls_res < 0) {
			if (gnutls_res == GNUTLS_E_AGAIN) {
				pollfd.events = POLLIN | POLLOUT;
				do {
					poll_res = poll(&pollfd, 1, 0);
				} while (poll_res < 0 && errno == EINTR);
				if (poll_res < 0)
					goto gnutls_connect_deinit_session;

				if ((pollfd.revents & (POLLIN | POLLOUT)) == (POLLIN | POLLOUT))
					continue;
				else if (pollfd.revents & (~(POLLIN | POLLOUT)))
					goto gnutls_connect_deinit_session;
				else
					pollfd.events = pollfd.revents ^ (POLLIN | POLLOUT);
			}
		} else {
			break;
		}

		do {
			poll_res = poll(&pollfd, 1, PING_INTERVAL*1000);
		} while (poll_res < 0 && errno == EINTR);
		if (poll_res < 0)
			goto gnutls_connect_deinit_session;
		if (poll_res == 0) // Timed out
			goto gnutls_connect_deinit_session;
		if ((pollfd.revents & (POLLIN | POLLOUT)) == 0)
			goto gnutls_connect_deinit_session;
	} while (1);

	addr_out->data = malloc(sockaddr_len);
	if (!addr_out->data)
		goto gnutls_connect_deinit_session;

	memcpy(addr_out->data, &sockaddr, sockaddr_len);
	addr_out->len = sockaddr_len;

	return fd;

	gnutls_connect_deinit_session:
	gnutls_deinit(gnutls_handle->session);
	gnutls_connect_close:
	close(fd);
	gnutls_connect_destroy_mutex:
	mutex_destroy(&(gnutls_handle->mutex));
	free(gnutls_handle);

	return -1;
}

int gnutls_buffered_accept(int listen_fd, void **handle, struct string *addr) {
	if (!GNUTLS_CERT_PATH || !GNUTLS_KEY_PATH)
		return -1;

	struct sockaddr_storage address;
	socklen_t address_len = sizeof(address);

	int con_fd;
	do {
		con_fd = accept(listen_fd, (struct sockaddr*)&address, &address_len);
	} while (con_fd == -1 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK || errno == ENETDOWN || errno == EPROTO || errno == ENOPROTOOPT || errno == EHOSTDOWN || errno == ENONET || errno == EHOSTUNREACH || errno == EOPNOTSUPP || errno == ENETUNREACH));

	if (con_fd == -1)
		return -1;

	int flags = fcntl(con_fd, F_GETFL);
	if (flags == -1)
		goto gnutls_accept_close;
	if (fcntl(con_fd, F_SETFL, flags | O_NONBLOCK) == -1)
		goto gnutls_accept_close;

	struct gnutls_buffered_handle *gnutls_handle;
	gnutls_handle = malloc(sizeof(*gnutls_handle));
	if (!gnutls_handle)
		goto gnutls_accept_close;

	*handle = gnutls_handle;
	gnutls_handle->valid = 1;
	gnutls_handle->fd = con_fd;

	mutex_init(&(gnutls_handle->mutex));

	addr->data = malloc(address_len);
	if (addr->data == 0 && address_len != 0)
		goto gnutls_accept_destroy_mutex;

	memcpy(addr->data, &address, address_len);
	addr->len = address_len;

	if (gnutls_init(&(gnutls_handle->session), GNUTLS_SERVER | GNUTLS_NONBLOCK) != GNUTLS_E_SUCCESS)
		goto gnutls_accept_free_addr_data;

	if (gnutls_credentials_set(gnutls_handle->session, GNUTLS_CRD_CERTIFICATE, gnutls_buffered_cert_creds) != GNUTLS_E_SUCCESS)
		goto gnutls_accept_deinit_session;

	if (gnutls_set_default_priority(gnutls_handle->session) != GNUTLS_E_SUCCESS)
		goto gnutls_accept_deinit_session;

	gnutls_transport_set_int(gnutls_handle->session, con_fd);

	gnutls_handshake_set_timeout(gnutls_handle->session, PING_INTERVAL * 1000);
	gnutls_record_set_timeout(gnutls_handle->session, PING_INTERVAL * 1000);

	struct pollfd pollfd = {
		.fd = con_fd,
	};
	ssize_t gnutls_res;
	do {
		int poll_res;
		do {
			gnutls_res = gnutls_handshake(gnutls_handle->session);
		} while (gnutls_res == GNUTLS_E_INTERRUPTED);
		if (gnutls_res < 0) {
			if (gnutls_res == GNUTLS_E_AGAIN) {
				pollfd.events = POLLIN | POLLOUT;
				do {
					poll_res = poll(&pollfd, 1, 0);
				} while (poll_res < 0 && errno == EINTR);
				if (poll_res < 0)
					goto gnutls_accept_deinit_session;

				if ((pollfd.revents & (POLLIN | POLLOUT)) == (POLLIN | POLLOUT))
					continue;
				else if (pollfd.revents & (~(POLLIN | POLLOUT)))
					goto gnutls_accept_deinit_session;
				else
					pollfd.events = pollfd.revents ^ (POLLIN | POLLOUT);
			}
		} else {
			break;
		}

		do {
			poll_res = poll(&pollfd, 1, PING_INTERVAL*1000);
		} while (poll_res < 0 && errno == EINTR);
		if (poll_res < 0)
			goto gnutls_accept_deinit_session;
		if (poll_res == 0) // Timed out
			goto gnutls_accept_deinit_session;
		if ((pollfd.revents & (POLLIN | POLLOUT)) == 0)
			goto gnutls_accept_deinit_session;
	} while (1);

	return con_fd;

	gnutls_accept_deinit_session:
	gnutls_deinit(gnutls_handle->session);
	gnutls_accept_free_addr_data:
	free(addr->data);
	gnutls_accept_destroy_mutex:
	mutex_destroy(&(gnutls_handle->mutex));
	free(gnutls_handle);
	gnutls_accept_close:
	close(con_fd);
	return -1;
}

void gnutls_buffered_shutdown(void *handle) {
	struct gnutls_buffered_handle *gnutls_handle = handle;
	mutex_lock(&(gnutls_handle->mutex));
	shutdown(gnutls_handle->fd, SHUT_RDWR);
	gnutls_handle->valid = 0;
	mutex_unlock(&(gnutls_handle->mutex));
}

void gnutls_buffered_close(int fd, void *handle) {
	struct gnutls_buffered_handle *gnutls_handle = handle;
	mutex_destroy(&(gnutls_handle->mutex));
	gnutls_deinit(gnutls_handle->session);
	free(gnutls_handle);
	close(fd);
}
