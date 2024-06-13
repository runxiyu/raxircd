// One of the code files for HaxServ
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
#include <gnutls/gnutls.h>
#include <poll.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "config.h"
#include "general_network.h"
#include "gnutls_network.h"

struct gnutls_handle {
	gnutls_session_t session;
	pthread_mutex_t mutex;
	int fd;
	char valid;
};

gnutls_certificate_credentials_t gnutls_cert_creds;

int init_gnutls_network(void) {
	if (gnutls_global_init() < 0)
		return 1;

	if (gnutls_certificate_allocate_credentials(&gnutls_cert_creds) != GNUTLS_E_SUCCESS)
		return 2;

	if (GNUTLS_USE_SYSTEM_TRUST && (gnutls_certificate_set_x509_system_trust(gnutls_cert_creds) < 0))
		return 3;

	if (gnutls_certificate_set_x509_key_file(gnutls_cert_creds, GNUTLS_CERT_PATH, GNUTLS_KEY_PATH, GNUTLS_X509_FMT_PEM) < 0)
		return 4;

	return 0;
}

int gnutls_send(void *handle, struct string msg) {
	struct gnutls_handle *gnutls_handle = handle;

	pthread_mutex_lock(&(gnutls_handle->mutex));

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

				if ((pollfd.revents & (POLLIN | POLLOUT)) == (POLLIN | POLLOUT) || (pollfd.revents & (POLLIN | POLLOUT)) == 0)
					continue;
				else if (pollfd.revents & POLLIN)
					pollfd.events = POLLOUT;
				else
					pollfd.events = POLLIN;
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

	pthread_mutex_unlock(&(gnutls_handle->mutex));
	return 0;

	gnutls_send_error_unlock:
	gnutls_handle->valid = 0;
	pthread_mutex_unlock(&(gnutls_handle->mutex));
	return 1;
}

size_t gnutls_recv(void *session, char *data, size_t len, char *err) {
	ssize_t res;
	do {
		res = gnutls_record_recv(*((gnutls_session_t*)session), data, len);
	} while (res < 0 && (res == GNUTLS_E_INTERRUPTED || res == GNUTLS_E_AGAIN));

	if (res < 0) {
		if (res == GNUTLS_E_TIMEDOUT) {
			*err = 1;
		} else {
			*err = 3;
		}
		return 0;
	} else if (res == 0) {
		*err = 2;
		return 0;
	}
	*err = 0;

	return (size_t)res;
}

int gnutls_connect(void **handle, struct string address, struct string port, struct string *addr_out) {
	struct sockaddr sockaddr;
	if (resolve(address, port, &sockaddr) != 0)
		return -1;

	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (fd == -1)
		return -1;

	{
		struct timeval timeout = {
			.tv_sec = PING_INTERVAL,
			.tv_usec = 0,
		};

		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
	}

	int res;
	do {
		res = connect(fd, &sockaddr, sizeof(sockaddr));
	} while (res < 0 && errno == EINTR);
	if (res < 0)
		goto gnutls_connect_close;

	gnutls_session_t *session;
	session = malloc(sizeof(*session));
	if (session == 0)
		goto gnutls_connect_close;
	*handle = session;

	if (gnutls_init(session, GNUTLS_CLIENT | GNUTLS_NONBLOCK) != GNUTLS_E_SUCCESS)
		goto gnutls_connect_free_session;

	if (gnutls_server_name_set(*session, GNUTLS_NAME_DNS, address.data, address.len) != GNUTLS_E_SUCCESS)
		goto gnutls_connect_deinit_session;

	if (gnutls_credentials_set(*session, GNUTLS_CRD_CERTIFICATE, gnutls_cert_creds) != GNUTLS_E_SUCCESS)
		goto gnutls_connect_deinit_session;

	if (gnutls_set_default_priority(*session) != GNUTLS_E_SUCCESS)
		goto gnutls_connect_deinit_session;

	gnutls_transport_set_int(*session, fd);

	gnutls_handshake_set_timeout(*session, PING_INTERVAL * 1000);
	gnutls_record_set_timeout(*session, PING_INTERVAL * 1000);

	do {
		res = gnutls_handshake(*session);
	} while (res == GNUTLS_E_INTERRUPTED || res == GNUTLS_E_AGAIN);
	if (res < 0)
		goto gnutls_connect_deinit_session;

	addr_out->data = malloc(sizeof(sockaddr));
	if (!addr_out->data)
		goto gnutls_connect_deinit_session;

	memcpy(addr_out->data, &sockaddr, sizeof(sockaddr));
	addr_out->len = sizeof(sockaddr);

	return fd;

	gnutls_connect_deinit_session:
	gnutls_deinit(*session);
	gnutls_connect_free_session:
	free(session);
	gnutls_connect_close:
	close(fd);
	return -1;
}

int gnutls_accept(int listen_fd, void **handle, struct string *addr) {
	struct sockaddr address;
	socklen_t address_len = sizeof(address);

	int con_fd;
	do {
		con_fd = accept(listen_fd, &address, &address_len);
	} while (con_fd == -1 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK || errno == ENETDOWN || errno == EPROTO || errno == ENOPROTOOPT || errno == EHOSTDOWN || errno == ENONET || errno == EHOSTUNREACH || errno == EOPNOTSUPP || errno == ENETUNREACH));

	if (con_fd == -1)
		return -1;

	addr->data = malloc(address_len);
	if (addr->data == 0 && address_len != 0)
		goto gnutls_accept_close;

	memcpy(addr->data, &address, address_len);
	addr->len = address_len;

	gnutls_session_t *session;
	session = malloc(sizeof(*session));
	if (!session)
		goto gnutls_accept_free_addr_data;
	*handle = session;

	if (gnutls_init(session, GNUTLS_SERVER | GNUTLS_NONBLOCK) != GNUTLS_E_SUCCESS)
		goto gnutls_accept_free_session;

	if (gnutls_credentials_set(*session, GNUTLS_CRD_CERTIFICATE, gnutls_cert_creds) != GNUTLS_E_SUCCESS)
		goto gnutls_accept_deinit_session;

	if (gnutls_set_default_priority(*session) != GNUTLS_E_SUCCESS)
		goto gnutls_accept_deinit_session;

	gnutls_transport_set_int(*session, con_fd);

	gnutls_handshake_set_timeout(*session, PING_INTERVAL * 1000);
	gnutls_record_set_timeout(*session, PING_INTERVAL * 1000);

	int res;
	do {
		res = gnutls_handshake(*session);
	} while (res == GNUTLS_E_INTERRUPTED || res == GNUTLS_E_AGAIN);
	if (res != GNUTLS_E_SUCCESS)
		goto gnutls_accept_deinit_session;

	return con_fd;

	gnutls_accept_deinit_session:
	gnutls_deinit(*session);
	gnutls_accept_free_session:
	free(session);
	gnutls_accept_free_addr_data:
	free(addr->data);
	gnutls_accept_close:
	close(con_fd);
	return -1;
}

void gnutls_close(int fd, void *handle) {
	gnutls_deinit(*((gnutls_session_t*)handle));
	free(handle);
	close(fd);
}
