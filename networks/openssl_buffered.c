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
#include <fcntl.h>
#include <openssl/ssl.h>
#include <openssl/tls1.h>
#include <poll.h>
#include <pthread.h>
#include <unistd.h>

#ifdef USE_FUTEX
#else
#include <semaphore.h>
#endif

#include "../config.h"
#include "../main.h"
#include "../mutex.h"
#include "openssl_buffered.h"

struct openssl_buffered_handle {
	SSL *ssl;
	MUTEX_TYPE mutex;
	int fd;
	char valid;
	char close;
#ifdef USE_FUTEX
	MUTEX_TYPE release_read;
	MUTEX_TYPE release_write;
#else
	sem_t release_read;
	sem_t release_write;
#endif
	char *buffer;
	size_t write_buffer_index;
	size_t buffer_len;
};

SSL_CTX *openssl_buffered_ctx;

int init_openssl_buffered_network(void) {
	SSL_library_init();

	openssl_buffered_ctx = SSL_CTX_new(TLS_method());
	if (OPENSSL_CERT_PATH && OPENSSL_KEY_PATH) {
		if (SSL_CTX_use_certificate_file(openssl_buffered_ctx, OPENSSL_CERT_PATH, SSL_FILETYPE_PEM) != 1)
			return 1;
		if (SSL_CTX_use_PrivateKey_file(openssl_buffered_ctx, OPENSSL_KEY_PATH, SSL_FILETYPE_PEM) != 1)
			return 1;
	}

	if (OPENSSL_USE_SYSTEM_TRUST) {
		if (SSL_CTX_set_default_verify_paths(openssl_buffered_ctx) != 1) {
			return 1;
		}
	}

	return 0;
}

void * openssl_buffered_send_thread(void *handle) {
	struct openssl_buffered_handle *info = handle;

	size_t read_buffer_index = 0;
	mutex_lock(&(info->mutex));
	while (1) {
		if (!info->valid)
			goto openssl_buffered_send_thread_error_unlock;

		size_t len;
		len = info->buffer_len;

#ifdef USE_FUTEX
		mutex_unlock(&(info->release_write));
		if (len == 0)
			info->release_read = 1;
#else
		sem_trywait(&(info->release_write));
		sem_post(&(info->release_write));
#endif

		mutex_unlock(&(info->mutex));

#ifdef USE_FUTEX
		if (len == 0) {
			mutex_lock(&(info->release_read));
			mutex_lock(&(info->mutex));
			continue;
		}
#else
		if (len == 0) {
			sem_wait(&(info->release_read));
			mutex_lock(&(info->mutex));
			continue;
		}
#endif

		if (read_buffer_index + len > OPENSSL_BUFFERED_LEN)
			len = OPENSSL_BUFFERED_LEN - read_buffer_index;
		if (len > OPENSSL_BUFFERED_LEN/2 && OPENSSL_BUFFERED_LEN > 1)
			len = OPENSSL_BUFFERED_LEN/2;

		struct pollfd pollfd = {
			.fd = info->fd,
		};
		int res;
		do {
			mutex_lock(&(info->mutex));
			res = SSL_write(info->ssl, &(info->buffer[read_buffer_index]), len);
			if (res <= 0) {
				switch(SSL_get_error(info->ssl, res)) {
					case SSL_ERROR_WANT_READ:
						pollfd.events = POLLIN;
						break;
					case SSL_ERROR_WANT_WRITE:
						pollfd.events = POLLOUT;
						break;
					default:
						goto openssl_buffered_send_thread_error_unlock;
				}
			} else {
				break;
			}
			mutex_unlock(&(info->mutex));

			do {
				res = poll(&pollfd, 1, PING_INTERVAL*1000);
			} while (res < 0 && errno == EINTR);
			if (res < 0)
				goto openssl_buffered_send_thread_error;
			if (res == 0) // Timed out... maybe handle differently later
				goto openssl_buffered_send_thread_error;
			if ((pollfd.revents & (POLLIN | POLLOUT)) == 0) // Only errors returned
				goto openssl_buffered_send_thread_error;
		} while (1);

		read_buffer_index += len;
		if (read_buffer_index >= OPENSSL_BUFFERED_LEN)
			read_buffer_index = 0;

		info->buffer_len -= len;
	}

	openssl_buffered_send_thread_error:
	mutex_lock(&(info->mutex));
	openssl_buffered_send_thread_error_unlock:
	info->valid = 0;
	mutex_unlock(&(info->mutex));

#ifdef USE_FUTEX
	mutex_unlock(&(info->release_write));
#else
	sem_trywait(&(info->release_write));
	sem_post(&(info->release_write));
#endif
	while (1) {
		mutex_lock(&(info->mutex));
		if (info->close) {
			mutex_unlock(&(info->mutex));
			mutex_destroy(&(info->mutex));
			SSL_free(info->ssl);
			close(info->fd);
			free(info->buffer);
#ifdef USE_FUTEX
#else
			sem_destroy(&(info->release_read));
			sem_destroy(&(info->release_write));
#endif
			free(info);
			return 0;
		} else {
#ifdef USE_FUTEX
			info->release_read = 1;
			mutex_unlock(&(info->mutex));
			mutex_lock(&(info->release_read));
			continue;
#else
			mutex_unlock(&(info->mutex));
			sem_wait(&(info->release_read));
			continue;
#endif
		}
		mutex_unlock(&(info->mutex));
	}
}

int openssl_buffered_send(void *handle, struct string msg) {
	struct openssl_buffered_handle *openssl_handle = handle;
	while (msg.len > 0) {
		size_t len = msg.len;
		if (len > OPENSSL_BUFFERED_LEN - openssl_handle->write_buffer_index)
			len = OPENSSL_BUFFERED_LEN - openssl_handle->write_buffer_index;
		mutex_lock(&(openssl_handle->mutex));
		if (!openssl_handle->valid) {
			mutex_unlock(&(openssl_handle->mutex));
			return 1;
		}
		if (len > OPENSSL_BUFFERED_LEN - openssl_handle->buffer_len)
			len = OPENSSL_BUFFERED_LEN - openssl_handle->buffer_len;
#ifdef USE_FUTEX
		if (len == 0) {
			openssl_handle->release_write = 1;
			mutex_unlock(&(openssl_handle->mutex));
			mutex_lock(&(openssl_handle->release_write));
			continue;
		}
#else
		if (len == 0) {
			mutex_unlock(&(openssl_handle->mutex));
			sem_wait(&(openssl_handle->release_write));
			continue;
		}
#endif
		memcpy(&(openssl_handle->buffer[openssl_handle->write_buffer_index]), msg.data, len);
		openssl_handle->buffer_len += len;
#ifdef USE_FUTEX
		mutex_unlock(&(openssl_handle->release_read));
#else
		sem_trywait(&(openssl_handle->release_read));
		sem_post(&(openssl_handle->release_read));
#endif
		mutex_unlock(&(openssl_handle->mutex));
		openssl_handle->write_buffer_index += len;
		if (openssl_handle->write_buffer_index >= OPENSSL_BUFFERED_LEN)
			openssl_handle->write_buffer_index = 0;
		msg.len -= len;
		msg.data += len;
	}

	return 0;
}

size_t openssl_buffered_recv(void *handle, char *data, size_t len, char *err) {
	struct openssl_buffered_handle *openssl_handle = handle;

	struct pollfd pollfd = {
		.fd = openssl_handle->fd,
	};
	int res;
	do {
		mutex_lock(&(openssl_handle->mutex));
		if (!openssl_handle->valid) {
			mutex_unlock(&(openssl_handle->mutex));
			*err = 3;
			return 0;
		}
		res = SSL_read(openssl_handle->ssl, data, len);
		if (res <= 0) {
			int ssl_err = SSL_get_error(openssl_handle->ssl, res);
			switch(ssl_err) {
				case SSL_ERROR_WANT_READ:
					pollfd.events = POLLIN;
					break;
				case SSL_ERROR_WANT_WRITE:
					pollfd.events = POLLOUT;
					break;
				default:
					mutex_unlock(&(openssl_handle->mutex));
					*err = 3;
					return 0;
			}
		} else {
			break;
		}
		mutex_unlock(&(openssl_handle->mutex));

		res = poll(&pollfd, 1, PING_INTERVAL*1000);
		if (res == 0) { // Timeout
			*err = 1;
			return 0;
		}
		if (res == -1) {
			if (errno != EINTR) {
				continue;
			} else {
				*err = 3;
				return 0;
			}
		}
		if ((pollfd.revents & (POLLIN | POLLOUT)) == 0) { // Only errors returned
			if (pollfd.revents & POLLHUP) {
				*err = 2;
			} else {
				*err = 3;
			}

			return 0;
		}
	} while (1);
	mutex_unlock(&(openssl_handle->mutex));

	*err = 0;
	return (size_t)res;
}

int openssl_buffered_connect(void **handle, struct string address, struct string port, struct string *addr_out) {
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
		goto openssl_connect_close;

	int flags = fcntl(fd, F_GETFL);
	if (flags == -1)
		goto openssl_connect_close;
	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
		goto openssl_connect_close;

	addr_out->data = malloc(sizeof(sockaddr));
	if (!addr_out->data)
		goto openssl_connect_close;
	memcpy(addr_out->data, &sockaddr, sizeof(sockaddr));
	addr_out->len = sizeof(sockaddr);

	struct openssl_buffered_handle *openssl_handle;
	openssl_handle = malloc(sizeof(*openssl_handle));
	if (!openssl_handle)
		goto openssl_connect_free_addr_data;
	*handle = openssl_handle;

	openssl_handle->fd = fd;

	openssl_handle->ssl = SSL_new(openssl_buffered_ctx);
	if (!openssl_handle->ssl)
		goto openssl_connect_free_openssl_handle;
	SSL_set_fd(openssl_handle->ssl, fd);

	res = mutex_init(&(openssl_handle->mutex));
	if (res != 0)
		goto openssl_connect_free_ssl;

	struct pollfd pollfd = {
		.fd = fd,
	};
	do {
		res = SSL_connect(openssl_handle->ssl);
		if (res == 0)
			goto openssl_connect_destroy_mutex;
		if (res < 0) {
			switch(SSL_get_error(openssl_handle->ssl, res)) {
				case SSL_ERROR_WANT_READ:
					pollfd.events = POLLIN;
					break;
				case SSL_ERROR_WANT_WRITE:
					pollfd.events = POLLOUT;
					break;
				default:
					goto openssl_connect_destroy_mutex;
			}
		} else {
			break;
		}

		res = poll(&pollfd, 1, PING_INTERVAL*1000);
		if (res == 0) // Timeout
			goto openssl_connect_destroy_mutex;
		if (res == -1) {
			if (errno != EINTR) {
				continue;
			} else {
				goto openssl_connect_destroy_mutex;
			}
		}
		if ((pollfd.revents & (POLLIN | POLLOUT)) == 0) // Only errors returned
			goto openssl_connect_destroy_mutex;
	} while (1);

	openssl_handle->valid = 1;
	openssl_handle->close = 0;
	openssl_handle->write_buffer_index = 0;
	openssl_handle->buffer_len = 0;

	openssl_handle->buffer = malloc(OPENSSL_BUFFERED_LEN);
	if (!openssl_handle->buffer)
		goto openssl_connect_destroy_mutex;

#ifdef USE_FUTEX
	openssl_handle->release_read = 0;
	openssl_handle->release_write = 0;
#else
	sem_init(&(openssl_handle->release_read), 0, 0);
	sem_init(&(openssl_handle->release_write), 0, 0);
#endif

	pthread_t trash;
	if (pthread_create(&trash, &pthread_attr, openssl_buffered_send_thread, openssl_handle) != 0)
		goto openssl_connect_destroy_releases;

	return fd;

	openssl_connect_destroy_releases:
#ifdef USE_FUTEX
#else
	sem_destroy(&(openssl_handle->release_read));
	sem_destroy(&(openssl_handle->release_write));
#endif
	openssl_connect_destroy_mutex:
	mutex_destroy(&(openssl_handle->mutex));
	openssl_connect_free_ssl:
	SSL_free(openssl_handle->ssl);
	openssl_connect_free_openssl_handle:
	free(openssl_handle);
	openssl_connect_free_addr_data:
	free(addr_out->data);
	openssl_connect_close:
	close(fd);

	return -1;
}

int openssl_buffered_accept(int listen_fd, void **handle, struct string *addr) {
	if (!OPENSSL_CERT_PATH || !OPENSSL_KEY_PATH)
		return -1;

	struct sockaddr address;
	socklen_t address_len = sizeof(address);

	int con_fd;
	do {
		con_fd = accept(listen_fd, &address, &address_len);
	} while (con_fd == -1 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK || errno == ENETDOWN || errno == EPROTO || errno == ENOPROTOOPT || errno == EHOSTDOWN || errno == ENONET || errno == EHOSTUNREACH || errno == EOPNOTSUPP || errno == ENETUNREACH));

	if (con_fd == -1)
		return -1;

	int flags = fcntl(con_fd, F_GETFL);
	if (flags == -1)
		goto openssl_accept_close;
	if (fcntl(con_fd, F_SETFL, flags | O_NONBLOCK) == -1)
		goto openssl_accept_close;

	addr->data = malloc(address_len);
	if (addr->data == 0 && address_len != 0)
		goto openssl_accept_close;

	memcpy(addr->data, &address, address_len);
	addr->len = address_len;

	struct openssl_buffered_handle *openssl_handle;
	openssl_handle = malloc(sizeof(*openssl_handle));
	if (!openssl_handle)
		goto openssl_accept_free_addr_data;

	*handle = openssl_handle;

	openssl_handle->fd = con_fd;

	openssl_handle->ssl = SSL_new(openssl_buffered_ctx);
	if (!openssl_handle->ssl)
		goto openssl_accept_free_openssl_handle;

	SSL_set_fd(openssl_handle->ssl, con_fd);

	int res = mutex_init(&(openssl_handle->mutex));
	if (res != 0)
		goto openssl_accept_free_ssl;

	struct pollfd pollfd = {
		.fd = con_fd,
	};
	do {
		res = SSL_accept(openssl_handle->ssl);
		if (res == 0)
			goto openssl_accept_destroy_mutex;
		if (res < 0) {
			switch(SSL_get_error(openssl_handle->ssl, res)) {
				case SSL_ERROR_WANT_READ:
					pollfd.events = POLLIN;
					break;
				case SSL_ERROR_WANT_WRITE:
					pollfd.events = POLLOUT;
					break;
				default:
					goto openssl_accept_destroy_mutex;
			}
		} else {
			break;
		}

		res = poll(&pollfd, 1, PING_INTERVAL*1000);
		if (res == 0) // Timeout
			goto openssl_accept_destroy_mutex;
		if (res == -1) {
			if (errno != EINTR) {
				continue;
			} else {
				goto openssl_accept_destroy_mutex;
			}
		}
		if ((pollfd.revents & (POLLIN | POLLOUT)) == 0) // Only errors returned
			goto openssl_accept_destroy_mutex;
	} while (1);

	openssl_handle->valid = 1;

	openssl_handle->buffer = malloc(OPENSSL_BUFFERED_LEN);
	if (!openssl_handle->buffer)
		goto openssl_accept_destroy_mutex;

#ifdef USE_FUTEX
	openssl_handle->release_read = 0;
	openssl_handle->release_write = 0;
#else
	sem_init(&(openssl_handle->release_read), 0, 0);
	sem_init(&(openssl_handle->release_write), 0, 0);
#endif

	pthread_t trash;
	if (pthread_create(&trash, &pthread_attr, openssl_buffered_send_thread, openssl_handle) != 0)
		goto openssl_accept_destroy_releases;

	return con_fd;

	openssl_accept_destroy_releases:
#ifdef USE_FUTEX
#else
	sem_destroy(&(openssl_handle->release_read));
	sem_destroy(&(openssl_handle->release_write));
#endif
	openssl_accept_destroy_mutex:
	mutex_destroy(&(openssl_handle->mutex));
	openssl_accept_free_ssl:
	SSL_free(openssl_handle->ssl);
	openssl_accept_free_openssl_handle:
	free(openssl_handle);
	openssl_accept_free_addr_data:
	free(addr->data);
	openssl_accept_close:
	close(con_fd);

	return -1;
}

void openssl_buffered_shutdown(void *handle) {
	struct openssl_buffered_handle *openssl_handle = handle;
	mutex_lock(&(openssl_handle->mutex));
	openssl_handle->valid = 0;
#ifdef USE_FUTEX
	mutex_unlock(&(openssl_handle->release_read));
#else
	sem_trywait(&(openssl_handle->release_read));
	sem_post(&(openssl_handle->release_read));
#endif
	mutex_unlock(&(openssl_handle->mutex));
	shutdown(openssl_handle->fd, SHUT_RDWR);
}

void openssl_buffered_close(int fd, void *handle) {
	struct openssl_buffered_handle *openssl_handle = handle;
	mutex_lock(&(openssl_handle->mutex));
	openssl_handle->valid = 0;
#ifdef USE_FUTEX
	mutex_unlock(&(openssl_handle->release_read));
#else
	sem_trywait(&(openssl_handle->release_read));
	sem_post(&(openssl_handle->release_read));
#endif
	openssl_handle->close = 1;
	mutex_unlock(&(openssl_handle->mutex));
}
