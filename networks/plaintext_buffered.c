// Plaintext TCP networking, with a buffer and a seperate sending thread
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
#include <pthread.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "../config.h"
#include "../general_network.h"
#include "../haxstring.h"
#include "../main.h"
#include "../mutex.h"
#include "plaintext_buffered.h"

struct plaintext_buffered_handle {
	MUTEX_TYPE mutex;
	MUTEX_TYPE release_read;
	MUTEX_TYPE release_write;
	int fd;
	char valid;
	char close;
	char *buffer;
	size_t write_buffer_index;
	size_t buffer_len;
};

int init_plaintext_buffered_network(void) {
	return 0;
}

void * plaintext_buffered_send_thread(void *handle) {
	struct plaintext_buffered_handle *info = handle;

	size_t read_buffer_index = 0;
	ssize_t res = 0;
	while (1) {
#ifdef USE_ATOMICS
		size_t len = __sync_sub_and_fetch(&(info->buffer_len), (size_t)res);
#else
		mutex_lock(&(info->mutex));

		info->buffer_len -= (size_t)res;
		size_t len = info->buffer_len;
#endif

		mutex_unlock(&(info->release_write));

#ifdef USE_ATOMICS
		if (!__sync_fetch_and_or(&(info->valid), 0)) { // TODO: Clean up mutexes in exit code too
			mutex_lock(&(info->mutex));
			goto plaintext_buffered_send_thread_error_unlock;
		}
#else
		if (!info->valid)
			goto plaintext_buffered_send_thread_error_unlock;

		mutex_unlock(&(info->mutex));
#endif

		if (len == 0) {
			res = 0;
			mutex_lock(&(info->release_read));
			continue;
		}

		if (read_buffer_index + len > PLAINTEXT_BUFFERED_LEN)
			len = PLAINTEXT_BUFFERED_LEN - read_buffer_index;
		if (len > PLAINTEXT_BUFFERED_LEN/2 && PLAINTEXT_BUFFERED_LEN > 1)
			len = PLAINTEXT_BUFFERED_LEN/2;

		do {
			res = send(info->fd, &(info->buffer[read_buffer_index]), len, 0);
		} while (res == -1 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK));
		if (res < 0)
			goto plaintext_buffered_send_thread_error;

		read_buffer_index += (size_t)res;
		if (read_buffer_index >= PLAINTEXT_BUFFERED_LEN)
			read_buffer_index = 0;
	}

	plaintext_buffered_send_thread_error:
	mutex_lock(&(info->mutex));
	plaintext_buffered_send_thread_error_unlock:
	info->valid = 0;
	mutex_unlock(&(info->mutex));
	mutex_unlock(&(info->release_write));
	while (1) {
		mutex_lock(&(info->mutex));
		if (info->close) {
			close(info->fd);
			free(info->buffer);
			mutex_unlock(&(info->mutex));
			mutex_destroy(&(info->mutex));
			mutex_destroy(&(info->release_read));
			mutex_destroy(&(info->release_write));
			free(info);
			return 0;
		} else {
			mutex_unlock(&(info->mutex));
			mutex_lock(&(info->release_read));
			continue;
		}
		mutex_unlock(&(info->mutex));
	}

	return 0;
}

int plaintext_buffered_send(void *handle, struct string msg) {
	struct plaintext_buffered_handle *plaintext_handle = handle;
	while (msg.len > 0) {
#ifdef USE_ATOMICS
		size_t len = PLAINTEXT_BUFFERED_LEN - __sync_fetch_and_or(&(plaintext_handle->buffer_len), 0); // There's no fetch-only for __sync
#else
		mutex_lock(&(plaintext_handle->mutex));
		size_t len = PLAINTEXT_BUFFERED_LEN - plaintext_handle->buffer_len;
#endif

		if (len > msg.len)
			len = msg.len;

		if (len > PLAINTEXT_BUFFERED_LEN - plaintext_handle->write_buffer_index)
			len = PLAINTEXT_BUFFERED_LEN - plaintext_handle->write_buffer_index;

#ifdef USE_ATOMICS
		if (!__sync_fetch_and_or(&(plaintext_handle->valid), 0))
			return 1;
#else
		if (!plaintext_handle->valid) {
			mutex_unlock(&(plaintext_handle->mutex));
			return 1;
		}
#endif

		if (len == 0) {
#ifdef USE_ATOMICS
#else
			mutex_unlock(&(plaintext_handle->mutex));
#endif
			mutex_lock(&(plaintext_handle->release_write));
			continue;
		}

		memcpy(&(plaintext_handle->buffer[plaintext_handle->write_buffer_index]), msg.data, len);

#ifdef USE_ATOMICS
		__sync_fetch_and_add(&(plaintext_handle->buffer_len), len); // No __sync add-only either
#else
		plaintext_handle->buffer_len += len;

		mutex_unlock(&(plaintext_handle->mutex));
#endif

		mutex_unlock(&(plaintext_handle->release_read));

		plaintext_handle->write_buffer_index += len;
		if (plaintext_handle->write_buffer_index >= PLAINTEXT_BUFFERED_LEN)
			plaintext_handle->write_buffer_index = 0;
		msg.len -= len;
		msg.data += len;
	}

	return 0;
}

size_t plaintext_buffered_recv(void *handle, char *data, size_t len, char *err) {
	struct plaintext_buffered_handle *plaintext_handle = handle;
	ssize_t res;
	do {
		res = recv(plaintext_handle->fd, data, len, 0);
	} while (res == -1 && (errno == EINTR));

	if (res == -1) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			*err = 1;
		} else if (errno == ESHUTDOWN || errno == ECONNRESET) {
			*err = 2;
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

int plaintext_buffered_connect(void **handle, struct string address, struct string port, struct string *addr_out) {
	struct sockaddr sockaddr;
	socklen_t sockaddr_len;
	int family;
	if (resolve(address, port, &sockaddr, &sockaddr_len, &family) != 0)
		return -1;

	int fd = socket(family, SOCK_STREAM, IPPROTO_TCP);
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
		res = connect(fd, &sockaddr, sockaddr_len);
	} while (res < 0 && errno == EINTR);
	if (res < 0)
		goto plaintext_buffered_connect_close;

	struct plaintext_buffered_handle *plaintext_handle;
	plaintext_handle = malloc(sizeof(*plaintext_handle));
	if (!handle)
		goto plaintext_buffered_connect_close;
	*handle = plaintext_handle;
	plaintext_handle->valid = 1;
	plaintext_handle->close = 0;
	plaintext_handle->fd = fd;

	addr_out->data = malloc(sockaddr_len);
	if (!addr_out->data)
		goto plaintext_buffered_connect_free_handle;
	memcpy(addr_out->data, &sockaddr, sockaddr_len);
	addr_out->len = sockaddr_len;

	plaintext_handle->buffer = malloc(PLAINTEXT_BUFFERED_LEN);
	if (!plaintext_handle->buffer)
		goto plaintext_buffered_connect_free_addr;
	plaintext_handle->write_buffer_index = 0;
	plaintext_handle->buffer_len = 0;

	mutex_init(&(plaintext_handle->mutex));

	mutex_init(&(plaintext_handle->release_read));
	mutex_init(&(plaintext_handle->release_write));

	pthread_t trash;
	if (pthread_create(&trash, &pthread_attr, plaintext_buffered_send_thread, plaintext_handle) != 0)
		goto plaintext_buffered_connect_destroy_mutex;

	return fd;

	plaintext_buffered_connect_destroy_mutex:
	mutex_destroy(&(plaintext_handle->mutex));
	mutex_destroy(&(plaintext_handle->release_read));
	mutex_destroy(&(plaintext_handle->release_write));
	free(plaintext_handle->buffer);
	plaintext_buffered_connect_free_addr:
	free(addr_out->data);
	plaintext_buffered_connect_free_handle:
	free(plaintext_handle);
	plaintext_buffered_connect_close:
	close(fd);

	return -1;
}

int plaintext_buffered_accept(int listen_fd, void **handle, struct string *addr) {
	struct sockaddr address;
	socklen_t address_len = sizeof(address);

	int con_fd;
	do {
		con_fd = accept(listen_fd, &address, &address_len);
	} while (con_fd == -1 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK || errno == ENETDOWN || errno == EPROTO || errno == ENOPROTOOPT || errno == EHOSTDOWN || errno == ENONET || errno == EHOSTUNREACH || errno == EOPNOTSUPP || errno == ENETUNREACH));

	if (con_fd == -1)
		return -1;

	{
		struct timeval timeout = {
			.tv_sec = PING_INTERVAL,
			.tv_usec = 0,
		};

		setsockopt(con_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
	}

	struct plaintext_buffered_handle *plaintext_handle = malloc(sizeof(*plaintext_handle));
	if (!plaintext_handle)
		goto plaintext_buffered_accept_close;
	*handle = plaintext_handle;
	plaintext_handle->valid = 1;
	plaintext_handle->close = 0;
	plaintext_handle->fd = con_fd;

	addr->data = malloc(address_len);
	if (addr->data == 0 && address_len != 0)
		goto plaintext_buffered_accept_free_handle;
	memcpy(addr->data, &address, address_len);
	addr->len = address_len;


	plaintext_handle->buffer = malloc(PLAINTEXT_BUFFERED_LEN);
	if (!plaintext_handle->buffer)
		goto plaintext_buffered_accept_free_addr;
	plaintext_handle->write_buffer_index = 0;
	plaintext_handle->buffer_len = 0;

	mutex_init(&(plaintext_handle->mutex));

	mutex_init(&(plaintext_handle->release_read));
	mutex_init(&(plaintext_handle->release_write));

	pthread_t trash;
	if (pthread_create(&trash, &pthread_attr, plaintext_buffered_send_thread, plaintext_handle) != 0)
		goto plaintext_buffered_accept_destroy_mutex;

	return con_fd;

	plaintext_buffered_accept_destroy_mutex:
	mutex_destroy(&(plaintext_handle->mutex));
	mutex_destroy(&(plaintext_handle->release_read));
	mutex_destroy(&(plaintext_handle->release_write));
	free(plaintext_handle->buffer);
	plaintext_buffered_accept_free_addr:
	free(addr->data);
	plaintext_buffered_accept_free_handle:
	free(plaintext_handle);
	plaintext_buffered_accept_close:
	close(con_fd);

	return -1;
}

void plaintext_buffered_shutdown(void *handle) {
	struct plaintext_buffered_handle *plaintext_handle = handle;
	mutex_lock(&(plaintext_handle->mutex));
	plaintext_handle->valid = 0;
	mutex_unlock(&(plaintext_handle->release_read));
	mutex_unlock(&(plaintext_handle->mutex));
	shutdown(plaintext_handle->fd, SHUT_RDWR);
}

void plaintext_buffered_close(int fd, void *handle) {
	struct plaintext_buffered_handle *plaintext_handle = handle;
	mutex_lock(&(plaintext_handle->mutex));
	plaintext_handle->valid = 0;
	mutex_unlock(&(plaintext_handle->release_read));
	plaintext_handle->close = 1;
	mutex_unlock(&(plaintext_handle->mutex));
}
