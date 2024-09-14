// Raw socket networking
//
// Written by: Test_User <hax@runxiyu.org>
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
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <netinet/in.h>

#include "../config.h"
#include "../general_network.h"
#include "hax_string.h"
#include "plaintext.h"

int init_plaintext_network(void) {
	return 0;
}

int plaintext_send(void *fd, struct string msg) {
	while (msg.len > 0) {
		ssize_t res;
		do {
			res = send(*((int*)fd), msg.data, msg.len, 0);
		} while (res == -1 && (errno == EINTR));

		if (res < 0 || (size_t)res > msg.len) { // res > len shouldn't be possible, but is still an error
			plaintext_shutdown(fd);
			return 1;
		} else if (res > 0) {
			msg.len -= (size_t)res;
			msg.data += (size_t)res;
		}
	}

	return 0;
}

size_t plaintext_recv(void *fd, char *data, size_t len, char *err) {
	ssize_t res;
	do {
		res = recv(*((int*)fd), data, len, 0);
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

int plaintext_connect(void **handle, struct string address, struct string port, struct string *addr_out) {
	struct sockaddr_storage sockaddr;
	socklen_t sockaddr_len;
	int family;
	if (resolve(address, port, (struct sockaddr*)&sockaddr, &sockaddr_len, &family) != 0)
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
		res = connect(fd, (struct sockaddr*)&sockaddr, sockaddr_len);
	} while (res < 0 && errno == EINTR);
	if (res < 0) {
		close(fd);
		return -1;
	}

	*handle = malloc(sizeof(fd));
	if (!handle) {
		close(fd);
		return -1;
	}
	*((int*)*handle) = fd;

	addr_out->data = malloc(sockaddr_len);
	if (!addr_out->data) {
		free(handle);
		close(fd);
		return -1;
	}
	memcpy(addr_out->data, &sockaddr, sockaddr_len);
	addr_out->len = sockaddr_len;

	return fd;
}

int plaintext_accept(int listen_fd, void **handle, struct string *addr) {
	struct sockaddr_storage address;
	socklen_t address_len = sizeof(address);

	int con_fd;
	do {
		con_fd = accept(listen_fd, (struct sockaddr*)&address, &address_len);
	} while (con_fd == -1 && RETRY_ACCEPT);

	if (con_fd == -1)
		return -1;

	{
		struct timeval timeout = {
			.tv_sec = PING_INTERVAL,
			.tv_usec = 0,
		};

		setsockopt(con_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
	}

	addr->data = malloc(address_len);
	if (addr->data == 0 && address_len != 0) {
		close(con_fd);
		return -1;
	}

	memcpy(addr->data, &address, address_len);
	addr->len = address_len;

	*handle = malloc(sizeof(con_fd));
	if (!handle) {
		free(addr->data);
		close(con_fd);
		return -1;
	}
	*((int*)*handle) = con_fd;

	return con_fd;
}

void plaintext_shutdown(void *handle) {
	shutdown(*((int*)handle), SHUT_RDWR);
}

void plaintext_close(int fd, void *handle) {
	free(handle);
	close(fd);
}
