// One of the headers for HaxServ
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

#pragma once

#include <limits.h>
#include <stddef.h>
#include <sys/socket.h>

#include "haxstring.h"
#include "table.h"

struct network {
	int (*send)(void *handle, struct string msg);
	size_t (*recv)(void *handle, char *data, size_t len, char *err);

	int (*connect)(void **handle, struct string address, struct string port, struct string *addr_out);
	int (*accept)(int listen_fd, void **handle, struct string *addr);

	void (*close)(int fd, void *handle);
};

int resolve(struct string address, struct string port, struct sockaddr *sockaddr);

int init_general_network(void);

extern char casemap[UCHAR_MAX+1];
#define CASEMAP(x) (casemap[(unsigned char)x])

#ifdef USE_PLAINTEXT
#define NET_TYPE_PLAINTEXT 0
#endif
#ifdef USE_GNUTLS
#define NET_TYPE_GNUTLS 1
#endif
#ifdef USE_OPENSSL
#define NET_TYPE_OPENSSL 2
#endif

#define NUM_NET_TYPES 3
extern struct network networks[NUM_NET_TYPES];
