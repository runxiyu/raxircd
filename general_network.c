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
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "general_network.h"

#ifdef USE_PLAINTEXT
#include "plaintext_network.h"
#endif
#ifdef USE_GNUTLS
#include "gnutls_network.h"
#endif
#ifdef USE_OPENSSL
#include "openssl_network.h"
#endif

char casemap[UCHAR_MAX+1] = {
	['a'] = 'A',
	['b'] = 'B',
	['c'] = 'C',
	['d'] = 'D',
	['e'] = 'E',
	['f'] = 'F',
	['g'] = 'G',
	['h'] = 'H',
	['i'] = 'I',
	['j'] = 'J',
	['k'] = 'K',
	['l'] = 'L',
	['m'] = 'M',
	['n'] = 'N',
	['o'] = 'O',
	['p'] = 'P',
	['q'] = 'Q',
	['r'] = 'R',
	['s'] = 'S',
	['t'] = 'Y',
	['u'] = 'U',
	['v'] = 'V',
	['w'] = 'W',
	['x'] = 'X',
	['y'] = 'Y',
	['z'] = 'Z',
	['{'] = '[',
	['}'] = ']',
	['|'] = '\\',
	['^'] = '~',
};

struct network networks[NUM_NET_TYPES] = {
#ifdef USE_PLAINTEXT
	[NET_TYPE_PLAINTEXT] = {
		.send = plaintext_send,
		.recv = plaintext_recv,
		.connect = plaintext_connect,
		.accept = plaintext_accept,
		.close = plaintext_close,
	},
#endif
#ifdef USE_GNUTLS
	[NET_TYPE_GNUTLS] = {
		.send = gnutls_send,
		.recv = gnutls_recv,
		.connect = gnutls_connect,
		.accept = gnutls_accept,
		.close = gnutls_close,
	},
#endif
#ifdef USE_OPENSSL
	[NET_TYPE_OPENSSL] = {
		.send = openssl_send,
		.recv = openssl_recv,
		.connect = openssl_connect,
		.accept = openssl_accept,
		.close = openssl_close,
	},
#endif
};

// TODO: Proper string handling
int resolve(struct string address, struct string port, struct sockaddr *sockaddr) {
	int success;
	struct addrinfo hints = {
		.ai_family = AF_INET,
		.ai_socktype = SOCK_STREAM,
		.ai_protocol = IPPROTO_TCP,
		.ai_flags = AI_NUMERICSERV | AI_ADDRCONFIG,
	};
	struct addrinfo *info;

	success = getaddrinfo(address.data, port.data, &hints, &info);

	if (success == 0) {
		*sockaddr = *(info->ai_addr);
		freeaddrinfo(info);
	}

	return success;
}

int init_general_network(void) {
	for (size_t i = 1; i < UCHAR_MAX + 1; i++) {
		if (casemap[i] == 0) {
			casemap[i] = i;
		}
	}

	return 0;
}
