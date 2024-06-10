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
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

#include "config.h"
#include "main.h"
#include "protocols.h"
#include "server_network.h"

#ifdef USE_PLAINTEXT_SERVER
#include "plaintext_network.h"
#endif
#ifdef USE_GNUTLS_SERVER
#include "gnutls_network.h"
#endif

struct table server_config = {0};

int init_server_network(void) {
	for (size_t i = 0; i < SERVER_CONFIG_LEN; i++) {
		if (set_table_index(&server_config, SERVER_CONFIG[i].sid, &(SERVER_CONFIG[i])) != 0) {
			return 1;
		}
	}

	return 0;
}

int start_server_network(void) {
#ifdef USE_PLAINTEXT_SERVER
	if (start_server_network_threads(NET_TYPE_PLAINTEXT) != 0)
		return 1;
#endif
#ifdef USE_GNUTLS_SERVER
	if (start_server_network_threads(NET_TYPE_GNUTLS) != 0)
		return 1;
#endif
#ifdef USE_OPENSSL_SERVER
	if (start_server_network_threads(NET_TYPE_OPENSSL) != 0)
		return 1;
#endif

	pthread_t trash;
	for (size_t i = 0; i < SERVER_CONFIG_LEN; i++) {
		if (SERVER_CONFIG[i].autoconnect) {
			if (pthread_create(&trash, &pthread_attr, protocols[SERVER_CONFIG[i].protocol].autoconnect, &(SERVER_CONFIG[i])) != 0) {
				return 1;
			}
		}
	}

	return 0;
}

int start_server_network_threads(size_t net) {
	pthread_t trash; // Not actually used, so discard
	struct server_network_info *type;
#ifdef USE_INSPIRCD2_PROTOCOL
	type = malloc(sizeof(*type));
	if (!type)
		return 1;
	type->net_type = net;
	type->protocol = INSPIRCD2_PROTOCOL;
	type->is_incoming = 1;
	if (pthread_create(&trash, &pthread_attr, server_accept_thread, type) != 0) {
		free(type);
		return 1;
	}
#endif
	return 0;
}

void * server_accept_thread(void *type) {
	size_t net;
	size_t protocol;
	{
		struct server_network_info *t = type;
		net = t->net_type;
		protocol = t->protocol;
	}

	// Check if there is actually an incoming server connection configured using this net+protocol, and if not just return from this thread; some excess may have been spawned
	{
		char found = 0;
		for (size_t i = 0; i < SERVER_CONFIG_LEN; i++) {
			if (SERVER_CONFIG[i].protocol == protocol && !(SERVER_CONFIG[i].autoconnect)) { // TODO: Don't make autoconnect conflict with incoming connections
				found = 1;
				break;
			}
		}
		if (!found)
			return 0;
	}

	int listen_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (listen_fd < 0)
		return 0;

	{
		int one = 1;
		setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	}

	{
		struct sockaddr_in sockaddr = {
			.sin_family = AF_INET,
		};

		sockaddr.sin_port = htons(SERVER_PORTS[net][protocol]);
		size_t listen_number = SERVER_LISTEN[net][protocol];

		if (bind(listen_fd, (struct sockaddr*)&sockaddr, sizeof(sockaddr)) != 0)
			return 0;

		listen(listen_fd, listen_number);
	}

	while (1) {
		struct string address;
		void *con_handle;
		int con_fd = networks[net].accept(listen_fd, &con_handle, &address);
		if (con_fd == -1)
			continue; // TODO: Handle error

		pthread_t trash;
		struct server_connection_info *info;
		info = malloc(sizeof(*info));
		if (!info) {
			networks[net].close(con_fd, con_handle);
			continue;
		}
		info->address = address;
		info->type = type;
		info->fd = con_fd;
		info->handle = con_handle;
		if (pthread_create(&trash, &pthread_attr, protocols[protocol].handle_connection, info) != 0) {
			free(info);
			networks[net].close(con_fd, con_handle);
		}
	}
}
