// Server networking setup and connection accepting
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
#include <netdb.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>

#include "config.h"
#include "haxstring.h"
#include "haxstring_utils.h"
#include "main.h"
#include "protocols.h"
#include "server_network.h"

#ifdef USE_PLAINTEXT_NETWORK
#include "networks/plaintext.h"
#endif
#ifdef USE_GNUTLS_NETWORK
#include "networks/gnutls.h"
#endif
#ifdef USE_OPENSSL_NETWORK
#include "networks/openssl.h"
#endif
#ifdef USE_PLAINTEXT_BUFFERED_NETWORK
#include "networks/plaintext_buffered.h"
#endif
#ifdef USE_GNUTLS_BUFFERED_NETWORK
#include "networks/gnutls_buffered.h"
#endif
#ifdef USE_OPENSSL_BUFFERED_NETWORK
#include "networks/openssl_buffered.h"
#endif

struct table server_config = {0};

int init_server_network(void) {
	for (size_t i = 0; i < SERVER_CONFIG_LEN; i++) {
		if (set_table_index(&server_config, SERVER_CONFIG[i].sid, &(SERVER_CONFIG[i])) != 0) {
			return 1;
		}
	}

	if (protocols_init() != 0)
		return 1;

	return 0;
}

int start_server_network(void) {
#ifdef USE_PLAINTEXT_NETWORK
	if (start_server_network_threads(NET_TYPE_PLAINTEXT) != 0)
		return 1;
#endif
#ifdef USE_GNUTLS_NETWORK
	if (GNUTLS_CERT_PATH && GNUTLS_KEY_PATH)
		if (start_server_network_threads(NET_TYPE_GNUTLS) != 0)
			return 1;
#endif
#ifdef USE_OPENSSL_NETWORK
	if (OPENSSL_CERT_PATH && OPENSSL_KEY_PATH)
		if (start_server_network_threads(NET_TYPE_OPENSSL) != 0)
			return 1;
#endif
#ifdef USE_PLAINTEXT_BUFFERED_NETWORK
	if (start_server_network_threads(NET_TYPE_PLAINTEXT_BUFFERED) != 0)
		return 1;
#endif
#ifdef USE_GNUTLS_BUFFERED_NETWORK
	if (GNUTLS_CERT_PATH && GNUTLS_KEY_PATH)
		if (start_server_network_threads(NET_TYPE_GNUTLS_BUFFERED) != 0)
			return 1;
#endif
#ifdef USE_OPENSSL_BUFFERED_NETWORK
	if (OPENSSL_CERT_PATH && OPENSSL_KEY_PATH)
		if (start_server_network_threads(NET_TYPE_OPENSSL_BUFFERED) != 0)
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
	for (size_t i = 0; i < NUM_PROTOCOLS; i++) {
		if (active_protocols[i] && SERVER_INCOMING[net][i]) {
#ifdef USE_IPv4
			type = malloc(sizeof(*type));
			if (!type)
				return 1;
			type->net_type = net;
			type->protocol = i;
			type->family = AF_INET;
			type->is_incoming = 1;
			if (pthread_create(&trash, &pthread_attr, server_accept_thread, type) != 0) {
				free(type);
				return 1;
			}
#endif

#ifdef USE_IPv6
			type = malloc(sizeof(*type));
			if (!type)
				return 1;
			type->net_type = net;
			type->protocol = i;
			type->family = AF_INET6;
			type->is_incoming = 1;
			if (pthread_create(&trash, &pthread_attr, server_accept_thread, type) != 0) {
				free(type);
				return 1;
			}
#endif
		}
	}
	return 0;
}

void * server_accept_thread(void *type) {
	size_t net;
	size_t protocol;
	int family;
	{
		struct server_network_info *t = type;
		net = t->net_type;
		protocol = t->protocol;
		family = t->family;
	}

	int listen_fd = socket(family, SOCK_STREAM, IPPROTO_TCP);
	if (listen_fd < 0)
		return 0;

	{
		int one = 1;
		setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	}

	{
		struct sockaddr_storage sockaddr = {
			.ss_family = family,
		};

		if (0) {
#ifdef USE_IPv4
		} else if (family == AF_INET) {
			((struct sockaddr_in *)&sockaddr)->sin_port = htons(SERVER_PORTS[net][protocol]);
#endif

#ifdef USE_IPv6
		} else if (family == AF_INET6) {
			int one = 1;
			setsockopt(listen_fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));
			struct addrinfo hints = {
				.ai_family = family,
				.ai_socktype = SOCK_STREAM,
				.ai_protocol = IPPROTO_TCP,
				.ai_flags = AI_PASSIVE | AI_NUMERICSERV,
			};
			struct addrinfo *res;
			int success = getaddrinfo(NULL, "0", &hints, &res);
			if (success != 0)
				return 0;
			memcpy(&sockaddr, res->ai_addr, res->ai_addrlen);
			freeaddrinfo(res);
			((struct sockaddr_in6 *)&sockaddr)->sin6_port = htons(SERVER_PORTS[net][protocol]);
#endif
		}

		size_t listen_number = SERVER_LISTEN[net][protocol];

		if (bind(listen_fd, (struct sockaddr*)&sockaddr, sizeof(sockaddr)) != 0)
			return 0;

		listen(listen_fd, listen_number);
	}

	while (1) {
		struct string address;
		void *con_handle;
		int con_fd = networks[net].accept(listen_fd, &con_handle, &address);
		if (con_fd == -1) {
			sleep(60);
			continue; // TODO: Handle error
		}

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

int add_server(struct string from, struct string attached_to, struct string sid, struct string name, struct string fullname, size_t protocol, size_t net, void *handle) {
	struct server_info *attached = get_table_index(server_list, attached_to);
	if (!attached)
		return 1;

	if (has_table_index(server_list, sid))
		return 1;

	struct server_info *new_info;
	new_info = malloc(sizeof(*new_info));
	if (!new_info)
		return 1;

	new_info->protocol = protocol;
	new_info->net = net;
	new_info->handle = handle;
	new_info->latency_valid = 0;
	new_info->awaiting_pong = 0;

	if (str_clone(&(new_info->sid), sid) != 0)
		goto add_server_free_new_info;

	if (str_clone(&(new_info->name), name) != 0)
		goto add_server_free_sid;

	if (str_clone(&(new_info->fullname), fullname) != 0)
		goto add_server_free_name;

	// new_info->next shares string with sid of the server it points to

	new_info->connected_to = (struct table){.array = malloc(0), .len = 0};
	if (set_table_index(&(new_info->connected_to), attached_to, attached) != 0)
		goto add_server_free_connected_to;

	if (set_table_index(&(attached->connected_to), sid, new_info) != 0)
		goto add_server_clear_connected_to;

	new_info->user_list = (struct table){.array = malloc(0), .len = 0};

	if (set_table_index(&(server_list), sid, new_info) != 0)
		goto add_server_remove_attached_connected_to;

	protocols[protocol].update_propagations();

	protocols_propagate_new_server(from, attached_to, new_info);

	return 0;

	add_server_remove_attached_connected_to:
	remove_table_index(&(attached->connected_to), sid);
	add_server_clear_connected_to:
	clear_table(&(new_info->connected_to));
	add_server_free_connected_to:
	free(new_info->connected_to.array);
	free(new_info->fullname.data);
	add_server_free_name:
	free(new_info->name.data);
	add_server_free_sid:
	free(new_info->sid.data);
	add_server_free_new_info:
	free(new_info);
	return 1;
}

void free_server(struct server_info *server) {
	free(server->sid.data);
	free(server->name.data);
	free(server->fullname.data);
	clear_table(&(server->connected_to));
	free(server->connected_to.array);
	clear_table(&(server->user_list));
	free(server->user_list.array);

	free(server);
}

void remove_server(struct string from, struct server_info *server, struct string reason) {
	protocols_propagate_remove_server(from, server, reason);

	while (server->user_list.len != 0) {
		remove_user(from, server->user_list.array[0].ptr, reason, 0);
	}

	for (size_t i = 0; i < server->connected_to.len; i++) {
		struct server_info *adjacent = server->connected_to.array[i].ptr;
		remove_table_index(&(adjacent->connected_to), server->sid);
	}

	remove_table_index(&(server_list), server->sid);

	free_server(server);
}

void unlink_server(struct string from, struct server_info *a, struct server_info *b, size_t protocol) {
	if (!has_table_index(a->connected_to, b->sid))
		return;

	remove_table_index(&(a->connected_to), b->sid);
	remove_table_index(&(b->connected_to), a->sid);

	protocols[protocol].update_propagations();

	protocols_propagate_unlink_server(from, a, b, protocol);

	protocols[protocol].do_unlink(from, a, b);
}
