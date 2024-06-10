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

#include <stddef.h>

#include "haxstring.h"
#include "table.h"

struct server_network_info {
	size_t net_type;
	size_t protocol;
	char is_incoming;
};

struct server_connection_info {
	struct string address;
	struct server_config *config;
	struct server_network_info *type;
	int fd;
	void *handle;
};

struct server_info {
	struct string sid;
	struct string name;
	struct string fullname;

	struct string next; // Self for self, else which server we should send a message to to get to this server

	struct table connected_to; // List of servers that this server is connected to

	struct table user_list;

	void *handle;

	size_t protocol;
	size_t net;

	size_t distance;
};

int init_server_network(void);
int start_server_network(void);
int start_server_network_threads(size_t net);

void * server_accept_thread(void *type);

void * handle_server_thread(void *type);

int add_server(struct string from, struct string attached_to, struct string sid, struct string name, struct string fullname, size_t protocol, size_t net, void *handle);
void free_server(struct server_info *server);

void update_all_propagations(void);
void unlink_server(struct string from, struct server_info *a, struct server_info *b, size_t protocol);

extern struct table server_config;

extern struct table server_list;
