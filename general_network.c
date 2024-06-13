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
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "config.h"
#include "general_network.h"
#include "haxstring.h"
#include "haxstring_utils.h"

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
		.shutdown = plaintext_shutdown,
		.close = plaintext_close,
	},
#endif
#ifdef USE_GNUTLS
	[NET_TYPE_GNUTLS] = {
		.send = gnutls_send,
		.recv = gnutls_recv,
		.connect = gnutls_connect,
		.accept = gnutls_accept,
		.shutdown = gnutls_shutdown,
		.close = gnutls_close,
	},
#endif
#ifdef USE_OPENSSL
	[NET_TYPE_OPENSSL] = {
		.send = openssl_send,
		.recv = openssl_recv,
		.connect = openssl_connect,
		.accept = openssl_accept,
		.shutdown = openssl_shutdown,
		.close = openssl_close,
	},
#endif
};

struct table server_list = {0};
struct table user_list = {0};

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

	server_list.array = malloc(0);

	struct server_info *own_info;
	own_info = malloc(sizeof(*own_info));
	if (!own_info)
		goto init_general_network_free_server_list;

	if (str_clone(&(own_info->sid), SID) != 0)
		goto init_general_network_free_own_info;

	if (str_clone(&(own_info->name), SERVER_NAME) != 0)
		goto init_general_network_free_sid;

	if (str_clone(&(own_info->fullname), SERVER_FULLNAME) != 0)
		goto init_general_network_free_name;

	if (set_table_index(&server_list, SID, own_info) != 0)
		goto init_general_network_free_fullname;

	own_info->next = SID;
	own_info->connected_to = (struct table){.array = malloc(0), .len = 0};
	own_info->user_list = (struct table){.array = malloc(0), .len = 0};
	own_info->distance = 0;
	own_info->net = 0;
	own_info->protocol = 0;

	user_list.array = malloc(0);

	return 0;

	init_general_network_free_fullname:
	free(own_info->fullname.data);
	init_general_network_free_name:
	free(own_info->name.data);
	init_general_network_free_sid:
	free(own_info->sid.data);
	init_general_network_free_own_info:
	free(own_info);
	init_general_network_free_server_list:
	free(server_list.array);

	return 1;
}

int add_user(struct string from, struct string attached_to, struct string uid, struct string nick, struct string fullname, struct string ident, struct string vhost, struct string host, struct string address, size_t user_ts, size_t nick_ts, void *handle, size_t protocol, size_t net) {
	struct server_info *attached = get_table_index(server_list, attached_to);
	if (!attached)
		return 1;

	if (has_table_index(user_list, uid))
		return 1;

	struct user_info *new_info;
	new_info = malloc(sizeof(*new_info));
	if (!new_info)
		return 1;

	new_info->user_ts = user_ts;
	new_info->nick_ts = nick_ts;

	new_info->protocol = protocol;
	new_info->net = net;
	new_info->handle = handle;

	new_info->server = attached->sid;

	if (unsigned_to_str(user_ts, &(new_info->user_ts_str)) != 0)
		goto add_user_free_info;

	if (unsigned_to_str(nick_ts, &(new_info->nick_ts_str)) != 0)
		goto add_user_free_user_ts;

	if (str_clone(&(new_info->uid), uid) != 0)
		goto add_user_free_nick_ts;

	if (str_clone(&(new_info->nick), nick) != 0)
		goto add_user_free_uid;

	if (str_clone(&(new_info->fullname), fullname) != 0)
		goto add_user_free_nick;

	if (str_clone(&(new_info->ident), ident) != 0)
		goto add_user_free_fullname;

	if (str_clone(&(new_info->vhost), vhost) != 0)
		goto add_user_free_ident;

	if (str_clone(&(new_info->host), host) != 0)
		goto add_user_free_vhost;

	if (str_clone(&(new_info->address), address) != 0)
		goto add_user_free_host;

	if (set_table_index(&user_list, uid, new_info) != 0)
		goto add_user_free_address;

	if (set_table_index(&(attached->user_list), uid, new_info) != 0)
		goto add_user_remove_user_list;

	new_info->channel_list.array = malloc(0);
	new_info->channel_list.len = 0;

#ifdef USE_SERVER
#ifdef USE_HAXIRCD_PROTOCOL
	protocols[HAXIRCD_PROTOCOL].propagate_new_user(from, new_info);
#endif
#ifdef USE_INSPIRCD2_PROTOCOL
	protocols[INSPIRCD2_PROTOCOL].propagate_new_user(from, new_info);
#endif
#endif

	return 0;

	add_user_remove_user_list:
	remove_table_index(&user_list, uid);
	add_user_free_address:
	free(new_info->address.data);
	add_user_free_host:
	free(new_info->host.data);
	add_user_free_vhost:
	free(new_info->vhost.data);
	add_user_free_ident:
	free(new_info->ident.data);
	add_user_free_fullname:
	free(new_info->fullname.data);
	add_user_free_nick:
	free(new_info->nick.data);
	add_user_free_uid:
	free(new_info->uid.data);
	add_user_free_nick_ts:
	free(new_info->nick_ts_str.data);
	add_user_free_user_ts:
	free(new_info->user_ts_str.data);
	add_user_free_info:
	free(new_info);

	return 1;
}

int rename_user(struct string from, struct user_info *user, struct string nick, size_t timestamp) {
	struct string timestamp_str;
	if (unsigned_to_str(timestamp, &timestamp_str) != 0)
		return 1;

	void *tmp = malloc(nick.len);
	if (!tmp) {
		free(timestamp_str.data);
		return 1;
	}

#ifdef USE_SERVER
#ifdef USE_HAXIRCD_PROTOCOL
	protocols[HAXIRCD_PROTOCOL].propagate_rename_user(from, user, nick, timestamp, timestamp_str);
#endif
#ifdef USE_INSPIRCD2_PROTOCOL
	protocols[INSPIRCD2_PROTOCOL].propagate_rename_user(from, user, nick, timestamp, timestamp_str);
#endif
#endif

	free(user->nick.data);
	user->nick.data = tmp;
	memcpy(user->nick.data, nick.data, nick.len);
	user->nick.len = nick.len;

	return 0;
}

void remove_user(struct string from, struct user_info *user, struct string reason, char propagate) {
#ifdef USE_SERVER
	if (propagate) {
#ifdef USE_HAXIRCD_PROTOCOL
		protocols[HAXIRCD_PROTOCOL].propagate_remove_user(from, user, reason);
#endif
#ifdef USE_INSPIRCD2_PROTOCOL
		protocols[INSPIRCD2_PROTOCOL].propagate_remove_user(from, user, reason);
#endif
	}
#endif

	remove_table_index(&user_list, user->uid);

	struct server_info *server = get_table_index(server_list, user->server);
	if (server) {
		remove_table_index(&(server->user_list), user->uid);
	}

	// TODO: Channel cleanup code hereish
	clear_table(&(user->channel_list));
	free(user->channel_list.array);

	free(user->user_ts_str.data);
	free(user->nick_ts_str.data);
	free(user->uid.data);
	free(user->nick.data);
	free(user->fullname.data);
	free(user->ident.data);
	free(user->vhost.data);
	free(user->host.data);
	free(user->address.data);
	free(user);
}

void kill_user(struct string from, struct string source, struct user_info *user, struct string reason) {
#ifdef USE_SERVER
#ifdef USE_HAXIRCD_PROTOCOL
	protocols[HAXIRCD_PROTOCOL].propagate_kill_user(from, source, user, reason);
#endif
#ifdef USE_INSPIRCD2_PROTOCOL
	protocols[INSPIRCD2_PROTOCOL].propagate_kill_user(from, source, user, reason);
#endif
#endif

	remove_user(from, user, reason, 0);
}
