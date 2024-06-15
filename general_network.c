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

#ifdef USE_PSUEDOCLIENTS
#include "psuedoclients.h"
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
struct table channel_list = {0};

int resolve(struct string address, struct string port, struct sockaddr *sockaddr) {
	// NULL isn't really valid in this anyways so... just checking it and replacing with null-terminated for now
	for (size_t i = 0; i < address.len; i++)
		if (address.data[i] == 0)
			return 1;
	for (size_t i = 0; i < port.len; i++)
		if (port.data[i] == 0)
			return 1;

	char *addr_null = malloc(address.len+1);
	if (!addr_null)
		return 1;
	memcpy(addr_null, address.data, address.len);
	addr_null[address.len] = 0;

	char *port_null = malloc(port.len+1);
	if (!port_null) {
		free(addr_null);
		return 1;
	}
	memcpy(port_null, port.data, port.len);
	port_null[port.len] = 0;

	int success;
	struct addrinfo hints = {
		.ai_family = AF_INET,
		.ai_socktype = SOCK_STREAM,
		.ai_protocol = IPPROTO_TCP,
		.ai_flags = AI_NUMERICSERV | AI_ADDRCONFIG,
	};
	struct addrinfo *info;

	success = getaddrinfo(addr_null, port_null, &hints, &info);

	if (success == 0) {
		*sockaddr = *(info->ai_addr);
		freeaddrinfo(info);
	}

	free(port_null);
	free(addr_null);
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
	own_info->awaiting_pong = 0;
	own_info->latency = (struct timeval){0};
	own_info->latency_valid = 1;

	user_list.array = malloc(0);
	channel_list.array = malloc(0);

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

int add_user(struct string from, struct string attached_to, struct string uid, struct string nick, struct string fullname, struct string ident, struct string vhost, struct string host, struct string address, size_t user_ts, size_t nick_ts, void *handle, size_t protocol, size_t net, char is_psuedoclient, size_t psuedoclient) {
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

	new_info->is_psuedoclient = is_psuedoclient;
	new_info->psuedoclient = psuedoclient;

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

	while (user->channel_list.len != 0)
		part_channel(from, user->channel_list.array[0].ptr, user, STRING(""), 0);
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

int kill_user(struct string from, struct string source, struct user_info *user, struct string reason) {
#ifdef USE_PSUEDOCLIENTS
	if (user->is_psuedoclient) {
		switch (user->psuedoclient) {
#ifdef USE_HAXSERV_PSUEDOCLIENT
			case HAXSERV_PSUEDOCLIENT:
				if (!psuedoclients[HAXSERV_PSUEDOCLIENT].allow_kill(from, source, user, reason))
					return 1;
				break;
#endif
			default:
				break;
		}
	}
#endif

#ifdef USE_SERVER
#ifdef USE_HAXIRCD_PROTOCOL
	protocols[HAXIRCD_PROTOCOL].propagate_kill_user(from, source, user, reason);
#endif
#ifdef USE_INSPIRCD2_PROTOCOL
	protocols[INSPIRCD2_PROTOCOL].propagate_kill_user(from, source, user, reason);
#endif
#endif

	remove_user(from, user, reason, 0);

	return 0;
}

int set_channel(struct string from, struct string name, size_t timestamp, size_t user_count, struct user_info **users) {
	char is_new_channel;
	struct channel_info *channel = get_table_index(channel_list, name);
	if (!channel) {
		is_new_channel = 1;
		channel = malloc(sizeof(*channel));
		if (!channel)
			return -1;

		channel->channel_ts = timestamp;

		if (set_table_index(&channel_list, name, channel) != 0)
			goto set_channel_free_channel;

		if (str_clone(&(channel->name), name) != 0)
			goto set_channel_remove_channel;

		channel->user_list.array = malloc(0);
		channel->user_list.len = 0;
	} else {
		is_new_channel = 0;
		size_t i = 0;
		while (i < user_count) {
			if (has_table_index(channel->user_list, users[i]->uid)) {
				memcpy(&(users[i]), &(users[i+1]), sizeof(**users) * (user_count - i - 1));
				user_count--;
			} else {
				i++;
			}
		}
	}

	if (join_channel(from, channel, user_count, users, 0) != 0)
		goto set_channel_free_name;

	{
		struct string ts_str;
		if (unsigned_to_str(timestamp, &ts_str) != 0)
			goto set_channel_remove_users;

		channel->channel_ts_str = ts_str;
		channel->channel_ts = timestamp;
	}

#ifdef USE_SERVER
#ifdef USE_HAXIRCD_PROTOCOL
	protocols[HAXIRCD_PROTOCOL].propagate_set_channel(from, channel, is_new_channel, user_count, users);
#endif
#ifdef USE_INSPIRCD2_PROTOCOL
	protocols[INSPIRCD2_PROTOCOL].propagate_set_channel(from, channel, is_new_channel, user_count, users);
#endif
#endif

	return 0;

	set_channel_remove_users:
	for (size_t i = 0; i < user_count; i++) {
		remove_table_index(&(channel->user_list), users[i]->uid);
		remove_table_index(&(users[i]->channel_list), channel->name);
	}

	set_channel_free_name:
	if (is_new_channel)
		free(channel->name.data);
	set_channel_remove_channel:
	if (is_new_channel)
		remove_table_index(&channel_list, name);
	set_channel_free_channel:
	if (is_new_channel)
		free(channel);

	return -1;
}

int join_channel(struct string from, struct channel_info *channel, size_t user_count, struct user_info **users, char propagate) {
	size_t i = 0;
	while (i < user_count) {
		if (has_table_index(channel->user_list, users[i]->uid)) {
			memcpy(&(users[i]), &(users[i+1]), sizeof(**users) * (user_count - i - 1));
			user_count--;
		} else {
			i++;
		}
	}

	i = 0;
	while (i < user_count) {
		if (set_table_index(&(channel->user_list), users[i]->uid, users[i]) != 0)
			goto join_channel_remove_users;
		i++;
	}

	i = 0;
	while (i < user_count) {
		if (set_table_index(&(users[i]->channel_list), channel->name, channel) != 0)
			goto join_channel_remove_channels;
		i++;
	}

	if (propagate) {
#ifdef USE_CLIENT
#endif

#ifdef USE_SERVER
#ifdef USE_HAXIRCD_PROTOCOL
		protocols[HAXIRCD_PROTOCOL].propagate_join_channel(from, channel, user_count, users);
#endif
#ifdef USE_INSPIRCD2_PROTOCOL
		protocols[INSPIRCD2_PROTOCOL].propagate_join_channel(from, channel, user_count, users);
#endif
#endif
	}

	return 0;

	join_channel_remove_channels:
	for (size_t x = 0; x < i; x++)
		remove_table_index(&(users[x]->channel_list), channel->name);
	i = user_count;
	join_channel_remove_users:
	for (size_t x = 0; x < i; x++)
		remove_table_index(&(channel->user_list), users[x]->uid);

	return -1;
}

void part_channel(struct string from, struct channel_info *channel, struct user_info *user, struct string reason, char propagate) {
	remove_table_index(&(channel->user_list), user->uid);
	remove_table_index(&(user->channel_list), channel->name);

	if (propagate) {
#ifdef USE_SERVER
#ifdef USE_HAXIRCD_PROTOCOL
		protocols[HAXIRCD_PROTOCOL].propagate_part_channel(from, channel, user, reason);
#endif
#ifdef USE_INSPIRCD2_PROTOCOL
		protocols[INSPIRCD2_PROTOCOL].propagate_part_channel(from, channel, user, reason);
#endif
#endif
	}

	if (channel->user_list.len == 0) {
		remove_table_index(&channel_list, channel->name);
		free(channel->name.data);
		free(channel->channel_ts_str.data);
		free(channel->user_list.array);
		free(channel);
	}
}

int kick_channel(struct string from, struct string source, struct channel_info *channel, struct user_info *user, struct string reason) {
#ifdef USE_PSUEDOCLIENTS
	if (user->is_psuedoclient) {
		switch (user->psuedoclient) {
#ifdef USE_HAXSERV_PSUEDOCLIENT
			case HAXSERV_PSUEDOCLIENT:
				if (!psuedoclients[HAXSERV_PSUEDOCLIENT].allow_kick(from, source, channel, user, reason))
					return 1;
				break;
#endif
			default:
				break;
		}
	}
#endif

#ifdef USE_SERVER
#ifdef USE_HAXIRCD_PROTOCOL
	protocols[HAXIRCD_PROTOCOL].propagate_kick_channel(from, source, channel, user, reason);
#endif
#ifdef USE_INSPIRCD2_PROTOCOL
	protocols[INSPIRCD2_PROTOCOL].propagate_kick_channel(from, source, channel, user, reason);
#endif
#endif

	return 1;
}

int privmsg(struct string from, struct string sender, struct string target, struct string msg) {
	struct user_info *user;
	struct server_info *server;
	struct channel_info *channel;
	do {
		user = get_table_index(user_list, target);
		if (user)
			break;
		server = get_table_index(server_list, target);
		if (server)
			break;

		channel = get_table_index(channel_list, target);
		if (channel)
			break;

		char found = 0;
		for (size_t i = 0; i < user_list.len; i++) {
			user = user_list.array[i].ptr;
			if (STRING_EQ(user->nick, target)) {
				target = user->uid;
				found = 1;
				break;
			}
		}
		if (found)
			break;

		return 1; // Target not valid
	} while (0);

#ifdef USE_SERVER
#ifdef USE_HAXIRCD_PROTOCOL
	protocols[HAXIRCD_PROTOCOL].propagate_privmsg(from, sender, target, msg);
#endif
#ifdef USE_INSPIRCD2_PROTOCOL
	protocols[INSPIRCD2_PROTOCOL].propagate_privmsg(from, sender, target, msg);
#endif
#endif

#ifdef USE_PSUEDOCLIENTS
	if ((user && user->is_psuedoclient && user->psuedoclient == HAXSERV_PSUEDOCLIENT) || (!user && !server)) {
		char send;
		if (!user && !server) {
			send = 0;
			for (size_t i = 0; i < channel->user_list.len; i++) {
				struct user_info *user = channel->user_list.array[i].ptr;
				if (user->is_psuedoclient && user->psuedoclient == HAXSERV_PSUEDOCLIENT && !STRING_EQ(sender, user->uid)) {
					send = 1;
					break;
				}
			}
		} else {
			send = 1;
		}
		if (send)
			psuedoclients[HAXSERV_PSUEDOCLIENT].handle_privmsg(from, sender, target, msg);
	}
#endif

	return 0;
}

int notice(struct string from, struct string sender, struct string target, struct string msg) {
	do {
		struct user_info *user = get_table_index(user_list, target);
		if (user)
			break;
		struct server_info *server = get_table_index(server_list, target);
		if (server)
			break;

		char found = 0;
		for (size_t i = 0; i < user_list.len; i++) {
			user = user_list.array[i].ptr;
			if (STRING_EQ(user->nick, target)) {
				target = user->uid;
				found = 1;
				break;
			}
		}
		if (found)
			break;

		struct channel_info *channel = get_table_index(channel_list, target);
		if (channel)
			break;

		return 1; // Target not valid
	} while (0);

#ifdef USE_SERVER
#ifdef USE_HAXIRCD_PROTOCOL
	protocols[HAXIRCD_PROTOCOL].propagate_notice(from, sender, target, msg);
#endif
#ifdef USE_INSPIRCD2_PROTOCOL
	protocols[INSPIRCD2_PROTOCOL].propagate_notice(from, sender, target, msg);
#endif
#endif

	return 0;
}
