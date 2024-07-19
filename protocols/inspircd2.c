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

#include <pthread.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#include "../config.h"
#include "../general_network.h"
#include "../haxstring.h"
#include "../haxstring_utils.h"
#include "../main.h"
#include "../mutex.h"
#include "../server_network.h"
#include "inspircd2.h"

struct table inspircd2_protocol_init_commands = {0};
struct table inspircd2_protocol_commands = {0};

char inspircd2_protocol_user_mode_types[UCHAR_MAX+1] = {
	['c'] = MODE_TYPE_NOARGS,
	['d'] = MODE_TYPE_NOARGS,
	['g'] = MODE_TYPE_NOARGS,
	['h'] = MODE_TYPE_NOARGS,
	['i'] = MODE_TYPE_NOARGS,
	['k'] = MODE_TYPE_NOARGS,
	['o'] = MODE_TYPE_NOARGS,
	['r'] = MODE_TYPE_NOARGS,
	['s'] = MODE_TYPE_MODE,
	['w'] = MODE_TYPE_NOARGS,
	['x'] = MODE_TYPE_NOARGS,
	['z'] = MODE_TYPE_NOARGS,
	['B'] = MODE_TYPE_NOARGS,
	['D'] = MODE_TYPE_NOARGS,
	['G'] = MODE_TYPE_NOARGS,
	['H'] = MODE_TYPE_NOARGS,
	['I'] = MODE_TYPE_NOARGS,
	['L'] = MODE_TYPE_NOARGS,
	['N'] = MODE_TYPE_NOARGS,
	['O'] = MODE_TYPE_NOARGS,
	['R'] = MODE_TYPE_NOARGS,
	['S'] = MODE_TYPE_NOARGS,
	['T'] = MODE_TYPE_NOARGS,
	['W'] = MODE_TYPE_NOARGS,
};

char inspircd2_protocol_channel_mode_types[UCHAR_MAX+1] = {
	['a'] = MODE_TYPE_USERS,
	['b'] = MODE_TYPE_MULTIPLE,
	['c'] = MODE_TYPE_NOARGS,
	['d'] = MODE_TYPE_REPLACE,
	['e'] = MODE_TYPE_MULTIPLE,
	['f'] = MODE_TYPE_REPLACE,
	['g'] = MODE_TYPE_REPLACE,
	['h'] = MODE_TYPE_USERS,
	['i'] = MODE_TYPE_NOARGS,
	['j'] = MODE_TYPE_REPLACE,
	['k'] = MODE_TYPE_REPLACE,
	['l'] = MODE_TYPE_REPLACE,
	['m'] = MODE_TYPE_NOARGS,
	['n'] = MODE_TYPE_NOARGS,
	['o'] = MODE_TYPE_USERS,
	['p'] = MODE_TYPE_NOARGS,
	['q'] = MODE_TYPE_USERS,
	['r'] = MODE_TYPE_NOARGS,
	['s'] = MODE_TYPE_NOARGS,
	['t'] = MODE_TYPE_NOARGS,
	['u'] = MODE_TYPE_NOARGS,
	['v'] = MODE_TYPE_USERS,
	['w'] = MODE_TYPE_MULTIPLE,
	['z'] = MODE_TYPE_NOARGS,
	['A'] = MODE_TYPE_NOARGS,
	['B'] = MODE_TYPE_NOARGS,
	['C'] = MODE_TYPE_NOARGS,
	['D'] = MODE_TYPE_NOARGS,
	['E'] = MODE_TYPE_REPLACE,
	['F'] = MODE_TYPE_REPLACE,
	['G'] = MODE_TYPE_NOARGS,
	['H'] = MODE_TYPE_REPLACE,
	['I'] = MODE_TYPE_MULTIPLE,
	['J'] = MODE_TYPE_REPLACE,
	['K'] = MODE_TYPE_NOARGS,
	['L'] = MODE_TYPE_REPLACE,
	['M'] = MODE_TYPE_NOARGS,
	['N'] = MODE_TYPE_NOARGS,
	['O'] = MODE_TYPE_NOARGS,
	['P'] = MODE_TYPE_NOARGS,
	['Q'] = MODE_TYPE_NOARGS,
	['R'] = MODE_TYPE_NOARGS,
	['S'] = MODE_TYPE_NOARGS,
	['T'] = MODE_TYPE_NOARGS,
	['X'] = MODE_TYPE_MULTIPLE,
};

int init_inspircd2_protocol(void) {
	inspircd2_protocol_commands.array = malloc(0);

	set_table_index(&inspircd2_protocol_init_commands, STRING("CAPAB"), &inspircd2_protocol_init_handle_capab);
	set_table_index(&inspircd2_protocol_init_commands, STRING("SERVER"), &inspircd2_protocol_init_handle_server);



	set_table_index(&inspircd2_protocol_commands, STRING("PING"), &inspircd2_protocol_handle_ping);
	set_table_index(&inspircd2_protocol_commands, STRING("PONG"), &inspircd2_protocol_handle_pong);

	set_table_index(&inspircd2_protocol_commands, STRING("SERVER"), &inspircd2_protocol_handle_server);
	set_table_index(&inspircd2_protocol_commands, STRING("SQUIT"), &inspircd2_protocol_handle_squit);
	set_table_index(&inspircd2_protocol_commands, STRING("RSQUIT"), &inspircd2_protocol_handle_rsquit);

	set_table_index(&inspircd2_protocol_commands, STRING("UID"), &inspircd2_protocol_handle_uid);
	set_table_index(&inspircd2_protocol_commands, STRING("NICK"), &inspircd2_protocol_handle_nick);
	set_table_index(&inspircd2_protocol_commands, STRING("QUIT"), &inspircd2_protocol_handle_quit);
	set_table_index(&inspircd2_protocol_commands, STRING("KILL"), &inspircd2_protocol_handle_kill);
	set_table_index(&inspircd2_protocol_commands, STRING("OPERTYPE"), &inspircd2_protocol_handle_opertype);

	set_table_index(&inspircd2_protocol_commands, STRING("FJOIN"), &inspircd2_protocol_handle_fjoin);
	set_table_index(&inspircd2_protocol_commands, STRING("PART"), &inspircd2_protocol_handle_part);
	set_table_index(&inspircd2_protocol_commands, STRING("KICK"), &inspircd2_protocol_handle_kick);

	set_table_index(&inspircd2_protocol_commands, STRING("PRIVMSG"), &inspircd2_protocol_handle_privmsg);
	set_table_index(&inspircd2_protocol_commands, STRING("NOTICE"), &inspircd2_protocol_handle_notice);

	set_table_index(&inspircd2_protocol_commands, STRING("MODE"), &inspircd2_protocol_handle_mode);
	set_table_index(&inspircd2_protocol_commands, STRING("FMODE"), &inspircd2_protocol_handle_fmode);

	set_table_index(&inspircd2_protocol_commands, STRING("METADATA"), &inspircd2_protocol_handle_metadata);

	set_table_index(&inspircd2_protocol_commands, STRING("DUMP"), &inspircd2_protocol_handle_dump);

	return 0;
}

void init_inspircd2_protocol_fail(void) {
	clear_table(&inspircd2_protocol_commands);
	free(inspircd2_protocol_commands.array);
}

void * inspircd2_protocol_connection(void *type) {
	struct string address;
	size_t net;
	char is_incoming;
	int fd;
	void *handle;
	struct server_config *config;

	char ready = 0;

	{
		struct server_connection_info *t = type;
		address = t->address;
		fd = t->fd;
		handle = t->handle;
		config = t->config;
		net = t->type->net_type;
		is_incoming = t->type->is_incoming;
		if (is_incoming)
			free(type);
	}

	if (!is_incoming) {
		networks[net].send(handle, STRING("CAPAB START 1202\nCAPAB END\n"));

		networks[net].send(handle, STRING("SERVER "));
		networks[net].send(handle, SERVER_NAME);
		networks[net].send(handle, STRING(" "));
		networks[net].send(handle, config->out_pass);
		networks[net].send(handle, STRING(" 0 "));
		networks[net].send(handle, SID);
		networks[net].send(handle, STRING(" :"));
		networks[net].send(handle, SERVER_FULLNAME);
		networks[net].send(handle, STRING("\n"));
	}

	struct string full_msg = {.data = malloc(0), .len = 0};

	while (1) {
		size_t msg_len;
		size_t old_len;
		{
			char data[512];
			unsigned char timeout = 0;
			size_t new_len;
			while (1) {
				char err;
				new_len = networks[net].recv(handle, data, sizeof(data), &err);
				if (err >= 2) { // Connection closed, or some uncorrected error
					if (err == 2) {
						if (ready) {
							WRITES(2, STRING("[InspIRCd v2] ["));
							WRITES(2, config->name);
							WRITES(2, STRING("] Disconnected: recv failed (connection closed).\r\n\n"));
						} else {
							WRITES(2, STRING("[InspIRCd v2] [unidentified server] Disconnected: recv failed (connection closed).\r\n\n"));
						}
					} else {
						if (ready) {
							WRITES(2, STRING("[InspIRCd v2] ["));
							WRITES(2, config->name);
							WRITES(2, STRING("] Disconnected: recv failed (unknown network error).\r\n\n"));
						} else {
							WRITES(2, STRING("[InspIRCd v2] [unidentified server] Disconnected: recv failed (unknown network error).\r\n\n"));
						}
					}
					goto inspircd2_protocol_handle_connection_close;
				} else if (err == 1) { // Timed out
					if (ready) {
						if (timeout > 0) {
							WRITES(2, STRING("[InspIRCd v2] ["));
							WRITES(2, config->name);
							WRITES(2, STRING("] Disconnected: Ping timeout.\r\n\n"));
							goto inspircd2_protocol_handle_connection_close;
						}
						timeout++;

						mutex_lock(&(state_lock));
						networks[net].send(handle, STRING(":"));
						networks[net].send(handle, SID);
						networks[net].send(handle, STRING(" PING "));
						networks[net].send(handle, SID);
						networks[net].send(handle, STRING(" :"));
						networks[net].send(handle, config->sid);
						networks[net].send(handle, STRING("\n"));

						struct server_info *server = get_table_index(server_list, config->sid);
						server->awaiting_pong = 1;
						gettimeofday(&(server->last_ping), 0);

						mutex_unlock(&(state_lock));
					} else {
						WRITES(2, STRING("[InspIRCd v2] [unidentified server] Disconnected: Ping timeout.\r\n\n"));
						goto inspircd2_protocol_handle_connection_close;
					}
				} else {
					break;
				}
			}
			old_len = full_msg.len;
			full_msg.len += new_len;
			void *tmp = realloc(full_msg.data, full_msg.len);
			if (!tmp && full_msg.len + new_len != 0)
				goto inspircd2_protocol_handle_connection_close;
			full_msg.data = tmp;
			memcpy(full_msg.data + old_len, data, new_len);
		}

		while (1) {
			char found = 0;
			for (size_t i = old_len; i < full_msg.len; i++) {
				if (full_msg.data[i] == '\n') {
					found = 1;
					msg_len = i;
					break;
				}
			}
			if (!found)
				break;
			old_len = 0;

			struct string line = {.data = full_msg.data, .len = msg_len};

			if (ready) {
				WRITES(2, STRING("[InspIRCd v2] ["));
				WRITES(2, config->name);
				WRITES(2, STRING(" -> us] Got `"));
			} else {
				WRITES(2, STRING("[InspIRCd v2] [unidentified server -> us] Got `"));
			}
			WRITES(2, line);
			WRITES(2, STRING("'\r\n"));

			size_t offset = 0;
			while (offset < msg_len && full_msg.data[offset] == ' ')
				offset++;

			if (msg_len == offset) {
				WRITES(2, STRING("[InspIRCd v2] Protocol violation: empty message.\r\n\n"));
				goto inspircd2_protocol_handle_connection_close;
			}

			struct string source;
			if (full_msg.data[offset] == ':') {
				source.data = full_msg.data + offset + 1;
				found = 0;
				source.len = 0;
				for (size_t i = offset + 1; i < msg_len; i++) {
					if (full_msg.data[i] == ' ') {
						found = 1;
						source.len = i - offset - 1;
						offset = i + 1;
						while (offset < msg_len && full_msg.data[offset] == ' ')
							offset++;
						break;
					}
					source.len++;
				}
				if (source.len == 0) {
					WRITES(2, STRING("[InspIRCd v2] Protocol violation: source prefix but no source.\r\n\n"));
					goto inspircd2_protocol_handle_connection_close;
				}
				if (!found || offset >= msg_len) {
					WRITES(2, STRING("[InspIRCd v2] Protocol violation: source but no command.\r\n\n"));
					goto inspircd2_protocol_handle_connection_close;
				}

				if (STRING_EQ(source, SID)) {
					WRITES(2, STRING("[InspIRCd v2] Protocol violation: other server sent us as source!\r\n\n"));
					goto inspircd2_protocol_handle_connection_close;
				}
			} else {
				if (ready)
					source = config->sid;
				else
					source = (struct string){0};
			}

			struct string command;
			command.data = full_msg.data + offset;
			found = 0;
			for (size_t i = offset; i < msg_len; i++) {
				if (full_msg.data[i] == ' ') {
					found = 1;
					command.len = i - offset;
					offset = i + 1;
					while (offset < msg_len && full_msg.data[offset] == ' ')
						offset++;
					break;
				}
			}
			if (!found) {
				command.len = msg_len - offset;
				offset = msg_len;
			}

			size_t argc = 0;
			size_t old_offset = offset;
			while (offset < msg_len) {
				if (full_msg.data[offset] == ':') {
					argc++;
					break;
				}

				while (offset < msg_len && full_msg.data[offset] != ' ')
					offset++;

				argc++;

				while (offset < msg_len && full_msg.data[offset] == ' ')
					offset++;
			}
			offset = old_offset;

			struct string argv[argc]; // TODO: Maybe dynamically allocate this if it exceeds some number that probably shouldn't be put on the stack
			for (size_t i = 0; offset < msg_len;) {
				if (full_msg.data[offset] == ':') {
					argv[i].data = full_msg.data + offset + 1;
					argv[i].len = msg_len - offset - 1;
					break;
				}

				argv[i].data = full_msg.data + offset;
				size_t start = offset;

				while (offset < msg_len && full_msg.data[offset] != ' ')
					offset++;

				argv[i].len = offset - start;

				while (offset < msg_len && full_msg.data[offset] == ' ')
					offset++;

				i++;
			}

			mutex_lock(&state_lock);

			if (source.len != 0) {
				struct server_info *server;
				struct user_info *user = get_table_index(user_list, source);
				if (user)
					server = get_table_index(server_list, user->server);
				else
					server = get_table_index(server_list, source);

				if (!server)
					goto inspircd2_protocol_handle_connection_unlock_next;

				if (STRING_EQ(server->sid, SID) || !STRING_EQ(server->next, config->sid)) {
					WRITES(2, STRING("[InspIRCd v2] Protocol violation: sourge isn't on this link.\r\n\n"));
					goto inspircd2_protocol_handle_connection_unlock_close;
				}
			}

			if (!ready) {
				int (*func)(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config **config, char is_incoming);
				func = get_table_index(inspircd2_protocol_init_commands, command);
				if (!func) {
					WRITES(2, STRING("WARNING: Command is unknown, ignoring.\r\n"));
					goto inspircd2_protocol_handle_connection_unlock_next;
				}

				int res = func(source, argc, argv, net, handle, &config, is_incoming);
				if (res < 0) { // Disconnect
					WRITES(2, STRING("[InspIRCd v2] [unidentified server] Disconnected: Command handler returned < 0.\r\n\n"));
					goto inspircd2_protocol_handle_connection_unlock_close;
				} else if (res > 0) { // Connection is now "ready"
					ready = 1;
				}
			} else {
				int (*func)(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming);
				func = get_table_index(inspircd2_protocol_commands, command);
				if (!func) {
					WRITES(2, STRING("WARNING: Command is unknown, ignoring.\r\n"));
					goto inspircd2_protocol_handle_connection_unlock_next;
				}

				int res = func(source, argc, argv, net, handle, config, is_incoming);
				if (res < 0) { // Disconnect
					WRITES(2, STRING("[InspIRCd v2] ["));
					WRITES(2, config->name);
					WRITES(2, STRING("] Disconnected: Command handler returned < 0.\r\n\n"));
					goto inspircd2_protocol_handle_connection_unlock_close;
				}
			}

			inspircd2_protocol_handle_connection_unlock_next:
			WRITES(2, STRING("\n"));

			do_trivial_reloads();
			mutex_unlock(&state_lock);
			memmove(full_msg.data, full_msg.data + msg_len + 1, full_msg.len - msg_len - 1);
			full_msg.len -= msg_len + 1;
			void *tmp = realloc(full_msg.data, full_msg.len);
			if (tmp || full_msg.len == 0)
				full_msg.data = tmp;
		}
	}

	inspircd2_protocol_handle_connection_unlock_close:
	mutex_unlock(&state_lock);
	inspircd2_protocol_handle_connection_close:
	free(full_msg.data);

	if (ready) {
		mutex_lock(&(state_lock));
		unlink_server(config->sid, get_table_index(server_list, config->sid), self, INSPIRCD2_PROTOCOL);
		mutex_unlock(&(state_lock));
	}

	networks[net].close(fd, handle);
	free(address.data);

	return 0;
}

void * inspircd2_protocol_autoconnect(void *tmp) {
	struct server_config *config = tmp;

	struct server_connection_info *info;
	info = malloc(sizeof(*info));
	if (!info)
		return 0;

	struct server_network_info *type;
	type = malloc(sizeof(*type));
	if (!type) {
		free(info);
		return 0;
	}

	type->net_type = config->autoconnect_type;
	type->protocol = INSPIRCD2_PROTOCOL;
	type->is_incoming = 0;
	info->type = type;
	info->config = config;

	time_t last_time = 0;
	while (1) {
		for (time_t current = time(NULL); current < last_time + 10; current = time(NULL))
			sleep(10 - (current - last_time));
		last_time = time(NULL);

		info->fd = networks[type->net_type].connect(&(info->handle), config->address, config->port, &(info->address));
		if (info->fd == -1)
			continue;

		inspircd2_protocol_connection(info);
	}
}

void inspircd2_protocol_update_propagations_inner(struct server_info *source) {
	for (size_t i = 0; i < source->connected_to.len; i++) {
		struct server_info *adjacent = source->connected_to.array[i].ptr;
		if (adjacent->distance == 0 && !STRING_EQ(adjacent->sid, SID)) {
			adjacent->distance = source->distance + 1;
			if (adjacent->distance == 1) {
				adjacent->next = adjacent->sid;
			} else {
				adjacent->next = source->next;
				adjacent->handle = source->handle;
			}
			inspircd2_protocol_update_propagations_inner(adjacent);
		}
	}
}

void inspircd2_protocol_update_propagations(void) {
	for (size_t i = 0; i < server_list.len; i++) {
		struct server_info *other = server_list.array[i].ptr;
		if (other->protocol == INSPIRCD2_PROTOCOL) {
			other->distance = 0;
		}
	}

	inspircd2_protocol_update_propagations_inner(self);
}

void inspircd2_protocol_propagate(struct string from, struct string msg) {
	for (size_t i = 0; i < self->connected_to.len; i++) {
		struct server_info *adjacent = self->connected_to.array[i].ptr;
		if (adjacent->protocol != INSPIRCD2_PROTOCOL || STRING_EQ(from, adjacent->sid))
			continue; // Not ours or it's the source of this message

		networks[adjacent->net].send(adjacent->handle, msg);
	}
}

// [:source] SERVER <name> <password> <always 0> <sid> <fullname>
void inspircd2_protocol_propagate_new_server(struct string from, struct string attached_to, struct server_info *info) {
	inspircd2_protocol_propagate(from, STRING(":"));

	if (info->protocol == INSPIRCD2_PROTOCOL)
		inspircd2_protocol_propagate(from, attached_to);
	else // Just pretend servers connected via a different protocol are connected directly to us
		inspircd2_protocol_propagate(from, SID);

	inspircd2_protocol_propagate(from, STRING(" SERVER "));
	inspircd2_protocol_propagate(from, info->name);
	inspircd2_protocol_propagate(from, STRING(" * 0 "));
	inspircd2_protocol_propagate(from, info->sid);
	inspircd2_protocol_propagate(from, STRING(" :"));
	inspircd2_protocol_propagate(from, info->fullname);
	inspircd2_protocol_propagate(from, STRING("\n"));

	inspircd2_protocol_propagate(from, STRING(":"));
	inspircd2_protocol_propagate(from, info->sid);
	inspircd2_protocol_propagate(from, STRING(" BURST "));

	time_t current = time(0);
	struct string current_time;
	char err = unsigned_to_str((size_t)current, &current_time);

	if (current < 0 || err) {
		inspircd2_protocol_propagate(from, STRING("1"));
	} else {
		inspircd2_protocol_propagate(from, current_time);
		free(current_time.data);
	}

	inspircd2_protocol_propagate(from, STRING("\n:"));
	inspircd2_protocol_propagate(from, info->sid);
	inspircd2_protocol_propagate(from, STRING(" ENDBURST\n"));
}

// [:source] SQUIT <sid> [<reason>?]
void inspircd2_protocol_propagate_unlink_server(struct string from, struct server_info *a, struct server_info *b, size_t protocol) {
	struct server_info *source;
	struct server_info *target;
	if (a->distance == 0 && !STRING_EQ(a->sid, SID)) {
		source = b;
		target = a;
	} else if (b->distance == 0 && !STRING_EQ(b->sid, SID)) {
		source = a;
		target = b;
	} else {
		return;
	}

	inspircd2_protocol_propagate(from, STRING(":"));
	if (protocol == INSPIRCD2_PROTOCOL)
		inspircd2_protocol_propagate(from, source->sid);
	else
		inspircd2_protocol_propagate(from, SID);
	inspircd2_protocol_propagate(from, STRING(" SQUIT "));
	inspircd2_protocol_propagate(from, target->sid);
	inspircd2_protocol_propagate(from, STRING(" :\n"));
}

// [:source] UID <UID> <nick_ts> <nick> <host> <vhost> <ident> <address> <user_ts> <modes> [<mode args>] <fullname>
void inspircd2_protocol_propagate_new_user(struct string from, struct user_info *info) {
	inspircd2_protocol_propagate(from, STRING(":"));
	inspircd2_protocol_propagate(from, info->server);
	inspircd2_protocol_propagate(from, STRING(" UID "));
	inspircd2_protocol_propagate(from, info->uid);
	inspircd2_protocol_propagate(from, STRING(" "));
	inspircd2_protocol_propagate(from, info->nick_ts_str);
	inspircd2_protocol_propagate(from, STRING(" "));
	inspircd2_protocol_propagate(from, info->nick);
	inspircd2_protocol_propagate(from, STRING(" "));
	inspircd2_protocol_propagate(from, info->host);
	inspircd2_protocol_propagate(from, STRING(" "));
	inspircd2_protocol_propagate(from, info->vhost);
	inspircd2_protocol_propagate(from, STRING(" "));
	inspircd2_protocol_propagate(from, info->ident);
	inspircd2_protocol_propagate(from, STRING(" "));
	inspircd2_protocol_propagate(from, info->address);
	inspircd2_protocol_propagate(from, STRING(" "));
	inspircd2_protocol_propagate(from, info->user_ts_str);
	inspircd2_protocol_propagate(from, STRING(" + :"));
	inspircd2_protocol_propagate(from, info->fullname);
	inspircd2_protocol_propagate(from, STRING("\n"));
}

// :source NICK <nick> <timestamp>
void inspircd2_protocol_propagate_rename_user(struct string from, struct user_info *user, struct string nick, size_t timestamp, struct string timestamp_str, char forced, char immediate) {
	if (forced) {
		if (STRING_EQ(user->uid, nick)) {
			inspircd2_protocol_propagate(from, STRING(":"));
			inspircd2_protocol_propagate(from, from);
			inspircd2_protocol_propagate(from, STRING(" SAVE "));
			inspircd2_protocol_propagate(from, user->uid);
			inspircd2_protocol_propagate(from, STRING(" :"));
			inspircd2_protocol_propagate(from, user->nick_ts_str);
			inspircd2_protocol_propagate(from, STRING("\n"));
		} else {
			inspircd2_protocol_propagate(from, STRING(":"));
			inspircd2_protocol_propagate(from, from);
			inspircd2_protocol_propagate(from, STRING(" SANICK "));
			inspircd2_protocol_propagate(from, user->uid);
			inspircd2_protocol_propagate(from, STRING(" :"));
			inspircd2_protocol_propagate(from, nick);
			inspircd2_protocol_propagate(from, STRING("\n"));
		}
	} else {
		inspircd2_protocol_propagate(from, STRING(":"));
		inspircd2_protocol_propagate(from, user->uid);
		inspircd2_protocol_propagate(from, STRING(" NICK "));
		inspircd2_protocol_propagate(from, nick);
		inspircd2_protocol_propagate(from, STRING(" "));
		inspircd2_protocol_propagate(from, timestamp_str);
		inspircd2_protocol_propagate(from, STRING("\n"));
	}
}

// :source QUIT [<reason>?]
void inspircd2_protocol_propagate_remove_user(struct string from, struct user_info *info, struct string reason) {
	inspircd2_protocol_propagate(from, STRING(":"));
	inspircd2_protocol_propagate(from, info->uid);
	inspircd2_protocol_propagate(from, STRING(" QUIT :"));
	inspircd2_protocol_propagate(from, reason);
	inspircd2_protocol_propagate(from, STRING("\n"));
}

// [:source] KILL <target> [<reason>?]
void inspircd2_protocol_propagate_kill_user(struct string from, struct string source, struct user_info *info, struct string reason) {
	inspircd2_protocol_propagate(from, STRING(":"));
	inspircd2_protocol_propagate(from, source);
	inspircd2_protocol_propagate(from, STRING(" KILL "));
	inspircd2_protocol_propagate(from, info->uid);
	inspircd2_protocol_propagate(from, STRING(" :"));
	inspircd2_protocol_propagate(from, reason);
	inspircd2_protocol_propagate(from, STRING("\n"));
}

// :source OPERTYPE <type>
void inspircd2_protocol_propagate_oper_user(struct string from, struct user_info *user, struct string type, struct string source) {
	if (type.len == 0) {
		inspircd2_protocol_propagate(from, STRING(":"));
		inspircd2_protocol_propagate(from, source);
		inspircd2_protocol_propagate(from, STRING(" MODE "));
		inspircd2_protocol_propagate(from, user->uid);
		inspircd2_protocol_propagate(from, STRING(" -o\n"));
	} else {
		inspircd2_protocol_propagate(from, STRING(":"));
		inspircd2_protocol_propagate(from, user->uid);
		inspircd2_protocol_propagate(from, STRING(" OPERTYPE :"));
		inspircd2_protocol_propagate(from, type);
		inspircd2_protocol_propagate(from, STRING("\n"));
	}
}

// [:source] METADATA <user> accountname <account>
void inspircd2_protocol_propagate_set_account(struct string from, struct user_info *user, struct string account, struct string source) {
	inspircd2_protocol_propagate(from, STRING(":"));
	inspircd2_protocol_propagate(from, source);
	inspircd2_protocol_propagate(from, STRING(" METADATA "));
	inspircd2_protocol_propagate(from, user->uid);
	inspircd2_protocol_propagate(from, STRING(" accountname :"));
	inspircd2_protocol_propagate(from, account);
	inspircd2_protocol_propagate(from, STRING("\n"));
}

// [:source] METADATA <user> ssl_cert <vtrsE (none) | vTrse <cert>>
void inspircd2_protocol_propagate_set_cert(struct string from, struct user_info *user, struct string cert, struct string source) {
	inspircd2_protocol_propagate(from, STRING(":"));
	inspircd2_protocol_propagate(from, source);
	inspircd2_protocol_propagate(from, STRING(" METADATA "));
	inspircd2_protocol_propagate(from, user->uid);
	if (cert.len != 0) {
		inspircd2_protocol_propagate(from, STRING(" ssl_cert :vTrse "));
		inspircd2_protocol_propagate(from, cert);
		inspircd2_protocol_propagate(from, STRING("\n"));
	} else {
		inspircd2_protocol_propagate(from, STRING(" ssl_cert :vtrsE No certificate was found.\n"));
	}
}

// [:source] FJOIN <channel> <timestamp> <modes> [<mode args>] <userlist: modes,uid [...]>
void inspircd2_protocol_propagate_set_channel(struct string from, struct channel_info *channel, char is_new_server, size_t user_count, struct user_info **users) {
	inspircd2_protocol_propagate(from, STRING(":"));
	inspircd2_protocol_propagate(from, SID);
	inspircd2_protocol_propagate(from, STRING(" FJOIN "));
	inspircd2_protocol_propagate(from, channel->name);
	inspircd2_protocol_propagate(from, STRING(" "));
	inspircd2_protocol_propagate(from, channel->channel_ts_str);
	inspircd2_protocol_propagate(from, STRING(" + :"));
	for (size_t x = 0; x < user_count; x++) {
		inspircd2_protocol_propagate(from, STRING(","));
		inspircd2_protocol_propagate(from, users[x]->uid);
		if (x != user_count - 1)
			inspircd2_protocol_propagate(from, STRING(" "));
	}
	inspircd2_protocol_propagate(from, STRING("\n"));
}

// [:source] FJOIN <channel> <timestamp> <modes> [<mode args>] <userlist: modes,uid [...]>
void inspircd2_protocol_propagate_join_channel(struct string from, struct channel_info *channel, size_t user_count, struct user_info **users) {
	inspircd2_protocol_propagate(from, STRING(":"));
	inspircd2_protocol_propagate(from, SID);
	inspircd2_protocol_propagate(from, STRING(" FJOIN "));
	inspircd2_protocol_propagate(from, channel->name);
	inspircd2_protocol_propagate(from, STRING(" "));
	inspircd2_protocol_propagate(from, channel->channel_ts_str);
	inspircd2_protocol_propagate(from, STRING(" + :"));
	for (size_t x = 0; x < user_count; x++) {
		inspircd2_protocol_propagate(from, STRING(","));
		inspircd2_protocol_propagate(from, users[x]->uid);
		if (x != user_count - 1)
			inspircd2_protocol_propagate(from, STRING(" "));
	}
	inspircd2_protocol_propagate(from, STRING("\n"));
}

// :source PART <channel> [<reason>]
void inspircd2_protocol_propagate_part_channel(struct string from, struct channel_info *channel, struct user_info *user, struct string reason) {
	inspircd2_protocol_propagate(from, STRING(":"));
	inspircd2_protocol_propagate(from, user->uid);
	inspircd2_protocol_propagate(from, STRING(" PART "));
	inspircd2_protocol_propagate(from, channel->name);
	inspircd2_protocol_propagate(from, STRING(" :"));
	inspircd2_protocol_propagate(from, reason);
	inspircd2_protocol_propagate(from, STRING("\n"));
}

// [:source] KICK <channel> <user> [<reason>]
void inspircd2_protocol_propagate_kick_channel(struct string from, struct string source, struct channel_info *channel, struct user_info *user, struct string reason) {
	inspircd2_protocol_propagate(from, STRING(":"));
	inspircd2_protocol_propagate(from, source);
	inspircd2_protocol_propagate(from, STRING(" KICK "));
	inspircd2_protocol_propagate(from, channel->name);
	inspircd2_protocol_propagate(from, STRING(" "));
	inspircd2_protocol_propagate(from, user->uid);
	inspircd2_protocol_propagate(from, STRING(" :"));
	inspircd2_protocol_propagate(from, reason);
	inspircd2_protocol_propagate(from, STRING("\n"));
}

// [:source] PRIVMSG <target> <message>
void inspircd2_protocol_propagate_privmsg(struct string from, struct string source, struct string target, struct string msg) {
	struct user_info *user = get_table_index(user_list, target);
	struct server_info *server;
	if (!user)
		server = get_table_index(server_list, target);

	if (user || server) {
		struct server_info *target_server;
		if (user) {
			target_server = get_table_index(server_list, user->server);
		} else {
			target_server = server;
		}

		if (target_server->protocol != INSPIRCD2_PROTOCOL || STRING_EQ(target_server->sid, SID))
			return;

		struct server_info *adjacent = get_table_index(server_list, target_server->next);
		networks[adjacent->net].send(adjacent->handle, STRING(":"));
		networks[adjacent->net].send(adjacent->handle, source);
		networks[adjacent->net].send(adjacent->handle, STRING(" PRIVMSG "));
		networks[adjacent->net].send(adjacent->handle, target);
		networks[adjacent->net].send(adjacent->handle, STRING(" :"));
		networks[adjacent->net].send(adjacent->handle, msg);
		networks[adjacent->net].send(adjacent->handle, STRING("\n"));
	} else {
		// TODO: Trim target list for channels as well
		inspircd2_protocol_propagate(from, STRING(":"));
		inspircd2_protocol_propagate(from, source);
		inspircd2_protocol_propagate(from, STRING(" PRIVMSG "));
		inspircd2_protocol_propagate(from, target);
		inspircd2_protocol_propagate(from, STRING(" :"));
		inspircd2_protocol_propagate(from, msg);
		inspircd2_protocol_propagate(from, STRING("\n"));
	}
}

// [:source] NOTICE <target> <message>
void inspircd2_protocol_propagate_notice(struct string from, struct string source, struct string target, struct string msg) {
	struct user_info *user = get_table_index(user_list, target);
	struct server_info *server;
	if (!user)
		server = get_table_index(server_list, target);

	if (user || server) {
		struct server_info *target_server;
		if (user) {
			target_server = get_table_index(server_list, user->server);
		} else {
			target_server = server;
		}

		if (target_server->protocol != INSPIRCD2_PROTOCOL || STRING_EQ(target_server->sid, SID))
			return;

		struct server_info *adjacent = get_table_index(server_list, target_server->next);
		networks[adjacent->net].send(adjacent->handle, STRING(":"));
		networks[adjacent->net].send(adjacent->handle, source);
		networks[adjacent->net].send(adjacent->handle, STRING(" NOTICE "));
		networks[adjacent->net].send(adjacent->handle, target);
		networks[adjacent->net].send(adjacent->handle, STRING(" :"));
		networks[adjacent->net].send(adjacent->handle, msg);
		networks[adjacent->net].send(adjacent->handle, STRING("\n"));
	} else {
		// TODO: Trim target list for channels as well
		inspircd2_protocol_propagate(from, STRING(":"));
		inspircd2_protocol_propagate(from, source);
		inspircd2_protocol_propagate(from, STRING(" NOTICE "));
		inspircd2_protocol_propagate(from, target);
		inspircd2_protocol_propagate(from, STRING(" :"));
		inspircd2_protocol_propagate(from, msg);
		inspircd2_protocol_propagate(from, STRING("\n"));
	}
}

int inspircd2_protocol_handle_new_server(struct string from, struct string attached_to, struct server_info *info) {
	return 0;
}

void inspircd2_protocol_handle_unlink_server(struct string from, struct server_info *a, struct server_info *b, size_t protocol) {
	return;
}

int inspircd2_protocol_handle_new_user(struct string from, struct user_info *info) {
	return 0;
}

int inspircd2_protocol_handle_rename_user(struct string from, struct user_info *info, struct string nick, size_t timestamp, struct string timestamp_str, char forced, char immediate) {
	return 0;
}

void inspircd2_protocol_handle_remove_user(struct string from, struct user_info *info, struct string reason, char propagate) {
	return;
}

void inspircd2_protocol_handle_kill_user(struct string from, struct string source, struct user_info *info, struct string reason) {
	return;
}

int inspircd2_protocol_handle_oper_user(struct string from, struct user_info *info, struct string type, struct string source) {
	return 0;
}

int inspircd2_protocol_handle_set_account(struct string from, struct user_info *info, struct string account, struct string source) {
	return 0;
}

int inspircd2_protocol_handle_set_cert(struct string from, struct user_info *info, struct string cert, struct string source) {
	return 0;
}

int inspircd2_protocol_handle_set_channel(struct string from, struct channel_info *channel, char is_new_channel, size_t user_count, struct user_info **users) {
	return 0;
}

int inspircd2_protocol_handle_join_channel(struct string from, struct channel_info *channel, size_t user_count, struct user_info **users, char propagate) {
	return 0;
}

void inspircd2_protocol_handle_part_channel(struct string from, struct channel_info *channel, struct user_info *user, struct string reason) {
	return;
}

void inspircd2_protocol_handle_kick_channel(struct string from, struct string source, struct channel_info *channel, struct user_info *user, struct string reason) {
	return;
}

void inspircd2_protocol_fail_new_server(struct string from, struct string attached_to, struct server_info *info) {
	return;
}

void inspircd2_protocol_fail_new_user(struct string from, struct user_info *info) {
	return;
}

void inspircd2_protocol_fail_rename_user(struct string from, struct user_info *info, struct string nick, size_t timestamp, struct string timestamp_str, char forced, char immediate) {
	return;
}

void inspircd2_protocol_fail_oper_user(struct string from, struct user_info *info, struct string type, struct string source) {
	return;
}

void inspircd2_protocol_fail_set_account(struct string from, struct user_info *info, struct string account, struct string source) {
	return;
}

void inspircd2_protocol_fail_set_cert(struct string from, struct user_info *info, struct string cert, struct string source) {
	return;
}

void inspircd2_protocol_fail_set_channel(struct string from, struct channel_info *channel, char is_new_channel, size_t user_count, struct user_info **users) {
	return;
}

void inspircd2_protocol_fail_join_channel(struct string from, struct channel_info *channel, size_t user_count, struct user_info **users, char propagate) {
	return;
}

void inspircd2_protocol_do_unlink_inner(struct string from, struct server_info *target, struct string reason) {
	target->distance = 1; // Reusing distance for `have passed`, since its set to 0 bc severed anyways

	unsigned char i = 0;
	while (target->connected_to.len > i) {
		struct server_info *adjacent = target->connected_to.array[i].ptr;
		if (adjacent->distance != 0) {
			i = 1;
			continue;
		}
		inspircd2_protocol_do_unlink_inner(from, adjacent, reason);
		remove_server(from, adjacent, reason);
	}
}

void inspircd2_protocol_do_unlink(struct string from, struct server_info *a, struct server_info *b) {
	char valid;
	struct string reason;
	reason.data = malloc(a->name.len + 1 + b->name.len);
	if (!reason.data) {
		valid = 0;
		reason = STRING("*.net *.split");
	} else {
		valid = 1;
		memcpy(reason.data, a->name.data, a->name.len);
		reason.data[a->name.len] = ' ';
		memcpy(&(reason.data[a->name.len + 1]), b->name.data, b->name.len);
		reason.len = a->name.len + 1 + b->name.len;
	}

	if (a->distance == 0 && !STRING_EQ(a->sid, SID)) {
		inspircd2_protocol_do_unlink_inner(from, a, reason);
		remove_server(from, a, reason);
	} else {
		inspircd2_protocol_do_unlink_inner(from, b, reason);
		remove_server(from, b, reason);
	}

	if (valid)
		free(reason.data);
}

void inspircd2_protocol_introduce_servers_to_inner(size_t net, void *handle, struct string source, struct server_info *target) {
	networks[net].send(handle, STRING(":"));
	networks[net].send(handle, source);
	networks[net].send(handle, STRING(" SERVER "));
	networks[net].send(handle, target->name);
	networks[net].send(handle, STRING(" * 0 "));
	networks[net].send(handle, target->sid);
	networks[net].send(handle, STRING(" :"));
	networks[net].send(handle, target->fullname);
	networks[net].send(handle, STRING("\n"));

	for (size_t i = 0; i < target->connected_to.len; i++) {
		struct server_info *adjacent = target->connected_to.array[i].ptr;
		if (adjacent->distance > target->distance) {
			inspircd2_protocol_introduce_servers_to_inner(net, handle, target->sid, adjacent);
		}
	}
}

void inspircd2_protocol_introduce_servers_to(size_t net, void *handle) {
	for (size_t i = 0; i < self->connected_to.len; i++) {
		struct server_info *info = self->connected_to.array[i].ptr;
		if (info->protocol == INSPIRCD2_PROTOCOL) { // This server hasn't been added to the list yet, so no need to check for that
			inspircd2_protocol_introduce_servers_to_inner(net, handle, SID, info);
		}
	}
}

void inspircd2_protocol_introduce_user_to(size_t net, void *handle, struct user_info *user, char join_channels) {
	networks[net].send(handle, STRING(":"));
	networks[net].send(handle, user->server);
	networks[net].send(handle, STRING(" UID "));
	networks[net].send(handle, user->uid);
	networks[net].send(handle, STRING(" "));
	networks[net].send(handle, user->user_ts_str);
	networks[net].send(handle, STRING(" "));
	networks[net].send(handle, user->nick);
	networks[net].send(handle, STRING(" "));
	networks[net].send(handle, user->host);
	networks[net].send(handle, STRING(" "));
	networks[net].send(handle, user->vhost);
	networks[net].send(handle, STRING(" "));
	networks[net].send(handle, user->ident);
	networks[net].send(handle, STRING(" "));
	networks[net].send(handle, user->address);
	networks[net].send(handle, STRING(" "));
	networks[net].send(handle, user->nick_ts_str);
	networks[net].send(handle, STRING(" + :"));
	networks[net].send(handle, user->fullname);
	networks[net].send(handle, STRING("\n"));

	if (user->oper_type.len != 0) {
		networks[net].send(handle, STRING(":"));
		networks[net].send(handle, user->uid);
		networks[net].send(handle, STRING(" OPERTYPE :"));
		networks[net].send(handle, user->oper_type);
		networks[net].send(handle, STRING("\n"));
	}

	if (join_channels) {
		for (size_t i = 0; i < user->channel_list.len; i++) {
			struct channel_info *channel = user->channel_list.array[i].ptr;

			networks[net].send(handle, STRING(":"));
			networks[net].send(handle, SID);
			networks[net].send(handle, STRING(" FJOIN "));
			networks[net].send(handle, channel->name);
			networks[net].send(handle, STRING(" "));
			networks[net].send(handle, channel->channel_ts_str);
			networks[net].send(handle, STRING(" + :,"));
			networks[net].send(handle, user->uid);
			networks[net].send(handle, STRING("\n"));
		}
	}
}

void inspircd2_protocol_introduce_channel_to(size_t net, void *handle, struct channel_info *channel) {
	networks[net].send(handle, STRING(":"));
	networks[net].send(handle, SID);
	networks[net].send(handle, STRING(" FJOIN "));
	networks[net].send(handle, channel->name);
	networks[net].send(handle, STRING(" "));
	networks[net].send(handle, channel->channel_ts_str);
	networks[net].send(handle, STRING(" + :"));
	for (size_t i = 0; i < channel->user_list.len; i++) {
		networks[net].send(handle, STRING(","));
		networks[net].send(handle, channel->user_list.array[i].name);
		if (i != channel->user_list.len - 1)
			networks[net].send(handle, STRING(" "));
	}
	networks[net].send(handle, STRING("\n"));
}

// CAPAB <type> [<args> [, ...]]
int inspircd2_protocol_init_handle_capab(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config **config, char is_incoming) {
	if (argc < 1) {
		WRITES(2, STRING("[InspIRCd v2] Invalid CAPAB received! (Missing parameters)\r\n"));
		return -1;
	}

	if (is_incoming && STRING_EQ(argv[0], STRING("START"))) { // This seems to be a proper server connection by now, can start sending stuff
		networks[net].send(handle, STRING("CAPAB START 1202\nCAPAB END\n"));
	}

	return 0;
}

// SERVER <address> <password> <always 0> <SID> <name>
int inspircd2_protocol_init_handle_server(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config **config, char is_incoming) {
	if (argc < 5) {
		WRITES(2, STRING("[InspIRCd v2] Invalid SERVER received! (Missing parameters)\r\n"));
		return -1;
	}

	if (source.len != 0) {
		WRITES(2, STRING("[InspIRCd v2] Server attempting to use a source without having introduced itself!\r\n"));
		return -1;
	}

	if (is_incoming) {
		*config = get_table_index(server_config, argv[3]);
		if (!(*config)) {
			WRITES(2, STRING("[InspIRCd v2] Unknown SID attempted to connect.\r\n"));
			return -1;
		}
	} else {
		if (!STRING_EQ(argv[3], (*config)->sid)) {
			WRITES(2, STRING("[InspIRCd v2] Wrong SID given in SERVER!\r\n"));
			return -1;
		}
	}

	if (!STRING_EQ(argv[1], (*config)->in_pass)) {
		WRITES(2, STRING("[InspIRCd v2] WARNING: Server supplied the wrong password!\r\n"));
		return -1;
	}

	if (is_incoming) {
		networks[net].send(handle, STRING("SERVER "));
		networks[net].send(handle, SERVER_NAME);
		networks[net].send(handle, STRING(" "));
		networks[net].send(handle, (*config)->out_pass);
		networks[net].send(handle, STRING(" 0 "));
		networks[net].send(handle, SID);
		networks[net].send(handle, STRING(" :"));
		networks[net].send(handle, SERVER_FULLNAME);
		networks[net].send(handle, STRING("\n"));
	}

	time_t now = time(0);
	if (now < 0) {
		WRITES(2, STRING("ERROR: Negative clock!\r\n"));
		return -1;
	}
	struct string time;
	int res = unsigned_to_str((size_t)now, &time);
	if (res != 0) {
		WRITES(2, STRING("[InspIRCd v2] ERROR: OOM, severing link.\r\n"));
		return -1;
	}

	networks[net].send(handle, STRING(":"));
	networks[net].send(handle, SID);
	networks[net].send(handle, STRING(" BURST "));
	networks[net].send(handle, time);
	networks[net].send(handle, STRING("\n"));

	inspircd2_protocol_introduce_servers_to(net, handle);

	for (size_t i = 0; i < user_list.len; i++)
		inspircd2_protocol_introduce_user_to(net, handle, user_list.array[i].ptr, 0);

	for (size_t i = 0; i < channel_list.len; i++)
		inspircd2_protocol_introduce_channel_to(net, handle, channel_list.array[i].ptr);

	networks[net].send(handle, STRING(":"));
	networks[net].send(handle, SID);
	networks[net].send(handle, STRING(" ENDBURST\n"));

	free(time.data);

	if (add_server((*config)->sid, SID, argv[3], argv[0], argv[4], INSPIRCD2_PROTOCOL, net, handle) != 0) {
		WRITES(2, STRING("ERROR: Unable to add server!\r\n"));
		return -1;
	}

	struct server_info *server = get_table_index(server_list, (*config)->sid);
	server->awaiting_pong = 0;

	return 1;
}

// [:source] PING <reply_to> <target>
int inspircd2_protocol_handle_ping(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming) {
	if (argc < 2) {
		WRITES(2, STRING("[InspIRCd v2] Invalid PING received! (Missing parameters)\r\n"));
		return -1;
	}

	if (STRING_EQ(config->sid, source) && STRING_EQ(SID, argv[1])) {
		struct server_info *server = get_table_index(server_list, config->sid);
		if (!server->awaiting_pong) {
			networks[net].send(handle, STRING(":"));
			networks[net].send(handle, SID);
			networks[net].send(handle, STRING(" PING "));
			networks[net].send(handle, SID);
			networks[net].send(handle, STRING(" :"));
			networks[net].send(handle, config->sid);
			networks[net].send(handle, STRING("\n"));

			server->awaiting_pong = 1;
			gettimeofday(&(server->last_ping), 0);
		}
	}

	struct server_info *reply = get_table_index(server_list, argv[0]);
	if (!reply || !STRING_EQ(reply->next, config->sid))
		return 0;

	networks[net].send(handle, STRING(":"));
	networks[net].send(handle, argv[1]);
	networks[net].send(handle, STRING(" PONG "));
	networks[net].send(handle, argv[1]);
	networks[net].send(handle, STRING(" :"));
	networks[net].send(handle, argv[0]);
	networks[net].send(handle, STRING("\n"));

	return 0;
}

// [:source] PONG <target> <reply_to>
int inspircd2_protocol_handle_pong(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming) {
	struct timeval now;
	gettimeofday(&now, 0);
	struct server_info *server = get_table_index(server_list, config->sid);

	if (!server->awaiting_pong) // We don't relay PINGs, so PONGs also shouldn't need relayed
		return 1;

	if (now.tv_usec < server->last_ping.tv_usec) {
		server->latency.tv_sec = now.tv_sec - server->last_ping.tv_sec - 1;
		server->latency.tv_usec = (suseconds_t)((size_t)1000000 - (size_t)server->last_ping.tv_usec + (size_t)now.tv_usec); // >_>
	} else {
		server->latency.tv_sec = now.tv_sec - server->last_ping.tv_sec;
		server->latency.tv_usec = now.tv_usec - server->last_ping.tv_usec;
	}
	server->latency_valid = 1;
	server->awaiting_pong = 0;

	return 0;
}

// [:source] SERVER <address> <password> <always 0> <SID> <name>
int inspircd2_protocol_handle_server(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming) {
	if (argc < 5) {
		WRITES(2, STRING("[InspIRCd v2] Invalid SERVER received! (Missing parameters)\r\n"));
		return -1;
	}

	if (has_table_index(server_list, argv[3])) {
		WRITES(2, STRING("[InspIRCd v2] Duplicate SERVER attempted to be created!\r\n"));
		return -1;
	}

	if (add_server(config->sid, source, argv[3], argv[0], argv[4], INSPIRCD2_PROTOCOL, net, handle) != 0) {
		WRITES(2, STRING("ERROR: Unable to add server!\r\n"));
		return -1;
	}

	return 0;
}

// [:source] SQUIT <SID> [<reason>?]
int inspircd2_protocol_handle_squit(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming) {
	if (argc < 1) {
		WRITES(2, STRING("[InspIRCd v2] Invalid SQUIT received! (Missing parameters)\r\n"));
		return -1;
	}

	if (STRING_EQ(argv[0], SID)) { // Not an error, this server is trying to split from us
		return -1;
	}

	struct server_info *a = get_table_index(server_list, source);
	struct server_info *b = get_table_index(server_list, argv[0]);
	if (!a || !b) {
		WRITES(2, STRING("[InspIRCd v2] Invalid SQUIT received! (Unknown source or target)\r\n"));
		return -1;
	}
	if (a->protocol != INSPIRCD2_PROTOCOL || b->protocol != INSPIRCD2_PROTOCOL) { // They're trying to use SQUIT for some unrelated server...
		WRITES(2, STRING("[InspIRCd v2] Invalid SQUIT received! (Bad SID or source)\r\n"));
		return -1;
	}

	unlink_server(config->sid, a, b, INSPIRCD2_PROTOCOL);

	return 0;
}

// [:source] RSQUIT <server name> [<reason>?]
int inspircd2_protocol_handle_rsquit(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming) {
	if (argc < 1) {
		WRITES(2, STRING("[InspIRCd v2] Invalid RSQUIT received! (Missing parameters)\r\n"));
		return -1;
	}

	if (config->ignore_remote_unlinks)
		return 0;

	for (size_t i = 0; i < server_list.len; i++) {
		struct server_info *target = server_list.array[i].ptr;
		if (target->protocol != INSPIRCD2_PROTOCOL)
			continue; // TODO: Maybe actually unlink this somehow
		if (!STRING_EQ(target->name, argv[0]))
			continue;

		if (has_table_index(target->connected_to, SID)) {
			networks[target->net].shutdown(target->handle);
		} else {
			struct server_info *next = get_table_index(server_list, target->next);
			networks[next->net].send(next->handle, STRING(":"));
			networks[next->net].send(next->handle, source);
			networks[next->net].send(next->handle, STRING(" RSQUIT "));
			networks[next->net].send(next->handle, argv[0]);
			if (argc > 1) {
				networks[next->net].send(next->handle, STRING(" :"));
				networks[next->net].send(next->handle, argv[1]);
				networks[next->net].send(next->handle, STRING("\n"));
			} else {
				networks[next->net].send(next->handle, STRING(" :\n"));
			}
		}
	}

	return 0;
}

// [:source] UID <UID> <nick_ts> <nick> <host> <vhost> <ident> <address> <user_ts> <modes> [<mode args>] <fullname>
int inspircd2_protocol_handle_uid(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming) {
	if (argc < 10) {
		WRITES(2, STRING("[InspIRCd v2] Invalid UID received! (Missing parameters)\r\n"));
		return -1;
	}

	if (has_table_index(user_list, argv[0])) {
		WRITES(2, STRING("[InspIRCd v2] Duplicate UID attempted to be created!\r\n"));
		return -1;
	}

	char dir = '?';
	size_t arg_i = 9;
	size_t mode_i = 0;

	while (1) {
		if (argv[8].len <= mode_i)
			break;
		switch(argv[8].data[mode_i]) {
			case '+':
			case '-':
				dir = argv[8].data[mode_i];
				break;
			default:
				if (dir == '?') {
					WRITES(2, STRING("[InspIRCd v2] Invalid UID received! (Mode direction not set)\r\n"));
					return -1;
				}

				switch(inspircd2_protocol_user_mode_types[(unsigned char)argv[8].data[mode_i]]) {
					case MODE_TYPE_NOARGS:
						break;
					case MODE_TYPE_REPLACE:
					case MODE_TYPE_MODE:
						if (dir == '-') // Shouldn't actually happen here, but whatever
							break;
					case MODE_TYPE_MULTIPLE:
						arg_i++;
						break;
					default:
						WRITES(2, STRING("[InspIRCd v2] Invalid UID received! (Unknown mode given)\r\n"));
						return -1;
				}
		}

		mode_i++;
	}

	if (arg_i >= argc) {
		WRITES(2, STRING("[InspIRCd v2] Invalid UID received! (Missing mode arguments)\r\n"));
		return -1;
	}

	char err;
	size_t nick_ts = str_to_unsigned(argv[1], &err);
	if (err) {
		WRITES(2, STRING("[InspIRCd v2] Invalid UID received! (Invalid nick timestamp)\r\n"));
		return -1;
	}

	size_t user_ts = str_to_unsigned(argv[7], &err);
	if (err) {
		WRITES(2, STRING("[InspIRCd v2] Invalid UID received! (Invalid user timestamp)\r\n"));
		return -1;
	}

	if (add_user(config->sid, source, argv[0], argv[2], argv[arg_i], argv[5], argv[4], argv[3], argv[6], user_ts, nick_ts, 0, 0, 0, 0, 0) != 0) {
		WRITES(2, STRING("ERROR: Unable to add user!\r\n"));
		return -1;
	}

	return 0;
}

// :source NICK <nick> <timestamp>
int inspircd2_protocol_handle_nick(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming) {
	if (argc < 2) {
		WRITES(2, STRING("[InspIRCd v2] Invalid NICK received! (Missing parameters)\r\n"));
		return -1;
	}

	char err;
	size_t nick_ts = str_to_unsigned(argv[1], &err);
	if (err) {
		WRITES(2, STRING("[InspIRCd v2] Invalid NICK received! (Invalid timestamp)\r\n"));
		return -1;
	}

	struct user_info *user = get_table_index(user_list, source);
	if (!user)
		return 0; // KILL timings, etc

	if (rename_user(config->sid, user, argv[0], nick_ts, 0, 1) != 0)
		return -1;

	return 0;
}

// :source QUIT [<reason>?]
int inspircd2_protocol_handle_quit(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming) {
	struct string reason;
	if (argc < 1)
		reason = STRING("");
	else
		reason = argv[0];

	struct user_info *user = get_table_index(user_list, source);
	if (!user)
		return 0; // Maybe KILLed or something

	if (STRING_EQ(user->server, SID)) {
		WRITES(2, STRING("[InspIRCd v2] Invalid QUIT received! (Attempting to quit a local user)\r\n"));
		return -1;
	}

	remove_user(config->sid, user, reason, 1);

	return 0;
}

// [:source] KILL <target> [<reason>?]
int inspircd2_protocol_handle_kill(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming) {
	if (argc < 1) {
		WRITES(2, STRING("[InspIRCd v2] Invalid KILL received! (Missing parameters)\r\n"));
		return -1;
	}

	struct user_info *user = get_table_index(user_list, argv[0]);
	if (!user) {
		for (size_t i = 0; i < user_list.len; i++) {
			struct user_info *tmp = user_list.array[i].ptr;
			if (STRING_EQ(tmp->nick, argv[0])) {
				user = tmp;
				break;
			}
		}

		if (!user)
			return 0;
	}

	int ignore;
	if (STRING_EQ(user->server, SID)) {
		if (config->ignore_local_kills) {
			ignore = 1;
		} else {
			if (argc > 1)
				ignore = kill_user(config->sid, source, user, argv[1]);
			else
				ignore = kill_user(config->sid, source, user, STRING(""));
		}
	} else if (!config->ignore_remote_kills) {
		if (argc > 1)
			ignore = kill_user(config->sid, source, user, argv[1]);
		else
			ignore = kill_user(config->sid, source, user, STRING(""));
	} else {
		ignore = 1;
	}

	if (ignore)
		inspircd2_protocol_introduce_user_to(net, handle, user, 1);

	return 0;
}

// :source OPERTYPE <type>
int inspircd2_protocol_handle_opertype(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming) {
	if (argc < 1) {
		WRITES(2, STRING("[InspIRCd v2] Invalid OPERTYPE received! (Missing parameters)\r\n"));
		return -1;
	}

	struct user_info *user = get_table_index(user_list, source);
	if (!user)
		return 0;

	if (oper_user(config->sid, user, argv[0], config->sid) != 0) {
		WRITES(2, STRING("[InspIRCd v2] ERROR: Unable to set oper type!\r\n"));
		return -1;
	}

	return 0;
}

// [:source] FJOIN <channel> <timestamp> <modes> [<mode args>] <userlist: modes,uid [...]>
int inspircd2_protocol_handle_fjoin(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming) {
	if (argc < 4) {
		WRITES(2, STRING("[InspIRCd v2] Invalid FJOIN received! (Missing parameters)\r\n"));
		return -1;
	}

	char err;
	size_t timestamp = str_to_unsigned(argv[1], &err);
	if (err) {
		WRITES(2, STRING("[InspIRCd v2] Invalid FJOIN received! (Invalid timestamp)\r\n"));
		return -1;
	}

	size_t arg_i = 3;
	char dir = '?';
	for (size_t i = 0; i < argv[2].len; i++) {
		switch(argv[2].data[i]) {
			case '+':
			case '-':
				dir = argv[2].data[i];
				break;
			default:
				if (dir == '?') {
					WRITES(2, STRING("[InspIRCd v2] Invalid FJOIN received (Mode direction not set)\r\n"));
					return -1;
				}
				switch(inspircd2_protocol_channel_mode_types[(unsigned char)argv[2].data[i]]) {
					case MODE_TYPE_NOARGS:
						break;
					case MODE_TYPE_REPLACE:
					case MODE_TYPE_MODE:
						if (dir == '-')
							break;
					case MODE_TYPE_MULTIPLE:
						arg_i++;
						break;
					case MODE_TYPE_USERS:
						WRITES(2, STRING("[InspIRCd v2] Invalid FJOIN received! (User mode put in the modes instead of the user list)\r\n"));
						return -1;
					default:
						WRITES(2, STRING("[InspIRCd v2] Invalid FJOIN received! (Unknown mode given)\r\n"));
						return -1;
				}
		}
	}

	size_t user_count = 0;
	for (size_t i = 0; i < argv[arg_i].len;) {
		while (i < argv[arg_i].len && argv[arg_i].data[i] != ',')
			i++;

		i++;

		user_count++;

		while (i < argv[arg_i].len && argv[arg_i].data[i] != ' ')
			i++;
	}

	struct user_info **users;
	users = malloc(sizeof(**users) * user_count);
	if (!users && user_count != 0) {
		WRITES(2, STRING("[InspIRCd v2] [FJOIN] OOM! Disconnecting server.\r\n"));
		return -1;
	}

	for (size_t i = 0, n = 0; i < argv[arg_i].len; n++) {
		struct string uid;
		while (i < argv[arg_i].len && argv[arg_i].data[i] != ',')
			i++;

		i++;

		uid.data = &(argv[arg_i].data[i]);

		while (i < argv[arg_i].len && argv[arg_i].data[i] != ' ')
			i++;

		uid.len = (size_t)(&(argv[arg_i].data[i]) - uid.data);

		users[n] = get_table_index(user_list, uid);
		if (!users[n]) { // Maybe KILLed or smth
			n--;
			user_count--;
		}
	}

	struct channel_info *channel = get_table_index(channel_list, argv[0]);
	if (!channel || timestamp < channel->channel_ts) {
		if (set_channel(config->sid, argv[0], timestamp, user_count, users) != 0)
			goto inspircd2_protocol_handle_fjoin_free_users;
	} else {
		if (join_channel(config->sid, channel, user_count, users, 1) != 0)
			goto inspircd2_protocol_handle_fjoin_free_users;
	}

	free(users);

	return 0;

	inspircd2_protocol_handle_fjoin_free_users:
	free(users);
	return -1;
}

// :source PART <channel> [<reason>]
int inspircd2_protocol_handle_part(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming) {
	if (argc < 1) {
		WRITES(2, STRING("[InspIRCd v2] Invalid PART received! (Missing parameters)\r\n"));
		return -1;
	}
	struct string reason;
	if (argc < 2)
		reason = STRING("");
	else
		reason = argv[1];

	struct user_info *user = get_table_index(user_list, source);
	if (!user)
		return 0;

	struct channel_info *channel = get_table_index(channel_list, argv[0]);
	if (!channel)
		return 0;

	part_channel(config->sid, channel, user, reason, 1);

	return 0;
}

// [:source] KICK <channel> <user> [<reason>]
int inspircd2_protocol_handle_kick(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming) {
	if (argc < 2) {
		WRITES(2, STRING("[InspIRCd v2] Invalid KICK received! (Missing parameters)\r\n"));
		return -1;
	}

	struct channel_info *channel = get_table_index(channel_list, argv[0]);
	if (!channel)
		return 0;

	struct user_info *user = get_table_index(user_list, argv[1]);
	if (!user) {
		char found = 0;
		for (size_t i = 0; i < user_list.len; i++) {
			user = user_list.array[i].ptr;
			if (STRING_EQ(user->nick, argv[1])) {
				found = 1;
				break;
			}
		}
		if (!found)
			return 0;
	}

	int rejoin;
	if (argc > 2)
		rejoin = kick_channel(config->sid, source, channel, user, argv[2]);
	else
		rejoin = kick_channel(config->sid, source, channel, user, STRING(""));

	if (rejoin) {
		networks[net].send(handle, STRING(":"));
		networks[net].send(handle, SID);
		networks[net].send(handle, STRING(" FJOIN "));
		networks[net].send(handle, channel->name);
		networks[net].send(handle, STRING(" "));
		networks[net].send(handle, channel->channel_ts_str);
		networks[net].send(handle, STRING(" + :,"));
		networks[net].send(handle, user->uid);
		networks[net].send(handle, STRING("\n"));
	}

	return 0;
}

// [:source] PRIVMSG <target> <message>
int inspircd2_protocol_handle_privmsg(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming) {
	if (argc < 2) {
		WRITES(2, STRING("[InspIRCd v2] Invalid PRIVMSG received! (Missing parameters)\r\n"));
		return -1;
	}

	privmsg(config->sid, source, argv[0], argv[1]);

	return 0;
}

// [:source] NOTICE <target> <message>
int inspircd2_protocol_handle_notice(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming) {
	if (argc < 2) {
		WRITES(2, STRING("[InspIRCd v2] Invalid NOTICE received! (Missing parameters)\r\n"));
		return -1;
	}

	notice(config->sid, source, argv[0], argv[1]);

	return 0;
}

// :source MODE <target> <modes> [<mode args>]
int inspircd2_protocol_handle_mode(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming) {
	if (argc < 2) {
		WRITES(2, STRING("[InspIRCd v2] Invalid MODE received! (Missing parameters)\r\n"));
		return -1;
	}

	struct user_info *user = get_table_index(user_list, argv[0]);
	if (!user) {
		if (has_table_index(server_list, argv[0]))
			return 0; // TODO: Probably not actually valid

		char found = 0;
		for (size_t i = 0; i < user_list.len; i++) {
			user = user_list.array[i].ptr;
			if (case_string_eq(user->nick, argv[0])) {
				found = 1;
				break;
			}
		}

		if (!found)
			return 0;
	}

	if (user) {
		size_t arg_i = 2;
		char dir = '?';
		for (size_t i = 0; i < argv[1].len; i++) {
			switch(argv[1].data[i]) {
				case '+':
				case '-':
					dir = argv[1].data[i];
					break;
				default:
					if (dir == '?') {
						WRITES(2, STRING("[InspIRCd v2] Invalid MODE received (Mode direction not set)\r\n"));
						return -1;
					}
					switch(inspircd2_protocol_user_mode_types[(unsigned char)argv[1].data[i]]) {
						case MODE_TYPE_NOARGS:
							if (dir == '-' && argv[1].data[i] == 'o') {
								if (oper_user(config->sid, user, STRING(""), source) != 0)
									return -1;
							}
							break;
						case MODE_TYPE_REPLACE:
						case MODE_TYPE_MODE:
							if (dir == '-')
								break;
						case MODE_TYPE_MULTIPLE:
							arg_i++;
							break;
						case MODE_TYPE_USERS:
							arg_i++;
							break;
						default:
							WRITES(2, STRING("[InspIRCd v2] Invalid MODE received! (Unknown mode given)\r\n"));
							return -1;
					}
			}
		}
	}

	return 0;
}

// :source FMODE <target> <timestamp> <modes> [<mode args>]
int inspircd2_protocol_handle_fmode(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming) {
	if (argc < 3) {
		WRITES(2, STRING("[InspIRCd v2] Invalid MODE received! (Missing parameters)\r\n"));
		return -1;
	}

	struct user_info *user = get_table_index(user_list, argv[0]);
	if (!user) {
		if (has_table_index(server_list, argv[0]))
			return 0; // TODO: Probably not actually valid

		char found = 0;
		for (size_t i = 0; i < user_list.len; i++) {
			user = user_list.array[i].ptr;
			if (case_string_eq(user->nick, argv[0])) {
				found = 1;
				break;
			}
		}

		if (!found)
			return 0;
	}

	if (user) {
		size_t arg_i = 3;
		char dir = '?';
		for (size_t i = 0; i < argv[2].len; i++) {
			switch(argv[2].data[i]) {
				case '+':
				case '-':
					dir = argv[2].data[i];
					break;
				default:
					if (dir == '?') {
						WRITES(2, STRING("[InspIRCd v2] Invalid MODE received (Mode direction not set)\r\n"));
						return -1;
					}
					switch(inspircd2_protocol_user_mode_types[(unsigned char)argv[2].data[i]]) {
						case MODE_TYPE_NOARGS:
							if (dir == '-' && argv[2].data[i] == 'o') {
								if (oper_user(config->sid, user, STRING(""), source) != 0)
									return -1;
							}
							break;
						case MODE_TYPE_REPLACE:
						case MODE_TYPE_MODE:
							if (dir == '-')
								break;
						case MODE_TYPE_MULTIPLE:
							arg_i++;
							break;
						case MODE_TYPE_USERS:
							arg_i++;
							break;
						default:
							WRITES(2, STRING("[InspIRCd v2] Invalid MODE received! (Unknown mode given)\r\n"));
							return -1;
					}
			}
		}
	}

	return 0;
}

// [:source] METADATA <target> <key> <value>
int inspircd2_protocol_handle_metadata(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming) {
	if (argc < 3) {
		WRITES(2, STRING("[InspIRCd v2] Invalid METADATA received! (Missing parameters)\r\n"));
		return -1;
	}

	struct user_info *info;
	do {
		info = get_table_index(user_list, argv[0]);
		if (info)
			break;

		return 0;
	} while (0);

	if (STRING_EQ(argv[1], STRING("accountname"))) {
		if (set_account(config->sid, info, argv[2], source) != 0)
			return -1;
	} else if (STRING_EQ(argv[1], STRING("ssl_cert"))) {
		struct string no_cert = STRING("vtrsE ");
		if (argv[2].len < no_cert.len)
			return -1;
		struct string start = {.data = argv[2].data, .len = no_cert.len};
		if (STRING_EQ(start, no_cert)) {
			if (set_cert(config->sid, info, STRING(""), source) != 0)
				return -1;
		} else if (STRING_EQ(start, STRING("vTrse "))) {
			struct string cert = {.data = argv[2].data + no_cert.len, .len = argv[2].len - no_cert.len};
			size_t len;
			for (len = 0; len < cert.len && cert.data[len] != ' '; len++)
				;
			cert.len = len;
			if (set_cert(config->sid, info, cert, source) != 0)
				return -1;
		}
	}

	return 0;
}

int inspircd2_protocol_handle_dump(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming) {
	for (size_t arg = 0; arg < argc; arg++) {
		if (STRING_EQ(argv[arg], STRING("LATENCIES"))) {
			for (size_t i = 0; i < server_list.len; i++) {
				struct server_info *server = server_list.array[i].ptr;
				WRITES(2, STRING("Server `"));
				WRITES(2, server->name);
				if (server->latency_valid) {
					WRITES(2, STRING("' has measured latency: "));
					struct string timestamp;
					if (unsigned_to_str((size_t)server->latency.tv_sec, &timestamp) == 0) {
						WRITES(2, timestamp);
						free(timestamp.data);
					} else {
						WRITES(2, STRING("<ERROR: Unable to convert timestamp to string>"));
					}
					WRITES(2, STRING("s, "));
					if (unsigned_to_str((size_t)server->latency.tv_usec, &timestamp) == 0) {
						WRITES(2, timestamp);
						free(timestamp.data);
					} else {
						WRITES(2, STRING("<ERROR: Unable to convert timestamp to string>"));
					}
					WRITES(2, STRING("us\r\n"));
				} else {
					WRITES(2, STRING("' has no latency measurement\r\n"));
				}
			}
		}
	}

	return 0;
}
