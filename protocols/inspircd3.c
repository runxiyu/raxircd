// InspIRCd v3 / InspIRCd 1205 protocol support
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

#include <pthread.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#include "../config.h"
#include "../general_network.h"
#include "hax_string.h"
#include "hax_string_utils.h"
#include "hax_table.h"
#include "../main.h"
#include "../mutex.h"
#include "../server_network.h"
#include "inspircd3.h"

struct table inspircd3_protocol_init_commands = {0};
struct table inspircd3_protocol_commands = {0};

char inspircd3_protocol_user_mode_types[UCHAR_MAX+1] = {
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

char inspircd3_protocol_channel_mode_types[UCHAR_MAX+1] = {
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

int init_inspircd3_protocol(void) {
	inspircd3_protocol_commands.array = malloc(0);

	set_table_index(&inspircd3_protocol_init_commands, STRING("CAPAB"), (union table_ptr){.function = (void (*)(void))&inspircd3_protocol_init_handle_capab});
	set_table_index(&inspircd3_protocol_init_commands, STRING("SERVER"), (union table_ptr){.function = (void (*)(void))&inspircd3_protocol_init_handle_server});



	set_table_index(&inspircd3_protocol_commands, STRING("PING"), (union table_ptr){.function = (void (*)(void))&inspircd3_protocol_handle_ping});
	set_table_index(&inspircd3_protocol_commands, STRING("PONG"), (union table_ptr){.function = (void (*)(void))&inspircd3_protocol_handle_pong});

	set_table_index(&inspircd3_protocol_commands, STRING("SERVER"), (union table_ptr){.function = (void (*)(void))&inspircd3_protocol_handle_server});
	set_table_index(&inspircd3_protocol_commands, STRING("SQUIT"), (union table_ptr){.function = (void (*)(void))&inspircd3_protocol_handle_squit});
	set_table_index(&inspircd3_protocol_commands, STRING("RSQUIT"), (union table_ptr){.function = (void (*)(void))&inspircd3_protocol_handle_rsquit});

	set_table_index(&inspircd3_protocol_commands, STRING("UID"), (union table_ptr){.function = (void (*)(void))&inspircd3_protocol_handle_uid});
	set_table_index(&inspircd3_protocol_commands, STRING("NICK"), (union table_ptr){.function = (void (*)(void))&inspircd3_protocol_handle_nick});
	set_table_index(&inspircd3_protocol_commands, STRING("QUIT"), (union table_ptr){.function = (void (*)(void))&inspircd3_protocol_handle_quit});
	set_table_index(&inspircd3_protocol_commands, STRING("KILL"), (union table_ptr){.function = (void (*)(void))&inspircd3_protocol_handle_kill});
	set_table_index(&inspircd3_protocol_commands, STRING("OPERTYPE"), (union table_ptr){.function = (void (*)(void))&inspircd3_protocol_handle_opertype});

	set_table_index(&inspircd3_protocol_commands, STRING("FJOIN"), (union table_ptr){.function = (void (*)(void))&inspircd3_protocol_handle_fjoin});
	set_table_index(&inspircd3_protocol_commands, STRING("IJOIN"), (union table_ptr){.function = (void (*)(void))&inspircd3_protocol_handle_ijoin});
	set_table_index(&inspircd3_protocol_commands, STRING("PART"), (union table_ptr){.function = (void (*)(void))&inspircd3_protocol_handle_part});
	set_table_index(&inspircd3_protocol_commands, STRING("KICK"), (union table_ptr){.function = (void (*)(void))&inspircd3_protocol_handle_kick});

	set_table_index(&inspircd3_protocol_commands, STRING("PRIVMSG"), (union table_ptr){.function = (void (*)(void))&inspircd3_protocol_handle_privmsg});
	set_table_index(&inspircd3_protocol_commands, STRING("NOTICE"), (union table_ptr){.function = (void (*)(void))&inspircd3_protocol_handle_notice});

	set_table_index(&inspircd3_protocol_commands, STRING("MODE"), (union table_ptr){.function = (void (*)(void))&inspircd3_protocol_handle_mode});
	set_table_index(&inspircd3_protocol_commands, STRING("FMODE"), (union table_ptr){.function = (void (*)(void))&inspircd3_protocol_handle_fmode});

	set_table_index(&inspircd3_protocol_commands, STRING("METADATA"), (union table_ptr){.function = (void (*)(void))&inspircd3_protocol_handle_metadata});

	return 0;
}

void init_inspircd3_protocol_fail(void) {
	clear_table(&inspircd3_protocol_commands);
	free(inspircd3_protocol_commands.array);
}

void * inspircd3_protocol_connection(void *type) {
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
		networks[net].send(handle, STRING("CAPAB START 1205\nCAPAB END\n"));

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
					goto inspircd3_protocol_handle_connection_close;
				} else if (err == 1) { // Timed out
					if (ready) {
						if (timeout > 0)
							goto inspircd3_protocol_handle_connection_close;
						timeout++;

						mutex_lock(&(state_lock));
						networks[net].send(handle, STRING(":"));
						networks[net].send(handle, SID);
						networks[net].send(handle, STRING(" PING :"));
						networks[net].send(handle, config->sid);
						networks[net].send(handle, STRING("\n"));

						char exists;
						struct server_info *server = get_table_index(server_list, config->sid, &exists).data;
						server->awaiting_pong = 1;
						gettimeofday(&(server->last_ping), 0);

						mutex_unlock(&(state_lock));
					} else {
						goto inspircd3_protocol_handle_connection_close;
					}
				} else {
					break;
				}
			}
			old_len = full_msg.len;
			full_msg.len += new_len;
			void *tmp = realloc(full_msg.data, full_msg.len);
			if (!tmp && full_msg.len + new_len != 0)
				goto inspircd3_protocol_handle_connection_close;
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
				WRITES(2, STRING("[InspIRCd v3] ["));
				WRITES(2, config->name);
				WRITES(2, STRING(" -> us] Got `"));
			} else {
				WRITES(2, STRING("[InspIRCd v3] [unidentified server -> us] Got `"));
			}
			WRITES(2, line);
			WRITES(2, STRING("'\r\n"));

			size_t offset = 0;
			while (offset < msg_len && full_msg.data[offset] == ' ')
				offset++;

			if (msg_len == offset) {
				WRITES(2, STRING("[InspIRCd v3] Protocol violation: empty message.\r\n\n"));
				goto inspircd3_protocol_handle_connection_close;
			}

			// Trim tags
			if (offset < full_msg.len && full_msg.data[offset] == '@') {
				while (offset < full_msg.len && full_msg.data[offset] != ' ')
					offset++;

				while (offset < full_msg.len && full_msg.data[offset] == ' ')
					offset++;
			}

			if (msg_len == offset) {
				WRITES(2, STRING("[InspIRCd v3] Protocol violation: empty message.\r\n\n"));
				goto inspircd3_protocol_handle_connection_close;
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
					WRITES(2, STRING("[InspIRCd v3] Protocol violation: source prefix but no source.\r\n\n"));
					goto inspircd3_protocol_handle_connection_close;
				}
				if (!found || offset >= msg_len) {
					WRITES(2, STRING("[InspIRCd v3] Protocol violation: source but no command.\r\n\n"));
					goto inspircd3_protocol_handle_connection_close;
				}

				if (STRING_EQ(source, SID)) {
					WRITES(2, STRING("[InspIRCd v3] Protocol violation: other server sent us as source!\r\n\n"));
					goto inspircd3_protocol_handle_connection_close;
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
				char exists;
				struct user_info *user = get_table_index(user_list, source, &exists).data;
				if (exists)
					server = get_table_index(server_list, user->server, &exists).data;
				else
					server = get_table_index(server_list, source, &exists).data;

				if (!exists)
					goto inspircd3_protocol_handle_connection_unlock_next;

				if (!STRING_EQ(server->next, config->sid)) {
					WRITES(2, STRING("[InspIRCd v3] Protocol violation: source isn't on this link.\r\n\n"));
					goto inspircd3_protocol_handle_connection_unlock_close;
				}
			}

			if (!ready) {
				int (*func)(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config **config, char is_incoming);
				char exists;
				func = (int (*)(struct string, size_t, struct string *, size_t, void *, struct server_config **, char))get_table_index(inspircd3_protocol_init_commands, command, &exists).function;
				if (!exists) {
					WRITES(2, STRING("WARNING: Command is unknown, ignoring.\r\n"));
					goto inspircd3_protocol_handle_connection_unlock_next;
				}

				int res = func(source, argc, argv, net, handle, &config, is_incoming);
				if (res < 0) // Disconnect
					goto inspircd3_protocol_handle_connection_unlock_close;
				else if (res > 0) // Connection is now "ready"
					ready = 1;
			} else {
				int (*func)(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming);
				char exists;
				func = (int (*)(struct string, size_t, struct string *, size_t, void *, struct server_config *, char))get_table_index(inspircd3_protocol_commands, command, &exists).function;
				if (!exists) {
					WRITES(2, STRING("WARNING: Command is unknown, ignoring.\r\n"));
					goto inspircd3_protocol_handle_connection_unlock_next;
				}

				int res = func(source, argc, argv, net, handle, config, is_incoming);
				if (res < 0) // Disconnect
					goto inspircd3_protocol_handle_connection_unlock_close;
			}

			inspircd3_protocol_handle_connection_unlock_next:
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

	inspircd3_protocol_handle_connection_unlock_close:
	mutex_unlock(&state_lock);
	inspircd3_protocol_handle_connection_close:
	free(full_msg.data);

	if (ready) {
		mutex_lock(&(state_lock));
		char exists;
		unlink_server(config->sid, get_table_index(server_list, config->sid, &exists).data, self, INSPIRCD3_PROTOCOL);
		mutex_unlock(&(state_lock));
	}

	networks[net].close(fd, handle);
	free(address.data);

	return 0;
}

void * inspircd3_protocol_autoconnect(void *tmp) {
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
	type->protocol = INSPIRCD3_PROTOCOL;
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

		inspircd3_protocol_connection(info);
	}
}

void inspircd3_protocol_update_propagations_inner(struct server_info *source) {
	for (size_t i = 0; i < source->connected_to.len; i++) {
		struct server_info *adjacent = source->connected_to.array[i].ptr.data;
		if (adjacent->distance == 0 && !STRING_EQ(adjacent->sid, SID)) {
			adjacent->distance = source->distance + 1;
			if (adjacent->distance == 1) {
				adjacent->next = adjacent->sid;
			} else {
				adjacent->next = source->next;
				adjacent->handle = source->handle;
			}
			inspircd3_protocol_update_propagations_inner(adjacent);
		}
	}
}

void inspircd3_protocol_update_propagations(void) {
	for (size_t i = 0; i < server_list.len; i++) {
		struct server_info *other = server_list.array[i].ptr.data;
		if (other->protocol == INSPIRCD3_PROTOCOL) {
			other->distance = 0;
		}
	}

	inspircd3_protocol_update_propagations_inner(self);
}

void inspircd3_protocol_propagate(struct string from, struct string msg) {
	for (size_t i = 0; i < self->connected_to.len; i++) {
		struct server_info *adjacent = self->connected_to.array[i].ptr.data;
		if (adjacent->protocol != INSPIRCD3_PROTOCOL || STRING_EQ(from, adjacent->sid))
			continue; // Not ours or it's the source of this message

		networks[adjacent->net].send(adjacent->handle, msg);
	}
}

// [:source] SERVER <name> <sid> <fullname>
void inspircd3_protocol_propagate_new_server(struct string from, struct string attached_to, struct server_info *info) {
	inspircd3_protocol_propagate(from, STRING(":"));

	if (info->protocol == INSPIRCD3_PROTOCOL)
		inspircd3_protocol_propagate(from, attached_to);
	else // Just pretend servers connected via a different protocol are connected directly to us
		inspircd3_protocol_propagate(from, SID);

	inspircd3_protocol_propagate(from, STRING(" SERVER "));
	inspircd3_protocol_propagate(from, info->name);
	inspircd3_protocol_propagate(from, STRING(" "));
	inspircd3_protocol_propagate(from, info->sid);
	inspircd3_protocol_propagate(from, STRING(" :"));
	inspircd3_protocol_propagate(from, info->fullname);
	inspircd3_protocol_propagate(from, STRING("\n"));

	inspircd3_protocol_propagate(from, STRING(":"));
	inspircd3_protocol_propagate(from, info->sid);
	inspircd3_protocol_propagate(from, STRING(" BURST "));

	time_t current = time(0);
	struct string current_time;
	char err = unsigned_to_str((size_t)current, &current_time);

	if (current < 0 || err) {
		inspircd3_protocol_propagate(from, STRING("1"));
	} else {
		inspircd3_protocol_propagate(from, current_time);
		free(current_time.data);
	}

	inspircd3_protocol_propagate(from, STRING("\n:"));
	inspircd3_protocol_propagate(from, info->sid);
	inspircd3_protocol_propagate(from, STRING(" ENDBURST\n"));
}

// [:source] SQUIT <sid> [<reason>?]
void inspircd3_protocol_propagate_remove_server(struct string from, struct server_info *server, struct string reason) {
	if (server->protocol == INSPIRCD3_PROTOCOL)
		return;

	inspircd3_protocol_propagate(from, STRING(":"));
	inspircd3_protocol_propagate(from, SID);
	inspircd3_protocol_propagate(from, STRING(" SQUIT "));
	inspircd3_protocol_propagate(from, server->sid);
	inspircd3_protocol_propagate(from, STRING(" :"));
	if (reason.len != 0)
		inspircd3_protocol_propagate(from, reason);
	else
		inspircd3_protocol_propagate(from, STRING(" "));
	inspircd3_protocol_propagate(from, STRING("\n"));
}

// [:source] SQUIT <sid> [<reason>?]
void inspircd3_protocol_propagate_unlink_server(struct string from, struct server_info *a, struct server_info *b, size_t protocol) {
	if (protocol != INSPIRCD3_PROTOCOL)
		return;

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

	inspircd3_protocol_propagate(from, STRING(":"));
	inspircd3_protocol_propagate(from, source->sid);
	inspircd3_protocol_propagate(from, STRING(" SQUIT "));
	inspircd3_protocol_propagate(from, target->sid);
	inspircd3_protocol_propagate(from, STRING(" : \n"));
}

// [:source] UID <UID> <nick_ts> <nick> <host> <vhost> <ident> <address> <user_ts> <modes> [<mode args>] <fullname>
void inspircd3_protocol_propagate_new_user(struct string from, struct user_info *info) {
	inspircd3_protocol_propagate(from, STRING(":"));
	inspircd3_protocol_propagate(from, info->server);
	inspircd3_protocol_propagate(from, STRING(" UID "));
	inspircd3_protocol_propagate(from, info->uid);
	inspircd3_protocol_propagate(from, STRING(" "));
	inspircd3_protocol_propagate(from, info->nick_ts_str);
	inspircd3_protocol_propagate(from, STRING(" "));
	inspircd3_protocol_propagate(from, info->nick);
	inspircd3_protocol_propagate(from, STRING(" "));
	inspircd3_protocol_propagate(from, info->host);
	inspircd3_protocol_propagate(from, STRING(" "));
	inspircd3_protocol_propagate(from, info->vhost);
	inspircd3_protocol_propagate(from, STRING(" "));
	inspircd3_protocol_propagate(from, info->ident);
	inspircd3_protocol_propagate(from, STRING(" "));
	inspircd3_protocol_propagate(from, info->address);
	inspircd3_protocol_propagate(from, STRING(" "));
	inspircd3_protocol_propagate(from, info->user_ts_str);
	inspircd3_protocol_propagate(from, STRING(" + :"));
	inspircd3_protocol_propagate(from, info->fullname);
	inspircd3_protocol_propagate(from, STRING("\n"));
}

// :source NICK <nick> <timestamp>
void inspircd3_protocol_propagate_rename_user(struct string from, struct user_info *user, struct string nick, size_t timestamp, struct string timestamp_str, char forced, char immediate) {
	if (forced) {
		if (STRING_EQ(user->uid, nick)) {
			inspircd3_protocol_propagate(from, STRING(":"));
			inspircd3_protocol_propagate(from, from);
			inspircd3_protocol_propagate(from, STRING(" SAVE "));
			inspircd3_protocol_propagate(from, user->uid);
			inspircd3_protocol_propagate(from, STRING(" :"));
			inspircd3_protocol_propagate(from, user->nick_ts_str);
			inspircd3_protocol_propagate(from, STRING("\n"));
		} else {
			inspircd3_protocol_propagate(from, STRING(":"));
			inspircd3_protocol_propagate(from, from);
			inspircd3_protocol_propagate(from, STRING(" SANICK "));
			inspircd3_protocol_propagate(from, user->uid);
			inspircd3_protocol_propagate(from, STRING(" :"));
			inspircd3_protocol_propagate(from, nick);
			inspircd3_protocol_propagate(from, STRING("\n"));
		}
	} else {
		inspircd3_protocol_propagate(from, STRING(":"));
		inspircd3_protocol_propagate(from, user->uid);
		inspircd3_protocol_propagate(from, STRING(" NICK "));
		inspircd3_protocol_propagate(from, nick);
		inspircd3_protocol_propagate(from, STRING(" "));
		inspircd3_protocol_propagate(from, timestamp_str);
		inspircd3_protocol_propagate(from, STRING("\n"));
	}
}

// :source QUIT [<reason>?]
void inspircd3_protocol_propagate_remove_user(struct string from, struct user_info *info, struct string reason) {
	inspircd3_protocol_propagate(from, STRING(":"));
	inspircd3_protocol_propagate(from, info->uid);
	inspircd3_protocol_propagate(from, STRING(" QUIT :"));
	inspircd3_protocol_propagate(from, reason);
	inspircd3_protocol_propagate(from, STRING("\n"));
}

// [:source] KILL <target> [<reason>?]
void inspircd3_protocol_propagate_kill_user(struct string from, struct string source, struct user_info *info, struct string reason) {
	inspircd3_protocol_propagate(from, STRING(":"));
	inspircd3_protocol_propagate(from, source);
	inspircd3_protocol_propagate(from, STRING(" KILL "));
	inspircd3_protocol_propagate(from, info->uid);
	inspircd3_protocol_propagate(from, STRING(" :"));
	inspircd3_protocol_propagate(from, reason);
	inspircd3_protocol_propagate(from, STRING("\n"));
}

// :source OPERTYPE <type>
void inspircd3_protocol_propagate_oper_user(struct string from, struct user_info *user, struct string type, struct string source) {
	if (type.len == 0) {
		inspircd3_protocol_propagate(from, STRING(":"));
		inspircd3_protocol_propagate(from, source);
		inspircd3_protocol_propagate(from, STRING(" MODE "));
		inspircd3_protocol_propagate(from, user->uid);
		inspircd3_protocol_propagate(from, STRING(" -o\n"));
	} else {
		inspircd3_protocol_propagate(from, STRING(":"));
		inspircd3_protocol_propagate(from, user->uid);
		inspircd3_protocol_propagate(from, STRING(" OPERTYPE :"));
		inspircd3_protocol_propagate(from, type);
		inspircd3_protocol_propagate(from, STRING("\n"));
	}
}

// [:source] METADATA <user> accountname <account>
void inspircd3_protocol_propagate_set_account(struct string from, struct user_info *user, struct string account, struct string source) {
	inspircd3_protocol_propagate(from, STRING(":"));
	inspircd3_protocol_propagate(from, source);
	inspircd3_protocol_propagate(from, STRING(" METADATA "));
	inspircd3_protocol_propagate(from, user->uid);
	inspircd3_protocol_propagate(from, STRING(" accountname :"));
	inspircd3_protocol_propagate(from, account);
	inspircd3_protocol_propagate(from, STRING("\n"));
}

// [:source] METADATA <user> ssl_cert <vtrsE (none) | vTrse <cert>>
void inspircd3_protocol_propagate_set_cert(struct string from, struct user_info *user, struct string cert, struct string source) {
	inspircd3_protocol_propagate(from, STRING(":"));
	inspircd3_protocol_propagate(from, source);
	inspircd3_protocol_propagate(from, STRING(" METADATA "));
	inspircd3_protocol_propagate(from, user->uid);
	if (cert.len != 0) {
		inspircd3_protocol_propagate(from, STRING(" ssl_cert :vTrse "));
		inspircd3_protocol_propagate(from, cert);
		inspircd3_protocol_propagate(from, STRING("\n"));
	} else {
		inspircd3_protocol_propagate(from, STRING(" ssl_cert :vtrsE No certificate was found.\n"));
	}
}

// [:source] FJOIN <channel> <timestamp> <modes> [<mode args>] <userlist: modes,uid:mid [...]>
void inspircd3_protocol_propagate_set_channel(struct string from, struct channel_info *channel, char is_new_server, size_t user_count, struct user_info **users) {
	inspircd3_protocol_propagate(from, STRING(":"));
	inspircd3_protocol_propagate(from, SID);
	inspircd3_protocol_propagate(from, STRING(" FJOIN "));
	inspircd3_protocol_propagate(from, channel->name);
	inspircd3_protocol_propagate(from, STRING(" "));
	inspircd3_protocol_propagate(from, channel->channel_ts_str);
	inspircd3_protocol_propagate(from, STRING(" + :"));
	for (size_t x = 0; x < user_count; x++) {
		inspircd3_protocol_propagate(from, STRING(","));
		inspircd3_protocol_propagate(from, users[x]->uid);

		char exists;
		struct server_info *server = get_table_index(server_list, users[x]->server, &exists).data;

		inspircd3_protocol_propagate(from, STRING(":"));
		struct inspircd3_protocol_member_id *member;
		if (!STRING_EQ(server->sid, SID) && server->protocol == INSPIRCD3_PROTOCOL) {
			struct inspircd3_protocol_specific_user *prot_specific = users[x]->protocol_specific[INSPIRCD3_PROTOCOL];
			member = get_table_index(prot_specific->memberships, channel->name, &exists).data;
			if (!exists)
				member = 0;
		} else {
			member = 0;
		}

		if (member)
			inspircd3_protocol_propagate(from, member->id_str);
		else
			inspircd3_protocol_propagate(from, STRING("0"));

		if (x != user_count - 1)
			inspircd3_protocol_propagate(from, STRING(" "));
	}
	inspircd3_protocol_propagate(from, STRING("\n"));
}

// [:source] FJOIN <channel> <timestamp> <modes> [<mode args>] <userlist: modes,uid:mid [...]>
void inspircd3_protocol_propagate_join_channel(struct string from, struct channel_info *channel, size_t user_count, struct user_info **users) {
	inspircd3_protocol_propagate(from, STRING(":"));
	inspircd3_protocol_propagate(from, SID);
	inspircd3_protocol_propagate(from, STRING(" FJOIN "));
	inspircd3_protocol_propagate(from, channel->name);
	inspircd3_protocol_propagate(from, STRING(" "));
	inspircd3_protocol_propagate(from, channel->channel_ts_str);
	inspircd3_protocol_propagate(from, STRING(" + :"));
	for (size_t x = 0; x < user_count; x++) {
		inspircd3_protocol_propagate(from, STRING(","));
		inspircd3_protocol_propagate(from, users[x]->uid);

		char exists;
		struct server_info *server = get_table_index(server_list, users[x]->server, &exists).data;

		inspircd3_protocol_propagate(from, STRING(":"));
		struct inspircd3_protocol_member_id *member;
		if (!STRING_EQ(server->sid, SID) && server->protocol == INSPIRCD3_PROTOCOL) {
			struct inspircd3_protocol_specific_user *prot_specific = users[x]->protocol_specific[INSPIRCD3_PROTOCOL];
			char exists;
			member = get_table_index(prot_specific->memberships, channel->name, &exists).data;
			if (!exists)
				member = 0;
		} else {
			member = 0;
		}

		if (member)
			inspircd3_protocol_propagate(from, member->id_str);
		else
			inspircd3_protocol_propagate(from, STRING("0"));

		if (x != user_count - 1)
			inspircd3_protocol_propagate(from, STRING(" "));
	}
	inspircd3_protocol_propagate(from, STRING("\n"));
}

// :source PART <channel> [<reason>]
void inspircd3_protocol_propagate_part_channel(struct string from, struct channel_info *channel, struct user_info *user, struct string reason) {
	inspircd3_protocol_propagate(from, STRING(":"));
	inspircd3_protocol_propagate(from, user->uid);
	inspircd3_protocol_propagate(from, STRING(" PART "));
	inspircd3_protocol_propagate(from, channel->name);
	inspircd3_protocol_propagate(from, STRING(" :"));
	inspircd3_protocol_propagate(from, reason);
	inspircd3_protocol_propagate(from, STRING("\n"));
}

// [:source] KICK <channel> <user> [<reason>]
void inspircd3_protocol_propagate_kick_channel(struct string from, struct string source, struct channel_info *channel, struct user_info *user, struct string reason) {
	inspircd3_protocol_propagate(from, STRING(":"));
	inspircd3_protocol_propagate(from, source);
	inspircd3_protocol_propagate(from, STRING(" KICK "));
	inspircd3_protocol_propagate(from, channel->name);
	inspircd3_protocol_propagate(from, STRING(" "));
	inspircd3_protocol_propagate(from, user->uid);
	inspircd3_protocol_propagate(from, STRING(" :"));
	inspircd3_protocol_propagate(from, reason);
	inspircd3_protocol_propagate(from, STRING("\n"));
}

// [:source] PRIVMSG <target> <message>
void inspircd3_protocol_propagate_privmsg(struct string from, struct string source, struct string target, struct string msg) {
	char exists;
	struct user_info *user = get_table_index(user_list, target, &exists).data;
	struct server_info *server;
	if (!exists) {
		user = 0;
		server = get_table_index(server_list, target, &exists).data;
		if (!exists)
			server = 0;
	}

	if (user || server) {
		struct server_info *target_server;
		if (user) {
			target_server = get_table_index(server_list, user->server, &exists).data;
		} else {
			target_server = server;
		}

		if (target_server->protocol != INSPIRCD3_PROTOCOL || STRING_EQ(target_server->sid, SID))
			return;

		struct server_info *adjacent = get_table_index(server_list, target_server->next, &exists).data;
		networks[adjacent->net].send(adjacent->handle, STRING(":"));
		networks[adjacent->net].send(adjacent->handle, source);
		networks[adjacent->net].send(adjacent->handle, STRING(" PRIVMSG "));
		networks[adjacent->net].send(adjacent->handle, target);
		networks[adjacent->net].send(adjacent->handle, STRING(" :"));
		networks[adjacent->net].send(adjacent->handle, msg);
		networks[adjacent->net].send(adjacent->handle, STRING("\n"));
	} else {
		// TODO: Trim target list for channels as well
		inspircd3_protocol_propagate(from, STRING(":"));
		inspircd3_protocol_propagate(from, source);
		inspircd3_protocol_propagate(from, STRING(" PRIVMSG "));
		inspircd3_protocol_propagate(from, target);
		inspircd3_protocol_propagate(from, STRING(" :"));
		inspircd3_protocol_propagate(from, msg);
		inspircd3_protocol_propagate(from, STRING("\n"));
	}
}

// [:source] NOTICE <target> <message>
void inspircd3_protocol_propagate_notice(struct string from, struct string source, struct string target, struct string msg) {
	char exists;
	struct user_info *user = get_table_index(user_list, target, &exists).data;
	struct server_info *server;
	if (!exists) {
		user = 0;
		server = get_table_index(server_list, target, &exists).data;
		if (!exists)
			server = 0;
	}

	if (user || server) {
		struct server_info *target_server;
		if (user) {
			char exists;
			target_server = get_table_index(server_list, user->server, &exists).data;
		} else {
			target_server = server;
		}

		if (target_server->protocol != INSPIRCD3_PROTOCOL || STRING_EQ(target_server->sid, SID))
			return;

		char exists;
		struct server_info *adjacent = get_table_index(server_list, target_server->next, &exists).data;
		networks[adjacent->net].send(adjacent->handle, STRING(":"));
		networks[adjacent->net].send(adjacent->handle, source);
		networks[adjacent->net].send(adjacent->handle, STRING(" NOTICE "));
		networks[adjacent->net].send(adjacent->handle, target);
		networks[adjacent->net].send(adjacent->handle, STRING(" :"));
		networks[adjacent->net].send(adjacent->handle, msg);
		networks[adjacent->net].send(adjacent->handle, STRING("\n"));
	} else {
		// TODO: Trim target list for channels as well
		inspircd3_protocol_propagate(from, STRING(":"));
		inspircd3_protocol_propagate(from, source);
		inspircd3_protocol_propagate(from, STRING(" NOTICE "));
		inspircd3_protocol_propagate(from, target);
		inspircd3_protocol_propagate(from, STRING(" :"));
		inspircd3_protocol_propagate(from, msg);
		inspircd3_protocol_propagate(from, STRING("\n"));
	}
}

int inspircd3_protocol_handle_new_server(struct string from, struct string attached_to, struct server_info *info) {
	return 0;
}

void inspircd3_protocol_handle_unlink_server(struct string from, struct server_info *a, struct server_info *b, size_t protocol) {
	return;
}

int inspircd3_protocol_handle_new_user(struct string from, struct user_info *info) {
	char exists;
	struct server_info *server = get_table_index(server_list, info->server, &exists).data;
	if (STRING_EQ(info->server, SID) || server->protocol != INSPIRCD3_PROTOCOL) {
		info->protocol_specific[INSPIRCD3_PROTOCOL] = 0;
		return 0;
	}

	struct inspircd3_protocol_specific_user *prot_info;
	prot_info = malloc(sizeof(*prot_info));
	if (!prot_info)
		return 1;

	prot_info->memberships.array = malloc(0);
	prot_info->memberships.len = 0;

	info->protocol_specific[INSPIRCD3_PROTOCOL] = prot_info;

	return 0;
}

int inspircd3_protocol_handle_rename_user(struct string from, struct user_info *info, struct string nick, size_t timestamp, struct string timestamp_str, char forced, char immediate) {
	return 0;
}

void inspircd3_protocol_handle_remove_user(struct string from, struct user_info *info, struct string reason, char propagate) {
	char exists;
	struct server_info *server = get_table_index(server_list, info->server, &exists).data;
	if (STRING_EQ(info->server, SID) || server->protocol != INSPIRCD3_PROTOCOL)
		return;

	struct inspircd3_protocol_specific_user *prot_info = info->protocol_specific[INSPIRCD3_PROTOCOL];
	while (prot_info->memberships.len > 0) {
		char exists;
		struct inspircd3_protocol_member_id *mid = get_and_remove_table_index(&(prot_info->memberships), prot_info->memberships.array[0].name, &exists).data;
		free(mid->id_str.data);
		free(mid);
	}
	free(prot_info->memberships.array);
	free(prot_info);

	return;
}

void inspircd3_protocol_handle_kill_user(struct string from, struct string source, struct user_info *info, struct string reason) {
	return;
}

int inspircd3_protocol_handle_oper_user(struct string from, struct user_info *info, struct string type, struct string source) {
	return 0;
}

int inspircd3_protocol_handle_set_account(struct string from, struct user_info *user, struct string account, struct string source) {
	return 0;
}

int inspircd3_protocol_handle_set_cert(struct string from, struct user_info *user, struct string cert, struct string source) {
	return 0;
}

int inspircd3_protocol_handle_set_channel(struct string from, struct channel_info *channel, char is_new_channel, size_t user_count, struct user_info **users) {
	return 0;
}

int inspircd3_protocol_handle_join_channel(struct string from, struct channel_info *channel, size_t user_count, struct user_info **users, char propagate) {
	return 0;
}

void inspircd3_protocol_handle_part_channel(struct string from, struct channel_info *channel, struct user_info *user, struct string reason) {
	return;
}

void inspircd3_protocol_handle_kick_channel(struct string from, struct string source, struct channel_info *channel, struct user_info *user, struct string reason) {
	return;
}

void inspircd3_protocol_fail_new_server(struct string from, struct string attached_to, struct server_info *info) {
	return;
}

void inspircd3_protocol_fail_new_user(struct string from, struct user_info *info) {
	char exists;
	struct server_info *server = get_table_index(server_list, info->server, &exists).data;
	if (STRING_EQ(server->sid, SID) || server->protocol != INSPIRCD3_PROTOCOL)
		return;

	struct inspircd3_protocol_specific_user *prot_info = info->protocol_specific[INSPIRCD3_PROTOCOL];

	for (size_t i = 0; i < prot_info->memberships.len; i++) {
		struct inspircd3_protocol_member_id *member = prot_info->memberships.array[i].ptr.data;
		free(member->id_str.data);
		free(member);
	}

	clear_table(&(prot_info->memberships));
	free(prot_info->memberships.array);
	free(prot_info);

	return;
}

void inspircd3_protocol_fail_rename_user(struct string from, struct user_info *info, struct string nick, size_t timestamp, struct string timestamp_str, char forced, char immediate) {
	return;
}

void inspircd3_protocol_fail_oper_user(struct string from, struct user_info *info, struct string type, struct string source) {
	return;
}

void inspircd3_protocol_fail_set_account(struct string from, struct user_info *user, struct string account, struct string source) {
	return;
}

void inspircd3_protocol_fail_set_cert(struct string from, struct user_info *user, struct string cert, struct string source) {
	return;
}

void inspircd3_protocol_fail_set_channel(struct string from, struct channel_info *channel, char is_new_channel, size_t user_count, struct user_info **users) {
	return;
}

void inspircd3_protocol_fail_join_channel(struct string from, struct channel_info *channel, size_t user_count, struct user_info **users, char propagate) {
	return;
}

void inspircd3_protocol_do_unlink_inner(struct string from, struct server_info *target, struct string reason) {
	target->distance = 1; // Reusing distance for `have passed`, since its set to 0 bc severed anyways

	unsigned char i = 0;
	while (target->connected_to.len > i) {
		struct server_info *adjacent = target->connected_to.array[i].ptr.data;
		if (adjacent->distance != 0) {
			i = 1;
			continue;
		}
		inspircd3_protocol_do_unlink_inner(from, adjacent, reason);
		remove_server(from, adjacent, reason);
	}
}

void inspircd3_protocol_do_unlink(struct string from, struct server_info *a, struct server_info *b) {
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
		inspircd3_protocol_do_unlink_inner(from, a, reason);
		remove_server(from, a, reason);
	} else {
		inspircd3_protocol_do_unlink_inner(from, b, reason);
		remove_server(from, b, reason);
	}

	if (valid)
		free(reason.data);
}

void inspircd3_protocol_introduce_servers_to_inner(size_t net, void *handle, struct string source, struct server_info *target) {
	networks[net].send(handle, STRING(":"));
	networks[net].send(handle, source);
	networks[net].send(handle, STRING(" SERVER "));
	networks[net].send(handle, target->name);
	networks[net].send(handle, STRING(" "));
	networks[net].send(handle, target->sid);
	networks[net].send(handle, STRING(" :"));
	networks[net].send(handle, target->fullname);
	networks[net].send(handle, STRING("\n"));

	for (size_t i = 0; i < target->connected_to.len; i++) {
		struct server_info *adjacent = target->connected_to.array[i].ptr.data;
		if (adjacent->distance > target->distance) {
			inspircd3_protocol_introduce_servers_to_inner(net, handle, target->sid, adjacent);
		}
	}
}

void inspircd3_protocol_introduce_servers_to(size_t net, void *handle) {
	for (size_t i = 0; i < self->connected_to.len; i++) {
		struct server_info *info = self->connected_to.array[i].ptr.data;
		if (info->protocol == INSPIRCD3_PROTOCOL) { // This server hasn't been added to the list yet, so no need to check for that
			inspircd3_protocol_introduce_servers_to_inner(net, handle, SID, info);
		}
	}

	for (size_t i = 0; i < server_list.len; i++) {
		struct server_info *target = server_list.array[i].ptr.data;
		if (target != self && target->protocol != INSPIRCD3_PROTOCOL) {
			networks[net].send(handle, STRING(":"));
			networks[net].send(handle, SID);
			networks[net].send(handle, STRING(" SERVER "));
			networks[net].send(handle, target->name);
			networks[net].send(handle, STRING(" "));
			networks[net].send(handle, target->sid);
			networks[net].send(handle, STRING(" :"));
			networks[net].send(handle, target->fullname);
			networks[net].send(handle, STRING("\n"));
		}
	}
}

void inspircd3_protocol_introduce_user_to(size_t net, void *handle, struct user_info *user, char join_channels) {
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
			struct channel_info *channel = user->channel_list.array[i].ptr.data;

			networks[net].send(handle, STRING(":"));
			networks[net].send(handle, SID);
			networks[net].send(handle, STRING(" FJOIN "));
			networks[net].send(handle, channel->name);
			networks[net].send(handle, STRING(" "));
			networks[net].send(handle, channel->channel_ts_str);
			networks[net].send(handle, STRING(" + :,"));
			networks[net].send(handle, user->uid);

			char exists;
			struct server_info *server = get_table_index(server_list, user->server, &exists).data;

			networks[net].send(handle, STRING(":"));
			struct inspircd3_protocol_specific_user *prot_specific = user->protocol_specific[INSPIRCD3_PROTOCOL];
			struct inspircd3_protocol_member_id *member;
			if (!STRING_EQ(user->server, SID) && server->protocol == INSPIRCD3_PROTOCOL) {
				char exists;
				member = get_table_index(prot_specific->memberships, channel->name, &exists).data;
				if (!exists)
					member = 0;
			} else {
				member = 0;
			}

			if (member)
				networks[net].send(handle, member->id_str);
			else
				networks[net].send(handle, STRING("0"));

			networks[net].send(handle, STRING("\n"));
		}
	}
}

void inspircd3_protocol_introduce_channel_to(size_t net, void *handle, struct channel_info *channel) {
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

		struct user_info *user = channel->user_list.array[i].ptr.data;
		char exists;
		struct server_info *server = get_table_index(server_list, user->server, &exists).data;

		networks[net].send(handle, STRING(":"));
		struct inspircd3_protocol_specific_user *prot_specific = user->protocol_specific[INSPIRCD3_PROTOCOL];
		struct inspircd3_protocol_member_id *member;
		if (!STRING_EQ(user->server, SID) && server->protocol == INSPIRCD3_PROTOCOL) {
			char exists;
			member = get_table_index(prot_specific->memberships, channel->name, &exists).data;
			if (!exists)
				member = 0;
		} else {
			member = 0;
		}

		if (member)
			networks[net].send(handle, member->id_str);
		else
			networks[net].send(handle, STRING("0"));

		if (i != channel->user_list.len - 1)
			networks[net].send(handle, STRING(" "));
	}
	networks[net].send(handle, STRING("\n"));
}

// CAPAB <type> [<args> [, ...]]
int inspircd3_protocol_init_handle_capab(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config **config, char is_incoming) {
	if (argc < 1) {
		WRITES(2, STRING("[InspIRCd v3] Invalid CAPAB received! (Missing parameters)\r\n"));
		return -1;
	}

	if (is_incoming && STRING_EQ(argv[0], STRING("START"))) { // This seems to be a proper server connection by now, can start sending stuff
		networks[net].send(handle, STRING("CAPAB START 1205\nCAPAB END\n"));
	}

	return 0;
}

// SERVER <address> <password> <always 0> <SID> [key=value, ...] <name>
int inspircd3_protocol_init_handle_server(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config **config, char is_incoming) {
	if (argc < 5) {
		WRITES(2, STRING("[InspIRCd v3] Invalid SERVER received! (Missing parameters)\r\n"));
		return -1;
	}

	if (source.len != 0) {
		WRITES(2, STRING("[InspIRCd v3] Server attempting to use a source without having introduced itself!\r\n"));
		return -1;
	}

	if (is_incoming) {
		char exists;
		*config = get_table_index(server_config, argv[3], &exists).data;
		if (!exists) {
			WRITES(2, STRING("[InspIRCd v3] Unknown SID attempted to connect.\r\n"));
			return -1;
		}
	} else {
		if (!STRING_EQ(argv[3], (*config)->sid)) {
			WRITES(2, STRING("[InspIRCd v3] Wrong SID given in SERVER!\r\n"));
			return -1;
		}
	}

	if (!STRING_EQ(argv[1], (*config)->in_pass)) {
		WRITES(2, STRING("[InspIRCd v3] WARNING: Server supplied the wrong password!\r\n"));
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
		WRITES(2, STRING("[InspIRCd v3] ERROR: OOM, severing link.\r\n"));
		return -1;
	}

	networks[net].send(handle, STRING(":"));
	networks[net].send(handle, SID);
	networks[net].send(handle, STRING(" BURST "));
	networks[net].send(handle, time);
	networks[net].send(handle, STRING("\n"));

	inspircd3_protocol_introduce_servers_to(net, handle);

	for (size_t i = 0; i < user_list.len; i++)
		inspircd3_protocol_introduce_user_to(net, handle, user_list.array[i].ptr.data, 0);

	for (size_t i = 0; i < channel_list.len; i++)
		inspircd3_protocol_introduce_channel_to(net, handle, channel_list.array[i].ptr.data);

	networks[net].send(handle, STRING(":"));
	networks[net].send(handle, SID);
	networks[net].send(handle, STRING(" ENDBURST\n"));

	free(time.data);

	if (add_server((*config)->sid, SID, argv[3], argv[0], argv[argc - 1], INSPIRCD3_PROTOCOL, net, handle) != 0) {
		WRITES(2, STRING("ERROR: Unable to add server!\r\n"));
		return -1;
	}

	char exists;
	struct server_info *server = get_table_index(server_list, (*config)->sid, &exists).data;
	server->awaiting_pong = 0;

	return 1;
}

// [:source] PING <target>
int inspircd3_protocol_handle_ping(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming) {
	if (argc < 1) {
		WRITES(2, STRING("[InspIRCd v3] Invalid PING received! (Missing parameters)\r\n"));
		return -1;
	}

	if (STRING_EQ(config->sid, source) && STRING_EQ(SID, argv[0])) {
		char exists;
		struct server_info *server = get_table_index(server_list, config->sid, &exists).data;
		if (!server->awaiting_pong) {
			networks[net].send(handle, STRING(":"));
			networks[net].send(handle, SID);
			networks[net].send(handle, STRING(" PING :"));
			networks[net].send(handle, config->sid);
			networks[net].send(handle, STRING("\n"));

			server->awaiting_pong = 1;
			gettimeofday(&(server->last_ping), 0);
		}
	}

	networks[net].send(handle, STRING(":"));
	networks[net].send(handle, argv[0]);
	networks[net].send(handle, STRING(" PONG :"));
	networks[net].send(handle, source);
	networks[net].send(handle, STRING("\n"));

	return 0;
}

// [:source] PONG <target> <reply_to>
int inspircd3_protocol_handle_pong(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming) {
	struct timeval now;
	gettimeofday(&now, 0);
	char exists;
	struct server_info *server = get_table_index(server_list, config->sid, &exists).data;

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

// [:source] SERVER <address> <SID> [key=value, ...] <name>
int inspircd3_protocol_handle_server(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming) {
	if (argc < 3) {
		WRITES(2, STRING("[InspIRCd v3] Invalid SERVER received! (Missing parameters)\r\n"));
		return -1;
	}

	if (has_table_index(server_list, argv[1])) {
		WRITES(2, STRING("[InspIRCd v3] Duplicate SERVER attempted to be created!\r\n"));
		return -1;
	}

	if (add_server(config->sid, source, argv[1], argv[0], argv[argc - 1], INSPIRCD3_PROTOCOL, net, handle) != 0) {
		WRITES(2, STRING("ERROR: Unable to add server!\r\n"));
		return -1;
	}

	return 0;
}

// [:source] SQUIT <SID> [<reason>?]
int inspircd3_protocol_handle_squit(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming) {
	if (argc < 1) {
		WRITES(2, STRING("[InspIRCd v3] Invalid SQUIT received! (Missing parameters)\r\n"));
		return -1;
	}

	if (STRING_EQ(argv[0], SID)) { // Not an error, this server is trying to split from us
		return -1;
	}

	char exists;
	struct server_info *a = get_table_index(server_list, source, &exists).data;
	if (!exists)
		a = 0;
	struct server_info *b = get_table_index(server_list, argv[0], &exists).data;
	if (!exists)
		b = 0;
	if (!a || !b) { // Maybe we already RSQUIT it or smth
		WRITES(2, STRING("[InspIRCd v3] Invalid SQUIT received! (Unknown source or target)\r\n"));
		return -1;
	}
	if (a->protocol != INSPIRCD3_PROTOCOL || b->protocol != INSPIRCD3_PROTOCOL) { // They're trying to use SQUIT for some unrelated server...
		WRITES(2, STRING("[InspIRCd v3] Invalid SQUIT received! (Bad SID or source)\r\n"));
		return -1;
	}

	unlink_server(config->sid, a, b, INSPIRCD3_PROTOCOL);

	return 0;
}

// [:source] RSQUIT <server name> [<reason>?]
int inspircd3_protocol_handle_rsquit(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming) {
	if (argc < 1) {
		WRITES(2, STRING("[InspIRCd v3] Invalid RSQUIT received! (Missing parameters)\r\n"));
		return -1;
	}

	if (config->ignore_remote_unlinks)
		return 0;

	for (size_t i = 0; i < server_list.len; i++) {
		struct server_info *target = server_list.array[i].ptr.data;
		if (target != self && target->protocol != INSPIRCD3_PROTOCOL)
			continue; // TODO: Maybe actually unlink this somehow
		if (!STRING_EQ(target->name, argv[0]))
			continue;

		if (target == self) {
			networks[net].shutdown(handle);
		} else if (has_table_index(target->connected_to, SID)) {
			networks[target->net].shutdown(target->handle);
		} else {
			char exists;
			struct server_info *next = get_table_index(server_list, target->next, &exists).data;
			networks[next->net].send(next->handle, STRING(":"));
			networks[next->net].send(next->handle, source);
			networks[next->net].send(next->handle, STRING(" RSQUIT "));
			networks[next->net].send(next->handle, argv[0]);
			if (argc > 1) {
				networks[next->net].send(next->handle, STRING(" :"));
				networks[next->net].send(next->handle, argv[1]);
				networks[next->net].send(next->handle, STRING("\n"));
			} else {
				networks[next->net].send(next->handle, STRING(":\n"));
			}
		}

		break;
	}

	return 0;
}

// [:source] UID <UID> <nick_ts> <nick> <host> <vhost> <ident> <address> <user_ts> <modes> [<mode args>] <fullname>
int inspircd3_protocol_handle_uid(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming) {
	if (argc < 10) {
		WRITES(2, STRING("[InspIRCd v3] Invalid UID received! (Missing parameters)\r\n"));
		return -1;
	}

	if (has_table_index(user_list, argv[0])) {
		WRITES(2, STRING("[InspIRCd v3] Duplicate UID attempted to be created!\r\n"));
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
					WRITES(2, STRING("[InspIRCd v3] Invalid UID received! (Mode direction not set)\r\n"));
					return -1;
				}

				switch(inspircd3_protocol_user_mode_types[(unsigned char)argv[8].data[mode_i]]) {
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
						WRITES(2, STRING("[InspIRCd v3] Invalid UID received! (Unknown mode given)\r\n"));
						return -1;
				}
		}

		mode_i++;
	}

	if (arg_i >= argc) {
		WRITES(2, STRING("[InspIRCd v3] Invalid UID received! (Missing mode arguments)\r\n"));
		return -1;
	}

	char err;
	size_t nick_ts = str_to_unsigned(argv[1], &err);
	if (err) {
		WRITES(2, STRING("[InspIRCd v3] Invalid UID received! (Invalid nick timestamp)\r\n"));
		return -1;
	}

	size_t user_ts = str_to_unsigned(argv[7], &err);
	if (err) {
		WRITES(2, STRING("[InspIRCd v3] Invalid UID received! (Invalid user timestamp)\r\n"));
		return -1;
	}

	if (add_user(config->sid, source, argv[0], argv[2], argv[arg_i], argv[5], argv[4], argv[3], argv[6], user_ts, nick_ts, 0, 0, 0, 0, 0) != 0) {
		WRITES(2, STRING("ERROR: Unable to add user!\r\n"));
		return -1;
	}

	return 0;
}

// :source NICK <nick> <timestamp>
int inspircd3_protocol_handle_nick(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming) {
	if (argc < 2) {
		WRITES(2, STRING("[InspIRCd v3] Invalid NICK received! (Missing parameters)\r\n"));
		return -1;
	}

	char err;
	size_t nick_ts = str_to_unsigned(argv[1], &err);
	if (err) {
		WRITES(2, STRING("[InspIRCd v3] Invalid NICK received! (Invalid timestamp)\r\n"));
		return -1;
	}

	char exists;
	struct user_info *user = get_table_index(user_list, source, &exists).data;
	if (!exists)
		return 0; // KILL timings, etc

	if (rename_user(config->sid, user, argv[0], nick_ts, 0, 1) != 0)
		return -1;

	return 0;
}

// :source QUIT [<reason>?]
int inspircd3_protocol_handle_quit(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming) {
	struct string reason;
	if (argc < 1)
		reason = STRING("");
	else
		reason = argv[0];

	char exists;
	struct user_info *user = get_table_index(user_list, source, &exists).data;
	if (!exists)
		return 0; // Maybe KILLed or something

	if (STRING_EQ(user->server, SID)) {
		WRITES(2, STRING("[InspIRCd v3] Invalid QUIT received! (Attempting to quit a local user)\r\n"));
		return -1;
	}

	remove_user(config->sid, user, reason, 1);

	return 0;
}

// [:source] KILL <target> [<reason>?]
int inspircd3_protocol_handle_kill(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming) {
	if (argc < 1) {
		WRITES(2, STRING("[InspIRCd v3] Invalid KILL received! (Missing parameters)\r\n"));
		return -1;
	}

	char exists;
	struct user_info *user = get_table_index(user_list, argv[0], &exists).data;
	if (!exists) {
		for (size_t i = 0; i < user_list.len; i++) {
			struct user_info *tmp = user_list.array[i].ptr.data;
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
		inspircd3_protocol_introduce_user_to(net, handle, user, 1);

	return 0;
}

// :source OPERTYPE <type>
int inspircd3_protocol_handle_opertype(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming) {
	if (argc < 1) {
		WRITES(2, STRING("[InspIRCd v3] Invalid OPERTYPE received! (Missing parameters)\r\n"));
		return -1;
	}

	char exists;
	struct user_info *user = get_table_index(user_list, source, &exists).data;
	if (!exists)
		return 0;

	if (oper_user(config->sid, user, argv[0], config->sid) != 0) {
		WRITES(2, STRING("[InspIRCd v3] ERROR: Unable to set oper type!\r\n"));
		return -1;
	}

	return 0;
}

// [:source] FJOIN <channel> <timestamp> <modes> [<mode args>] <userlist: modes,uid [...]>
int inspircd3_protocol_handle_fjoin(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming) {
	if (argc < 4) {
		WRITES(2, STRING("[InspIRCd v3] Invalid FJOIN received! (Missing parameters)\r\n"));
		return -1;
	}

	char err;
	size_t timestamp = str_to_unsigned(argv[1], &err);
	if (err) {
		WRITES(2, STRING("[InspIRCd v3] Invalid FJOIN received! (Invalid timestamp)\r\n"));
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
					WRITES(2, STRING("[InspIRCd v3] Invalid FJOIN received (Mode direction not set)\r\n"));
					return -1;
				}
				switch(inspircd3_protocol_channel_mode_types[(unsigned char)argv[2].data[i]]) {
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
						WRITES(2, STRING("[InspIRCd v3] Invalid FJOIN received! (User mode put in the modes instead of the user list)\r\n"));
						return -1;
					default:
						WRITES(2, STRING("[InspIRCd v3] Invalid FJOIN received! (Unknown mode given)\r\n"));
						return -1;
				}
		}
	}

	size_t user_count = 0;
	for (size_t i = 0; i < argv[arg_i].len;) {
		while (i < argv[arg_i].len && argv[arg_i].data[i] != ',')
			i++;

		i++;

		while (i < argv[arg_i].len && argv[arg_i].data[i] != ':' && argv[arg_i].data[i] != ' ')
			i++;

		user_count++;

		while (i < argv[arg_i].len && argv[arg_i].data[i] != ' ')
			i++;
	}

	struct user_info **users;
	users = malloc(sizeof(**users) * user_count);
	if (!users && user_count != 0) {
		WRITES(2, STRING("[InspIRCd v3] [FJOIN] OOM! Disconnecting server.\r\n"));
		return -1;
	}

	struct inspircd3_protocol_member_id **members;
	members = malloc(sizeof(*members) * user_count * 2);
	if (!members && user_count != 0)
		goto inspircd3_protocol_handle_fjoin_free_users;

	size_t n = 0;
	for (size_t i = 0; i < argv[arg_i].len; n++) {
		struct string uid;
		while (i < argv[arg_i].len && argv[arg_i].data[i] != ',')
			i++;

		i++;

		uid.data = &(argv[arg_i].data[i]);

		while (i < argv[arg_i].len && argv[arg_i].data[i] != ':' && argv[arg_i].data[i] != ' ')
			i++;

		uid.len = (size_t)(&(argv[arg_i].data[i]) - uid.data);

		char exists;
		users[n] = get_table_index(user_list, uid, &exists).data;
		if (!exists || !users[n]->protocol_specific[INSPIRCD3_PROTOCOL]) // TODO: Check that it's coming the right way too
			user_count--;

		if (i < argv[arg_i].len && argv[arg_i].data[i] != ' ')
			i++;

		struct string mid;
		mid.data = &(argv[arg_i].data[i]);

		while (i < argv[arg_i].len && argv[arg_i].data[i] != ' ')
			i++;

		if (!exists || !users[n]->protocol_specific[INSPIRCD3_PROTOCOL]) {
			n--;
			continue;
		}

		mid.len = (size_t)(&(argv[arg_i].data[i]) - mid.data);
		if (mid.len == 0)
			mid = STRING("0");

		char err;
		size_t mid_number = str_to_unsigned(mid, &err);
		if (err) {
			WRITES(2, STRING("[InspIRCd v3] [FJOIN] Invalid member ID given!\r\n"));
			goto inspircd3_protocol_handle_fjoin_free_member_ids;
		}

		members[n] = malloc(sizeof(**members));
		if (!members[n])
			goto inspircd3_protocol_handle_fjoin_free_member_ids;


		members[n]->id = mid_number;

		if (str_clone(&(members[n]->id_str), mid) != 0) {
			free(members[n]);
			goto inspircd3_protocol_handle_fjoin_free_member_ids;
		}
	}

	for (n = 0; n < user_count; n++) {
		struct inspircd3_protocol_specific_user *this = users[n]->protocol_specific[INSPIRCD3_PROTOCOL];
		char exists;
		members[user_count + n] = get_table_index(this->memberships, argv[0], &exists).data;
		if (!exists)
			members[user_count + n] = 0;
		if (set_table_index(&(this->memberships), argv[0], (union table_ptr){.data = members[n]}) != 0)
			goto inspircd3_protocol_handle_fjoin_reset_member_ids;
	}

	for (size_t i = 0; i < user_count; i++) {
		if (members[user_count + i]) {
			free(members[user_count + i]->id_str.data);
			free(members[user_count + i]);
		}
	}

	char exists;
	struct channel_info *channel = get_table_index(channel_list, argv[0], &exists).data;
	if (!exists || timestamp < channel->channel_ts) {
		if (set_channel(config->sid, argv[0], timestamp, user_count, users) != 0)
			goto inspircd3_protocol_handle_fjoin_free_member_ids;
	} else {
		if (join_channel(config->sid, channel, user_count, users, 1) != 0)
			goto inspircd3_protocol_handle_fjoin_free_member_ids;
	}

	free(members);
	free(users);

	return 0;

	inspircd3_protocol_handle_fjoin_reset_member_ids:
	for (size_t x = n; x > 0;) {
		x--;
		struct inspircd3_protocol_specific_user *this = users[x]->protocol_specific[INSPIRCD3_PROTOCOL];
		if (members[user_count + x])
			set_table_index(&(this->memberships), argv[0], (union table_ptr){.data = members[user_count + x]}); // Cannot fail
		else
			remove_table_index(&(this->memberships), argv[0]);
	}

	n = user_count;
	inspircd3_protocol_handle_fjoin_free_member_ids:
	for (size_t x = n; n > 0;) {
		n--;
		free(members[x]->id_str.data);
		free(members[x]);
	}
	free(members);
	inspircd3_protocol_handle_fjoin_free_users:
	free(users);
	return -1;
}

// :source IJOIN <channel> <member id>
int inspircd3_protocol_handle_ijoin(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming) {
	if (argc < 2) {
		WRITES(2, STRING("[InspIRCd v3] Invalid IJOIN received! (Missing parameters)\r\n"));
		return -1;
	}

	char exists;
	struct user_info *user = get_table_index(user_list, source, &exists).data;
	if (!exists)
		return 0;

	struct string *mid;
	mid = malloc(sizeof(*mid));
	if (!mid)
		return -1;

	if (str_clone(mid, argv[1]) != 0) {
		free(mid);
		return -1;
	}

	struct inspircd3_protocol_specific_user *this = user->protocol_specific[INSPIRCD3_PROTOCOL];

	struct string *old_mid = get_table_index(this->memberships, argv[0], &exists).data;
	if (!exists)
		old_mid = 0;
	if (set_table_index(&(this->memberships), argv[0], (union table_ptr){.data = mid}) != 0) {
		free(mid->data);
		free(mid);
		return -1;
	}

	struct channel_info *channel = get_table_index(channel_list, argv[0], &exists).data;
	if (!exists) {
		size_t timestamp;
		{
			ssize_t t = time(0);
			if (t < 0) {
				WRITES(2, STRING("Please check your clock.\r\n"));
				if (old_mid)
					set_table_index(&(this->memberships), argv[0], (union table_ptr){.data = old_mid});
				else
					remove_table_index(&(this->memberships), argv[0]);
				free(mid->data);
				free(mid);
				return -1;
			}
			timestamp = (size_t)t;
		}
		if (set_channel(config->sid, argv[0], timestamp, 1, &user) != 0) {
			if (old_mid)
				set_table_index(&(this->memberships), argv[0], (union table_ptr){.data = old_mid});
			else
				remove_table_index(&(this->memberships), argv[0]);
			free(mid->data);
			free(mid);
			return -1;
		}
	} else {
		if (join_channel(config->sid, channel, 1, &user, 1) != 0) {
			if (old_mid)
				set_table_index(&(this->memberships), argv[0], (union table_ptr){.data = old_mid});
			else
				remove_table_index(&(this->memberships), argv[0]);
			free(mid->data);
			free(mid);
			return -1;
		}
	}

	if (old_mid) {
		free(old_mid->data);
		free(old_mid);
	}

	return 0;
}

// :source PART <channel> [<reason>]
int inspircd3_protocol_handle_part(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming) {
	if (argc < 1) {
		WRITES(2, STRING("[InspIRCd v3] Invalid PART received! (Missing parameters)\r\n"));
		return -1;
	}
	struct string reason;
	if (argc < 2)
		reason = STRING("");
	else
		reason = argv[1];

	char exists;
	struct user_info *user = get_table_index(user_list, source, &exists).data;
	if (!user)
		return 0;

	struct channel_info *channel = get_table_index(channel_list, argv[0], &exists).data;
	if (!channel)
		return 0;

	part_channel(config->sid, channel, user, reason, 1);

	return 0;
}

// [:source] KICK <channel> <user> [<member id>] [<reason>]
int inspircd3_protocol_handle_kick(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming) {
	if (argc < 2) {
		WRITES(2, STRING("[InspIRCd v3] Invalid KICK received! (Missing parameters)\r\n"));
		return -1;
	}

	char exists;
	struct channel_info *channel = get_table_index(channel_list, argv[0], &exists).data;
	if (!exists)
		return 0;

	struct user_info *user = get_table_index(user_list, argv[1], &exists).data;
	if (!exists) {
		char found = 0;
		for (size_t i = 0; i < user_list.len; i++) {
			user = user_list.array[i].ptr.data;
			if (STRING_EQ(user->nick, argv[1])) {
				found = 1;
				break;
			}
		}
		if (!found)
			return 0;
	}

	char uses_inspircd3;
	if (!STRING_EQ(user->server, SID)) {
		char exists;
		struct server_info *server = get_table_index(server_list, user->server, &exists).data;
		uses_inspircd3 = (server->protocol == INSPIRCD3_PROTOCOL);
	} else {
		uses_inspircd3 = 0;
	}

	struct string reason;
	if (argc >= 4) {
		if (uses_inspircd3) {
			char err;
			size_t member_id = str_to_unsigned(argv[2], &err);
			if (err) {
				kill_user(SID, SID, user, STRING("Member ID limit exceeded. Please reconnect to reset it."));
				return 0;
			}

			struct inspircd3_protocol_specific_user *prot_specific = user->protocol_specific[INSPIRCD3_PROTOCOL];
			char exists;
			struct inspircd3_protocol_member_id *current_member_id = get_table_index(prot_specific->memberships, channel->name, &exists).data;
			if (member_id < current_member_id->id)
				return 0; // Kick was for an old membership, ignore it
		}

		reason = argv[3];
	} else if (argc >= 3) {
		reason = argv[2];
	} else {
		reason = STRING("");
	}

	int rejoin = kick_channel(config->sid, source, channel, user, reason);

	if (rejoin) {
		char exists;
		struct server_info *server = get_table_index(server_list, user->server, &exists).data;
		networks[net].send(handle, STRING(":"));
		networks[net].send(handle, SID);
		networks[net].send(handle, STRING(" FJOIN "));
		networks[net].send(handle, channel->name);
		networks[net].send(handle, STRING(" "));
		networks[net].send(handle, channel->channel_ts_str);
		networks[net].send(handle, STRING(" + :,"));
		networks[net].send(handle, user->uid);
		if (!STRING_EQ(server->sid, SID) && server->protocol == INSPIRCD3_PROTOCOL) {
			networks[net].send(handle, STRING(":"));
			struct inspircd3_protocol_specific_user *prot_specific = user->protocol_specific[INSPIRCD3_PROTOCOL];
			struct string *mid = get_table_index(prot_specific->memberships, channel->name, &exists).data;
			if (exists)
				networks[net].send(handle, *mid);
			else
				networks[net].send(handle, STRING("0"));
			networks[net].send(handle, STRING("\n"));
		} else {
			networks[net].send(handle, STRING(":0\n"));
		}
	}

	return 0;
}

// [:source] PRIVMSG <target> <message>
int inspircd3_protocol_handle_privmsg(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming) {
	if (argc < 2) {
		WRITES(2, STRING("[InspIRCd v3] Invalid PRIVMSG received! (Missing parameters)\r\n"));
		return -1;
	}

	privmsg(config->sid, source, argv[0], argv[1]);

	return 0;
}

// [:source] NOTICE <target> <message>
int inspircd3_protocol_handle_notice(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming) {
	if (argc < 2) {
		WRITES(2, STRING("[InspIRCd v3] Invalid NOTICE received! (Missing parameters)\r\n"));
		return -1;
	}

	notice(config->sid, source, argv[0], argv[1]);

	return 0;
}

// :source MODE <target> <modes> [<mode args>]
int inspircd3_protocol_handle_mode(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming) {
	if (argc < 2) {
		WRITES(2, STRING("[InspIRCd v3] Invalid MODE received! (Missing parameters)\r\n"));
		return -1;
	}

	char exists;
	struct user_info *user = get_table_index(user_list, argv[0], &exists).data;
	if (!exists) {
		if (has_table_index(server_list, argv[0]))
			return 0; // TODO: Probably not actually valid

		char found = 0;
		for (size_t i = 0; i < user_list.len; i++) {
			user = user_list.array[i].ptr.data;
			if (case_string_eq(user->nick, argv[0])) {
				found = 1;
				break;
			}
		}

		if (!found)
			return 0;
	}

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
					WRITES(2, STRING("[InspIRCd v3] Invalid MODE received (Mode direction not set)\r\n"));
					return -1;
				}
				switch(inspircd3_protocol_user_mode_types[(unsigned char)argv[1].data[i]]) {
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
						WRITES(2, STRING("[InspIRCd v3] Invalid MODE received! (Unknown mode given)\r\n"));
						return -1;
				}
		}
	}

	return 0;
}

// :source FMODE <target> <timestamp> <modes> [<mode args>]
int inspircd3_protocol_handle_fmode(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming) {
	if (argc < 3) {
		WRITES(2, STRING("[InspIRCd v3] Invalid MODE received! (Missing parameters)\r\n"));
		return -1;
	}

	char exists;
	struct user_info *user = get_table_index(user_list, argv[0], &exists).data;
	if (!exists) {
		if (has_table_index(server_list, argv[0]))
			return 0; // TODO: Probably not actually valid

		char found = 0;
		for (size_t i = 0; i < user_list.len; i++) {
			user = user_list.array[i].ptr.data;
			if (case_string_eq(user->nick, argv[0])) {
				found = 1;
				break;
			}
		}

		if (!found)
			return 0;
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
					WRITES(2, STRING("[InspIRCd v3] Invalid MODE received (Mode direction not set)\r\n"));
					return -1;
				}
				switch(inspircd3_protocol_user_mode_types[(unsigned char)argv[2].data[i]]) {
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
						WRITES(2, STRING("[InspIRCd v3] Invalid MODE received! (Unknown mode given)\r\n"));
						return -1;
				}
		}
	}

	return 0;
}

// [:source] METADATA <target> <key> <value>
int inspircd3_protocol_handle_metadata(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming) {
	if (argc < 3) {
		WRITES(2, STRING("[InspIRCd v3] Invalid METADATA received! (Missing parameters)\r\n"));
		return -1;
	}

	struct user_info *info;
	do {
		char exists;
		info = get_table_index(user_list, argv[0], &exists).data;
		if (exists)
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
