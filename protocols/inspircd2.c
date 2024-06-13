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
#include <unistd.h>

#include "../config.h"
#include "../general_network.h"
#include "../haxstring.h"
#include "../haxstring_utils.h"
#include "../main.h"
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
	set_table_index(&inspircd2_protocol_commands, STRING("SERVER"), &inspircd2_protocol_handle_server);
	set_table_index(&inspircd2_protocol_commands, STRING("SQUIT"), &inspircd2_protocol_handle_squit);
	set_table_index(&inspircd2_protocol_commands, STRING("RSQUIT"), &inspircd2_protocol_handle_rsquit);

	set_table_index(&inspircd2_protocol_commands, STRING("UID"), &inspircd2_protocol_handle_uid);
	set_table_index(&inspircd2_protocol_commands, STRING("NICK"), &inspircd2_protocol_handle_nick);
	set_table_index(&inspircd2_protocol_commands, STRING("QUIT"), &inspircd2_protocol_handle_quit);
	set_table_index(&inspircd2_protocol_commands, STRING("KILL"), &inspircd2_protocol_handle_kill);

	return 0;
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
					goto inspircd2_protocol_handle_connection_close;
				} else if (err == 1) { // Timed out
					if (ready) {
						if (timeout > 0)
							goto inspircd2_protocol_handle_connection_close;
						timeout++;

						pthread_mutex_lock(&(state_lock));
						networks[net].send(handle, STRING(":"));
						networks[net].send(handle, SID);
						networks[net].send(handle, STRING(" PING "));
						networks[net].send(handle, SID);
						networks[net].send(handle, STRING(" :"));
						networks[net].send(handle, config->sid);
						networks[net].send(handle, STRING("\n"));
						pthread_mutex_unlock(&(state_lock));
					} else {
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

			WRITES(2, STRING("[InspIRCd v2] [server -> us] Got `"));
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

			pthread_mutex_lock(&state_lock);

			if (!ready) {
				int (*func)(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config **config, char is_incoming);
				func = get_table_index(inspircd2_protocol_init_commands, command);
				if (!func) {
					WRITES(2, STRING("WARNING: Command is unknown, ignoring.\r\n"));
					goto inspircd2_protocol_handle_connection_unlock_next;
				}

				int res = func(source, argc, argv, net, handle, &config, is_incoming);
				if (res < 0) // Disconnect
					goto inspircd2_protocol_handle_connection_unlock_close;
				else if (res > 0) // Connection is now "ready"
					ready = 1;
			} else {
				int (*func)(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming);
				func = get_table_index(inspircd2_protocol_commands, command);
				if (!func) {
					WRITES(2, STRING("WARNING: Command is unknown, ignoring.\r\n"));
					goto inspircd2_protocol_handle_connection_unlock_next;
				}

				int res = func(source, argc, argv, net, handle, config, is_incoming);
				if (res < 0) // Disconnect
					goto inspircd2_protocol_handle_connection_unlock_close;
			}

			inspircd2_protocol_handle_connection_unlock_next:
			WRITES(2, STRING("\n"));

			pthread_mutex_unlock(&state_lock);
			memmove(full_msg.data, full_msg.data + msg_len + 1, full_msg.len - msg_len - 1);
			full_msg.len -= msg_len + 1;
			void *tmp = realloc(full_msg.data, full_msg.len);
			if (tmp || full_msg.len == 0)
				full_msg.data = tmp;
		}
	}

	inspircd2_protocol_handle_connection_unlock_close:
	pthread_mutex_unlock(&state_lock);
	inspircd2_protocol_handle_connection_close:
	free(full_msg.data);

	if (ready) {
		pthread_mutex_lock(&(state_lock));
		unlink_server(config->sid, get_table_index(server_list, config->sid), get_table_index(server_list, SID), INSPIRCD2_PROTOCOL);
		pthread_mutex_unlock(&(state_lock));
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
	struct server_info *self = get_table_index(server_list, SID);
	for (size_t i = 0; i < server_list.len; i++) {
		struct server_info *other = server_list.array[i].ptr;
		if (other->protocol == INSPIRCD2_PROTOCOL) {
			other->distance = 0;
		}
	}

	inspircd2_protocol_update_propagations_inner(self);
}

void inspircd2_protocol_propagate_new_server(struct string from, struct string attached_to, struct server_info *info) {
	struct server_info *self = get_table_index(server_list, SID);

	for (size_t i = 0; i < self->connected_to.len; i++) {
		struct server_info *adjacent = self->connected_to.array[i].ptr;
		if (adjacent->protocol != INSPIRCD2_PROTOCOL || STRING_EQ(from, adjacent->sid))
			continue; // Not ours or it's the source of this message

		networks[adjacent->net].send(adjacent->handle, STRING(":"));

		if (info->protocol == INSPIRCD2_PROTOCOL)
			networks[adjacent->net].send(adjacent->handle, attached_to);
		else // Just pretend servers connected via a different protocol are connected directly to us
			networks[adjacent->net].send(adjacent->handle, SID);

		networks[adjacent->net].send(adjacent->handle, STRING(" SERVER "));
		networks[adjacent->net].send(adjacent->handle, info->name);
		networks[adjacent->net].send(adjacent->handle, STRING(" * 0 "));
		networks[adjacent->net].send(adjacent->handle, info->sid);
		networks[adjacent->net].send(adjacent->handle, STRING(" :"));
		networks[adjacent->net].send(adjacent->handle, info->fullname);
		networks[adjacent->net].send(adjacent->handle, STRING("\n"));

		networks[adjacent->net].send(adjacent->handle, STRING(":"));
		networks[adjacent->net].send(adjacent->handle, info->sid);
		networks[adjacent->net].send(adjacent->handle, STRING(" BURST "));

		time_t current = time(0);
		struct string current_time;
		char err = unsigned_to_str((size_t)current, &current_time);

		if (current < 0 || err) {
			networks[adjacent->net].send(adjacent->handle, STRING("1"));
		} else {
			networks[adjacent->net].send(adjacent->handle, current_time);
			free(current_time.data);
		}

		networks[adjacent->net].send(adjacent->handle, STRING("\n:"));
		networks[adjacent->net].send(adjacent->handle, info->sid);
		networks[adjacent->net].send(adjacent->handle, STRING(" ENDBURST\n"));
	}
}

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

	struct server_info *self = get_table_index(server_list, SID);
	for (size_t i = 0; i < self->connected_to.len; i++) {
		struct server_info *adjacent = self->connected_to.array[i].ptr;
		if (STRING_EQ(from, adjacent->next) || adjacent->protocol != INSPIRCD2_PROTOCOL)
			continue;

		networks[adjacent->net].send(adjacent->handle, STRING(":"));
		if (protocol == INSPIRCD2_PROTOCOL)
			networks[adjacent->net].send(adjacent->handle, source->sid);
		else
			networks[adjacent->net].send(adjacent->handle, SID);
		networks[adjacent->net].send(adjacent->handle, STRING(" SQUIT "));
		networks[adjacent->net].send(adjacent->handle, target->sid);
		networks[adjacent->net].send(adjacent->handle, STRING(" :\n"));
	}
}

void inspircd2_protocol_propagate_new_user(struct string from, struct user_info *info) {
	struct server_info *self = get_table_index(server_list, SID);

	for (size_t i = 0; i < self->connected_to.len; i++) {
		struct server_info *adjacent = self->connected_to.array[i].ptr;
		if (adjacent->protocol != INSPIRCD2_PROTOCOL || STRING_EQ(from, adjacent->sid))
			continue;

		networks[adjacent->net].send(adjacent->handle, STRING(":"));
		networks[adjacent->net].send(adjacent->handle, info->server);
		networks[adjacent->net].send(adjacent->handle, STRING(" UID "));
		networks[adjacent->net].send(adjacent->handle, info->uid);
		networks[adjacent->net].send(adjacent->handle, STRING(" "));
		networks[adjacent->net].send(adjacent->handle, info->nick_ts_str);
		networks[adjacent->net].send(adjacent->handle, STRING(" "));
		networks[adjacent->net].send(adjacent->handle, info->nick);
		networks[adjacent->net].send(adjacent->handle, STRING(" "));
		networks[adjacent->net].send(adjacent->handle, info->host);
		networks[adjacent->net].send(adjacent->handle, STRING(" "));
		networks[adjacent->net].send(adjacent->handle, info->vhost);
		networks[adjacent->net].send(adjacent->handle, STRING(" "));
		networks[adjacent->net].send(adjacent->handle, info->ident);
		networks[adjacent->net].send(adjacent->handle, STRING(" "));
		networks[adjacent->net].send(adjacent->handle, info->address);
		networks[adjacent->net].send(adjacent->handle, STRING(" "));
		networks[adjacent->net].send(adjacent->handle, info->user_ts_str);
		networks[adjacent->net].send(adjacent->handle, STRING(" + :"));
		networks[adjacent->net].send(adjacent->handle, info->fullname);
		networks[adjacent->net].send(adjacent->handle, STRING("\n"));
	}
}

void inspircd2_protocol_propagate_rename_user(struct string from, struct user_info *user, struct string nick, size_t timestamp, struct string timestamp_str) {
	struct server_info *self = get_table_index(server_list, SID);

	for (size_t i = 0; i < self->connected_to.len; i++) {
		struct server_info *adjacent = self->connected_to.array[i].ptr;
		if (adjacent->protocol != INSPIRCD2_PROTOCOL || STRING_EQ(from, adjacent->sid))
			continue;

		networks[adjacent->net].send(adjacent->handle, STRING(":"));
		networks[adjacent->net].send(adjacent->handle, user->uid);
		networks[adjacent->net].send(adjacent->handle, STRING(" NICK "));
		networks[adjacent->net].send(adjacent->handle, nick);
		networks[adjacent->net].send(adjacent->handle, STRING(" "));
		networks[adjacent->net].send(adjacent->handle, timestamp_str);
		networks[adjacent->net].send(adjacent->handle, STRING("\n"));
	}
}

void inspircd2_protocol_propagate_remove_user(struct string from, struct user_info *info, struct string reason) {
	struct server_info *self = get_table_index(server_list, SID);

	for (size_t i = 0; i < self->connected_to.len; i++) {
		struct server_info *adjacent = self->connected_to.array[i].ptr;
		if (adjacent->protocol != INSPIRCD2_PROTOCOL || STRING_EQ(from, adjacent->sid))
			continue;

		networks[adjacent->net].send(adjacent->handle, STRING(":"));
		networks[adjacent->net].send(adjacent->handle, info->uid);
		networks[adjacent->net].send(adjacent->handle, STRING(" QUIT :"));
		networks[adjacent->net].send(adjacent->handle, reason);
		networks[adjacent->net].send(adjacent->handle, STRING("\n"));
	}
}

void inspircd2_protocol_propagate_kill_user(struct string from, struct string source, struct user_info *info, struct string reason) {
	struct server_info *self = get_table_index(server_list, SID);

	for (size_t i = 0; i < self->connected_to.len; i++) {
		struct server_info *adjacent = self->connected_to.array[i].ptr;
		if (adjacent->protocol != INSPIRCD2_PROTOCOL || STRING_EQ(from, adjacent->sid))
			continue;

		networks[adjacent->net].send(adjacent->handle, STRING(":"));
		networks[adjacent->net].send(adjacent->handle, source);
		networks[adjacent->net].send(adjacent->handle, STRING(" KILL "));
		networks[adjacent->net].send(adjacent->handle, info->uid);
		networks[adjacent->net].send(adjacent->handle, STRING(" :"));
		networks[adjacent->net].send(adjacent->handle, reason);
		networks[adjacent->net].send(adjacent->handle, STRING("\n"));
	}
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
	struct server_info *self = get_table_index(server_list, SID);
	for (size_t i = 0; i < self->connected_to.len; i++) {
		struct server_info *info = self->connected_to.array[i].ptr;
		if (info->protocol == INSPIRCD2_PROTOCOL) { // This server hasn't been added to the list yet, so no need to check for that
			inspircd2_protocol_introduce_servers_to_inner(net, handle, SID, info);
		}
	}
}

void inspircd2_protocol_introduce_user_to(size_t net, void *handle, struct user_info *user) {
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
}

// CAPAB <type> [<args> [, ...]]
int inspircd2_protocol_init_handle_capab(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config **config, char is_incoming) {
	if (argc < 1) {
		WRITES(2, STRING("[InspIRCd v2] Invalid CAPAB recieved! (Missing parameters)\r\n"));
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
		WRITES(2, STRING("[InspIRCd v2] Invalid SERVER recieved! (Missing parameters)\r\n"));
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
		inspircd2_protocol_introduce_user_to(net, handle, user_list.array[i].ptr);

	networks[net].send(handle, STRING(":"));
	networks[net].send(handle, SID);
	networks[net].send(handle, STRING(" ENDBURST\n"));

	free(time.data);

	if (add_server((*config)->sid, SID, argv[3], argv[0], argv[4], INSPIRCD2_PROTOCOL, net, handle) != 0) {
		WRITES(2, STRING("ERROR: Unable to add server!\r\n"));
		return -1;
	}

	return 1;
}

// [:source] PING <reply_to> <target>
int inspircd2_protocol_handle_ping(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming) {
	if (argc < 2) {
		WRITES(2, STRING("[InspIRCd v2] Invalid PING recieved! (Missing parameters)\r\n"));
		return -1;
	}

	networks[net].send(handle, STRING(":"));
	networks[net].send(handle, argv[1]);
	networks[net].send(handle, STRING(" PONG "));
	networks[net].send(handle, argv[1]);
	networks[net].send(handle, STRING(" :"));
	networks[net].send(handle, argv[0]);
	networks[net].send(handle, STRING("\n"));

	return 0;
}

// [:source] SERVER <address> <password> <always 0> <SID> <name>
int inspircd2_protocol_handle_server(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming) {
	if (argc < 5) {
		WRITES(2, STRING("[InspIRCd v2] Invalid SERVER recieved! (Missing parameters)\r\n"));
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
		WRITES(2, STRING("[InspIRCd v2] Invalid SQUIT recieved! (Missing parameters)\r\n"));
		return -1;
	}

	if (STRING_EQ(argv[0], SID)) { // Not an error, this server is trying to split from us
		return -1;
	}

	struct server_info *a = get_table_index(server_list, source);
	struct server_info *b = get_table_index(server_list, argv[0]);
	if (!a || !b) { // Maybe we already RSQUIT it or smth
		WRITES(2, STRING("[InspIRCd v2] Invalid SQUIT recieved! (Unknown source or target)\r\n"));
		return -1;
	}
	if (a->protocol != INSPIRCD2_PROTOCOL || b->protocol != INSPIRCD2_PROTOCOL) { // They're trying to use SQUIT for some unrelated server...
		WRITES(2, STRING("[InspIRCd v2] Invalid SQUIT recieved! (Bad SID or source)\r\n"));
		return -1;
	}

	unlink_server(config->sid, a, b, INSPIRCD2_PROTOCOL);

	return 0;
}

// [:source] RSQUIT <server name> [<reason>?]
int inspircd2_protocol_handle_rsquit(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming) {
	if (argc < 1) {
		WRITES(2, STRING("[InspIRCd v2] Invalid RSQUIT recieved! (Missing parameters)\r\n"));
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
				networks[next->net].send(next->handle, STRING(":\n"));
			}
		}
	}

	return 0;
}

// [:source] UID <UID> <nick_ts> <nick> <host> <vhost> <ident> <address> <user_ts> <modes> [<mode args>] <fullname>
int inspircd2_protocol_handle_uid(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming) {
	if (argc < 10) {
		WRITES(2, STRING("[InspIRCd v2] Invalid UID recieved! (Missing parameters)\r\n"));
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
					WRITES(2, STRING("[InspIRCd v2] Invalid UID recieved! (Mode direction not set)\r\n"));
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
						WRITES(2, STRING("[InspIRCd v2] Invalid UID recieved! (Unknown mode given)\r\n"));
						return -1;
				}
		}

		mode_i++;
	}

	if (arg_i >= argc) {
		WRITES(2, STRING("[InspIRCd v2] Invalid UID recieved! (Missing mode arguments)\r\n"));
		return -1;
	}

	char err;
	size_t nick_ts = str_to_unsigned(argv[1], &err);
	if (err) {
		WRITES(2, STRING("[InspIRCd v2] Invalid UID recieved! (Invalid nick timestamp)\r\n"));
		return -1;
	}

	size_t user_ts = str_to_unsigned(argv[7], &err);
	if (err) {
		WRITES(2, STRING("[InspIRCd v2] Invalid UID recieved! (Invalid user timestamp)\r\n"));
		return -1;
	}

	if (add_user(config->sid, source, argv[0], argv[2], argv[arg_i], argv[5], argv[4], argv[3], argv[6], user_ts, nick_ts, 0, 0, 0) != 0) {
		WRITES(2, STRING("ERROR: Unable to add user!\r\n"));
		return -1;
	}

	return 0;
}

// :source NICK <nick> <timestamp>
int inspircd2_protocol_handle_nick(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming) {
	if (argc < 2) {
		WRITES(2, STRING("[InspIRCd v2] Invalid NICK recieved! (Missing parameters)\r\n"));
		return -1;
	}

	char err;
	size_t nick_ts = str_to_unsigned(argv[1], &err);
	if (err) {
		WRITES(2, STRING("[InspIRCd v2] Invalid NICK recieved! (Invalid timestamp)\r\n"));
		return -1;
	}

	struct user_info *user = get_table_index(user_list, source);
	if (!user)
		return 0; // KILL timings, etc

	if (rename_user(config->sid, user, argv[0], nick_ts) != 0)
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
		WRITES(2, STRING("[InspIRCd v2] Invalid QUIT recieved! (Attempting to quit a local user)\r\n"));
		return -1;
	}

	remove_user(config->sid, user, reason, 1);

	return 0;
}

// [:source] KILL <target> [<reason>?]
int inspircd2_protocol_handle_kill(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming) {
	if (argc < 1) {
		WRITES(2, STRING("[InspIRCd v2] Invalid KILL recieved! (Missing parameters)\r\n"));
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

	if (STRING_EQ(user->server, SID)) {
		if (config->ignore_local_kills) {
			inspircd2_protocol_introduce_user_to(net, handle, user);
		} else {
			if (argc > 1)
				kill_user(config->sid, source, user, argv[1]);
			else
				kill_user(config->sid, source, user, STRING(""));
		}
	} else if (config->ignore_remote_kills) {
		inspircd2_protocol_introduce_user_to(net, handle, user);
	} else {
		if (argc > 1)
			kill_user(config->sid, source, user, argv[1]);
		else
			kill_user(config->sid, source, user, STRING(""));
	}

	return 0;
}
