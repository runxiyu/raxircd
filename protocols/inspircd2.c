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

int init_inspircd2_protocol(void) {
	inspircd2_protocol_commands.array = malloc(0);

	set_table_index(&inspircd2_protocol_init_commands, STRING("CAPAB"), &inspircd2_protocol_init_handle_capab);
	set_table_index(&inspircd2_protocol_init_commands, STRING("SERVER"), &inspircd2_protocol_init_handle_server);
	set_table_index(&inspircd2_protocol_commands, STRING("PING"), &inspircd2_protocol_handle_ping);

	return 0;
}

void * inspircd2_protocol_handle_connection(void *type) {
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

	struct string full_msg = {.data = malloc(0), .len = 0}; // TODO: move this down below after incoming connections are handled

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

						networks[net].send(handle, STRING(":"));
						networks[net].send(handle, SID);
						networks[net].send(handle, STRING(" PING "));
						networks[net].send(handle, SID);
						networks[net].send(handle, STRING(" :"));
						networks[net].send(handle, config->sid);
						networks[net].send(handle, STRING("\n"));
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
				WRITES(2, STRING("Protocol violation: empty message.\r\n\n"));
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
					WRITES(2, STRING("Protocol violation: source prefix but no source.\r\n\n"));
					goto inspircd2_protocol_handle_connection_close;
				}
				if (!found || offset >= msg_len) {
					WRITES(2, STRING("Protocol violation: source but no command.\r\n\n"));
					goto inspircd2_protocol_handle_connection_close;
				}
			} else {
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

			WRITES(2, STRING("Source: `"));
			WRITES(2, source);
			WRITES(2, STRING("'\r\nCommand: `"));
			WRITES(2, command);
			WRITES(2, STRING("'\r\n"));
			if (argc > 0) {
				WRITES(2, STRING("Args:\r\n"));
				for (size_t i = 0; i < argc; i++) {
					WRITES(2, STRING("\t`"));
					WRITES(2, argv[i]);
					WRITES(2, STRING("'\r\n"));
				}
			}

			pthread_mutex_lock(&state_lock);

			if (!ready) {
				int (*func)(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config **config, char is_incoming);
				func = get_table_index(inspircd2_protocol_init_commands, command);
				if (!func) {
					WRITES(2, STRING("WARNING: Command is unknown, ignoring.\r\n\n"));
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
					WRITES(2, STRING("WARNING: Command is unknown, ignoring.\r\n\n"));
					goto inspircd2_protocol_handle_connection_unlock_next;
				}

				int res = func(source, argc, argv, net, handle, config, is_incoming);
				if (res < 0) // Disconnect
					goto inspircd2_protocol_handle_connection_unlock_close;
			}

			inspircd2_protocol_handle_connection_unlock_next:
			pthread_mutex_unlock(&state_lock);
			inspircd2_protocol_handle_connection_next:
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
		for (time_t current = time(NULL); current < last_time + 60; current = time(NULL))
			sleep(60 - (current - last_time));
		last_time = time(NULL);

		info->fd = networks[type->net_type].connect(&(info->handle), config->address, config->port, &(info->address));
		if (info->fd == -1)
			continue;

		inspircd2_protocol_handle_connection(info);
	}
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
		if (!has_table_index(server_config, argv[3])) {
			WRITES(2, STRING("[InspIRCd v2] Unknown SID attempted to connect.\r\n"));
			return -1;
		}
		*config = get_table_index(server_config, argv[3]);
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
	networks[net].send(handle, STRING("\n:"));
	networks[net].send(handle, SID);
	networks[net].send(handle, STRING(" ENDBURST\n"));

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
