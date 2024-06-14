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

#include <stddef.h>
#include <stdlib.h>
#include <time.h>

#include "../config.h"
#include "../haxstring.h"
#include "../haxstring_utils.h"
#include "../general_network.h"
#include "../psuedoclients.h"

struct table haxserv_psuedoclient_commands = {0};

// TODO: Potentially leaky on failure
int haxserv_psuedoclient_init(void) {
	size_t now;
	{
		time_t tmp = time(0);
		if (tmp < 0) {
			WRITES(2, STRING("Please check your clock.\r\n"));
			return 1;
		}

		now = (size_t)tmp;
	}

	if (add_user(SID, SID, HAXSERV_UID, HAXSERV_NICK, HAXSERV_FULLNAME, HAXSERV_IDENT, HAXSERV_VHOST, HAXSERV_HOST, HAXSERV_ADDRESS, now, now, 0, 0, 0, 1, HAXSERV_PSUEDOCLIENT) != 0)
		return 1;

	struct user_info *user = get_table_index(user_list, HAXSERV_UID);
	for (size_t i = 0; i < HAXSERV_NUM_PREJOIN_CHANNELS; i++) {
		if (set_channel(SID, HAXSERV_PREJOIN_CHANNELS[i], now, 1, &user) != 0)
			return 1;
	}

	haxserv_psuedoclient_commands.array = malloc(0);

	return 0;
}

int haxserv_psuedoclient_allow_kill(struct string from, struct string source, struct user_info *user, struct string reason) {
	return 0;
}

int haxserv_psuedoclient_allow_kick(struct string from, struct string source, struct channel_info *channel, struct user_info *user, struct string reason) {
	return 0;
}

void haxserv_psuedoclient_handle_privmsg(struct string from, struct string source, struct string target, struct string msg) {
	if (STRING_EQ(source, HAXSERV_UID))
		return;

	struct string respond_to;
	struct string prefix;

	size_t offset;
	if (!STRING_EQ(target, HAXSERV_UID)) { // Must be channel
		if (msg.len < HAXSERV_COMMAND_PREFIX.len || memcmp(msg.data, HAXSERV_COMMAND_PREFIX.data, HAXSERV_COMMAND_PREFIX.len) != 0)
			return;

		offset = HAXSERV_COMMAND_PREFIX.len;

		respond_to = target;
		prefix = HAXSERV_COMMAND_PREFIX;
	} else {
		offset = 0;

		respond_to = source;
		prefix = STRING("");
	}

	if (offset >= msg.len || msg.data[offset] == ' ')
		return;

	size_t argc = 0;
	size_t old_offset = offset;
	while (offset < msg.len) {
		while (offset < msg.len && msg.data[offset] != ' ')
			offset++;

		argc++;

		while (offset < msg.len && msg.data[offset] == ' ')
			offset++;
	}
	offset = old_offset;

	struct string argv[argc];
	size_t i = 0;
	while (offset < msg.len) {
		argv[i].data = &(msg.data[offset]);
		size_t start = offset;

		while (offset < msg.len && msg.data[offset] != ' ')
			offset++;

		argv[i].len = offset - start;

		while (offset < msg.len && msg.data[offset] == ' ')
			offset++;

		i++;
	}

	msg.data += prefix.len;
	msg.len -= prefix.len;
	struct command_def *cmd = get_table_index(haxserv_psuedoclient_commands, argv[0]);
	if (cmd) {
	} else {
		struct string msg_parts[] = {
			STRING("Unknown command: "),
			prefix,
			argv[0],
		};

		struct string full_msg;
		if (str_combine(&full_msg, 3, msg_parts) != 0)
			return;

		notice(SID, HAXSERV_UID, respond_to, full_msg);

		free(full_msg.data);
	}
}
