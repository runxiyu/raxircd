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

#include "haxserv.h"

#ifdef USE_INSPIRCD2_PROTOCOL
#include "../protocols/inspircd2.h"
#endif

struct table haxserv_psuedoclient_commands = {0};
struct table haxserv_psuedoclient_prefixes = {0};

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

	if (set_table_index(&haxserv_psuedoclient_commands, STRING("HELP"), &haxserv_psuedoclient_help_command_def) != 0)
		return 1;
	if (set_table_index(&haxserv_psuedoclient_commands, STRING("SUS"), &haxserv_psuedoclient_sus_command_def) != 0)
		return 1;
	if (set_table_index(&haxserv_psuedoclient_commands, STRING("CR"), &haxserv_psuedoclient_cr_command_def) != 0)
		return 1;
	haxserv_psuedoclient_clear_command_def.privs = HAXSERV_REQUIRED_OPER_TYPE;
	if (set_table_index(&haxserv_psuedoclient_commands, STRING("CLEAR"), &haxserv_psuedoclient_clear_command_def) != 0)
		return 1;
#ifdef USE_INSPIRCD2_PROTOCOL
	haxserv_psuedoclient_raw_inspircd2_command_def.privs = HAXSERV_REQUIRED_OPER_TYPE;
	if (set_table_index(&haxserv_psuedoclient_prefixes, STRING(":"), &haxserv_psuedoclient_raw_inspircd2_command_def) != 0)
		return 1;
#endif

	return 0;
}

int haxserv_psuedoclient_allow_kill(struct string from, struct string source, struct user_info *user, struct string reason) {
	return 0;
}

int haxserv_psuedoclient_allow_kick(struct string from, struct string source, struct channel_info *channel, struct user_info *user, struct string reason) {
	return 0;
}

void haxserv_psuedoclient_handle_privmsg(struct string from, struct string source, struct string target, struct string msg) {
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

	struct command_def *cmd;

	struct string case_str = {.len = argv[0].len};
	case_str.data = malloc(case_str.len);
	if (case_str.data) {
		for (size_t i = 0; i < case_str.len; i++)
			case_str.data[i] = CASEMAP(argv[0].data[i]);

		cmd = get_table_index(haxserv_psuedoclient_commands, case_str);

		free(case_str.data);
	} else {
		cmd = get_table_index(haxserv_psuedoclient_commands, argv[0]);
	}

	if (!cmd) {
		case_str.len = msg.len;
		case_str.data = malloc(case_str.len);
		if (case_str.data) {
			for (size_t i = 0; i < case_str.len; i++)
				case_str.data[i] = CASEMAP(msg.data[i]);

			cmd = get_table_prefix(haxserv_psuedoclient_prefixes, case_str);

			free(case_str.data);
		} else {
			cmd = get_table_prefix(haxserv_psuedoclient_prefixes, msg);
		}
	}

	if (cmd) {
		if (cmd->privs.len != 0 && !(!has_table_index(user_list, source) && has_table_index(server_list, source))) {
			struct user_info *user = get_table_index(user_list, source);
			// TODO: Multiple privilege levels
			if (!STRING_EQ(user->oper_type, cmd->privs)) {
				notice(SID, HAXSERV_UID, respond_to, STRING("You are not authorized to execute this command."));
				return;
			}
		}

		cmd->func(from, source, msg, respond_to, argc - 1, &(argv[1]));
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

int haxserv_psuedoclient_help_command(struct string from, struct string sender, struct string original_message, struct string respond_to, size_t argc, struct string *argv) {
	for (size_t i = 0; i < haxserv_psuedoclient_commands.len; i++) {
		struct command_def *cmd = haxserv_psuedoclient_commands.array[i].ptr;

		struct string msg_parts[] = {
			HAXSERV_COMMAND_PREFIX,
			cmd->name,
			STRING("\x0F" " "),
			cmd->summary,
		};

		struct string full_msg;
		if (str_combine(&full_msg, 4, msg_parts) != 0) {
			notice(SID, HAXSERV_UID, respond_to, STRING("ERROR: Unable to create help message line."));
		} else {
			privmsg(SID, HAXSERV_UID, respond_to, full_msg);
			free(full_msg.data);
		}
	}

	return 0;
}
struct command_def haxserv_psuedoclient_help_command_def = {
	.func = haxserv_psuedoclient_help_command,
	.summary = STRING("Shows a list of commands."),
	.name = STRING("help"),
};

struct kill_or_msg {
	char type;
	struct string msg;
} haxserv_psuedoclient_sus_actions[] = {
	{0, STRING("DuckServ is very sus.")},
	{0, STRING("I was the impostor, but you only know because I killed you.")},
	{0, STRING("\\x1b(0")},
	{1, STRING("Ejected (1 Impostor remains)")},
	{1, STRING("Ejected, and the crewmates have won.")},
}, haxserv_psuedoclient_cr_actions[] = {
	{0, STRING("You are now a cruxian toxicpod, kill the sharded crewmates.")},
	{0, STRING("You are now a cruxian omura, kill the sharded crewmates.")},
	{0, STRING("You are now a cruxian oct, but you can out of reactors.")},
	{1, STRING("Eliminated (You became a cruxian eclipse, but were drawn to my bait reactor)")},
	{0, STRING("You attempted to change into a cruxian navanax, but were caught in the act.")},
};

int haxserv_psuedoclient_sus_command(struct string from, struct string sender, struct string original_message, struct string respond_to, size_t argc, struct string *argv) {
	size_t index = (size_t)random() % (sizeof(haxserv_psuedoclient_sus_actions) / sizeof(*haxserv_psuedoclient_sus_actions));

	if (haxserv_psuedoclient_sus_actions[index].type) {
		struct user_info *user = get_table_index(user_list, sender);
		if (!user)
			return 0;

		kill_user(SID, HAXSERV_UID, user, haxserv_psuedoclient_sus_actions[index].msg);
	} else {
		privmsg(SID, HAXSERV_UID, respond_to, haxserv_psuedoclient_sus_actions[index].msg);
	}

	return 0;
}
struct command_def haxserv_psuedoclient_sus_command_def = {
	.func = haxserv_psuedoclient_sus_command,
	.summary = STRING("You seem a bit sus today."),
	.name = STRING("sus"),
};

int haxserv_psuedoclient_cr_command(struct string from, struct string sender, struct string original_message, struct string respond_to, size_t argc, struct string *argv) {
	size_t index = (size_t)random() % (sizeof(haxserv_psuedoclient_cr_actions) / sizeof(*haxserv_psuedoclient_cr_actions));

	if (haxserv_psuedoclient_cr_actions[index].type) {
		struct user_info *user = get_table_index(user_list, sender);
		if (!user)
			return 0;

		kill_user(SID, HAXSERV_UID, user, haxserv_psuedoclient_cr_actions[index].msg);
	} else {
		privmsg(SID, HAXSERV_UID, respond_to, haxserv_psuedoclient_cr_actions[index].msg);
	}

	return 0;
}
struct command_def haxserv_psuedoclient_cr_command_def = {
	.func = haxserv_psuedoclient_cr_command,
	.summary = STRING("Join the crux side."),
	.name = STRING("cr"),
};

int haxserv_psuedoclient_clear_command(struct string from, struct string sender, struct string original_message, struct string respond_to, size_t argc, struct string *argv) {
	if (argc < 1) {
		notice(SID, HAXSERV_UID, respond_to, STRING("Missing args!"));
		return 0;
	}

	struct channel_info *channel = get_table_index(channel_list, argv[0]);
	if (!channel) {
		notice(SID, HAXSERV_UID, respond_to, STRING("That channel doesn't seem to exist, so is thereby already cleared."));
		return 0;
	}

	size_t i = 0;
	while (channel->user_list.len > i) {
		if (kick_channel(SID, HAXSERV_UID, channel, channel->user_list.array[i].ptr, STRING("(B")) != 0) {
			i++;
		}
	}

	return 0;
}
struct command_def haxserv_psuedoclient_clear_command_def = {
	.func = haxserv_psuedoclient_clear_command,
	.summary = STRING("Clears a channel."),
	.name = STRING("clear"),
};

#ifdef USE_INSPIRCD2_PROTOCOL
int haxserv_psuedoclient_raw_inspircd2_command(struct string from, struct string sender, struct string original_message, struct string respond_to, size_t argc, struct string *argv) {
	struct server_info *self = get_table_index(server_list, SID);

	inspircd2_protocol_propagate(SID, self, original_message);
	inspircd2_protocol_propagate(SID, self, STRING("\n"));

	return 0;
}
struct command_def haxserv_psuedoclient_raw_inspircd2_command_def = {
	.func = haxserv_psuedoclient_raw_inspircd2_command,
	.summary = STRING("Sends a raw message to all InspIRCd v2 links."),
	.name = STRING(":"),
};
#endif
