// The HaxServ pseudoclient
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

#include <dlfcn.h>
#include <stddef.h>
#include <stdlib.h>
#include <time.h>

#include "../config.h"
#include "../haxstring.h"
#include "../haxstring_utils.h"
#include "../general_network.h"
#include "../pseudoclients.h"

#include "haxserv.h"

#ifdef USE_PROTOCOLS
#include "../protocols.h"
#endif

struct table haxserv_pseudoclient_commands = {0};
struct table haxserv_pseudoclient_prefixes = {0};

// TODO: Potentially leaky on failure
int haxserv_pseudoclient_init(void) {
	size_t now;
	{
		time_t tmp = time(0);
		if (tmp < 0) {
			WRITES(2, STRING("Please check your clock.\r\n"));
			return 1;
		}

		now = (size_t)tmp;
	}

	if (add_user(SID, SID, HAXSERV_UID, HAXSERV_NICK, HAXSERV_FULLNAME, HAXSERV_IDENT, HAXSERV_VHOST, HAXSERV_HOST, HAXSERV_ADDRESS, now, now, 0, 0, 0, 1, HAXSERV_PSEUDOCLIENT) != 0)
		return 1;
	if (oper_user(SID, get_table_index(user_list, HAXSERV_UID), HAXSERV_REQUIRED_OPER_TYPE, HAXSERV_UID) != 0)
		return 1;

	struct user_info *user = get_table_index(user_list, HAXSERV_UID);
	for (size_t i = 0; i < HAXSERV_NUM_PREJOIN_CHANNELS; i++) {
		if (set_channel(SID, HAXSERV_PREJOIN_CHANNELS[i], now, 1, &user) != 0)
			return 1;
	}

	return haxserv_pseudoclient_post_reload();
}

int haxserv_pseudoclient_post_reload(void) {
	haxserv_pseudoclient_commands.array = malloc(0);
	haxserv_pseudoclient_prefixes.array = malloc(0);

	if (set_table_index(&haxserv_pseudoclient_commands, STRING("HELP"), &haxserv_pseudoclient_help_command_def) != 0)
		return 1;
	if (set_table_index(&haxserv_pseudoclient_commands, STRING("SUS"), &haxserv_pseudoclient_sus_command_def) != 0)
		return 1;
	if (set_table_index(&haxserv_pseudoclient_commands, STRING("CR"), &haxserv_pseudoclient_cr_command_def) != 0)
		return 1;
	haxserv_pseudoclient_clear_command_def.privs = HAXSERV_REQUIRED_OPER_TYPE;
	if (set_table_index(&haxserv_pseudoclient_commands, STRING("CLEAR"), &haxserv_pseudoclient_clear_command_def) != 0)
		return 1;
#ifdef USE_INSPIRCD2_PROTOCOL
	haxserv_pseudoclient_raw_inspircd2_command_def.privs = HAXSERV_REQUIRED_OPER_TYPE;
	if (set_table_index(&haxserv_pseudoclient_commands, STRING(":"), &haxserv_pseudoclient_raw_inspircd2_command_def) != 0)
		return 1;
	if (set_table_index(&haxserv_pseudoclient_prefixes, STRING(":"), &haxserv_pseudoclient_raw_inspircd2_command_def) != 0)
		return 1;
#endif
	haxserv_pseudoclient_kill_command_def.privs = HAXSERV_REQUIRED_OPER_TYPE;
	if (set_table_index(&haxserv_pseudoclient_commands, STRING("KILL"), &haxserv_pseudoclient_kill_command_def) != 0)
		return 1;
	haxserv_pseudoclient_spam_command_def.privs = HAXSERV_REQUIRED_OPER_TYPE;
	if (set_table_index(&haxserv_pseudoclient_commands, STRING("SPAM"), &haxserv_pseudoclient_spam_command_def) != 0)
		return 1;
	haxserv_pseudoclient_reload_command_def.privs = HAXSERV_REQUIRED_OPER_TYPE;
	if (set_table_index(&haxserv_pseudoclient_commands, STRING("RELOAD"), &haxserv_pseudoclient_reload_command_def) != 0)
		return 1;
	haxserv_pseudoclient_allow_command_def.privs = HAXSERV_REQUIRED_OPER_TYPE;
	if (set_table_index(&haxserv_pseudoclient_commands, STRING("ALLOW"), &haxserv_pseudoclient_allow_command_def) != 0)
		return 1;
	haxserv_pseudoclient_deny_command_def.privs = HAXSERV_REQUIRED_OPER_TYPE;
	if (set_table_index(&haxserv_pseudoclient_commands, STRING("DENY"), &haxserv_pseudoclient_deny_command_def) != 0)
		return 1;
	haxserv_pseudoclient_reconnect_command_def.privs = HAXSERV_REQUIRED_OPER_TYPE;
	if (set_table_index(&haxserv_pseudoclient_commands, STRING("RECONNECT"), &haxserv_pseudoclient_reconnect_command_def) != 0)
		return 1;
//	haxserv_pseudoclient_sanick_command_def.privs = HAXSERV_REQUIRED_OPER_TYPE;
//	if (set_table_index(&haxserv_pseudoclient_commands, STRING("SANICK"), &haxserv_pseudoclient_sanick_command_def) != 0)
//		return 1;
	haxserv_pseudoclient_get_command_def.privs = HAXSERV_REQUIRED_OPER_TYPE;
	if (set_table_index(&haxserv_pseudoclient_commands, STRING("GET"), &haxserv_pseudoclient_get_command_def) != 0)
		return 1;

	pseudoclients[HAXSERV_PSEUDOCLIENT].init = haxserv_pseudoclient_init;

	pseudoclients[HAXSERV_PSEUDOCLIENT].post_reload = haxserv_pseudoclient_post_reload;
	pseudoclients[HAXSERV_PSEUDOCLIENT].pre_reload = haxserv_pseudoclient_pre_reload;

	pseudoclients[HAXSERV_PSEUDOCLIENT].allow_kill = haxserv_pseudoclient_allow_kill;
	pseudoclients[HAXSERV_PSEUDOCLIENT].allow_kick = haxserv_pseudoclient_allow_kick;

	pseudoclients[HAXSERV_PSEUDOCLIENT].handle_privmsg = haxserv_pseudoclient_handle_privmsg;
	pseudoclients[HAXSERV_PSEUDOCLIENT].handle_rename_user = haxserv_pseudoclient_handle_rename_user;
	pseudoclients[HAXSERV_PSEUDOCLIENT].handle_set_cert = haxserv_pseudoclient_handle_set_cert;
	pseudoclients[HAXSERV_PSEUDOCLIENT].handle_post_rename_user = haxserv_pseudoclient_handle_post_rename_user;

	return 0;
}

int haxserv_pseudoclient_pre_reload(void) {
	clear_table(&haxserv_pseudoclient_commands);
	clear_table(&haxserv_pseudoclient_prefixes);

	free(haxserv_pseudoclient_commands.array);
	free(haxserv_pseudoclient_prefixes.array);

	return 0;
}

int haxserv_pseudoclient_allow_kill(struct string from, struct string source, struct user_info *user, struct string reason) {
	return 0;
}

int haxserv_pseudoclient_allow_kick(struct string from, struct string source, struct channel_info *channel, struct user_info *user, struct string reason) {
	return 0;
}

void haxserv_pseudoclient_handle_privmsg(struct string from, struct string source, struct string target, struct string msg) {
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

		cmd = get_table_index(haxserv_pseudoclient_commands, case_str);

		free(case_str.data);
	} else {
		cmd = get_table_index(haxserv_pseudoclient_commands, argv[0]);
	}

	char trim;
	if (cmd) {
		trim = 1;
	} else {
		trim = 0;
		case_str.len = msg.len;
		case_str.data = malloc(case_str.len);
		if (case_str.data) {
			for (size_t i = 0; i < case_str.len; i++)
				case_str.data[i] = CASEMAP(msg.data[i]);

			cmd = get_table_prefix(haxserv_pseudoclient_prefixes, case_str);

			free(case_str.data);
		} else {
			cmd = get_table_prefix(haxserv_pseudoclient_prefixes, msg);
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

		{
			struct string log_msg_parts[] = {
				STRING("User `"),
				STRING(""),
				STRING("' executes `"),
				msg,
				STRING("'"),
			};

			if (trim) {
				msg.data += argv[0].len;
				msg.len -= argv[0].len;
				if (msg.len > 1) {
					msg.data++;
					msg.len--;
				}
			}

			struct user_info *user = get_table_index(user_list, source);
			if (user) {
				log_msg_parts[1] = user->nick;
			} else {
				log_msg_parts[0] = STRING("Unknown user executes `");
				log_msg_parts[2] = STRING("");
			}

			struct string log_msg;
			if (str_combine(&log_msg, sizeof(log_msg_parts)/sizeof(*log_msg_parts), log_msg_parts) != 0)
				return;
			privmsg(SID, HAXSERV_UID, HAXSERV_LOG_CHANNEL, log_msg);
			free(log_msg.data);
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

void haxserv_pseudoclient_handle_rename_user(struct string from, struct user_info *user, struct string nick, size_t timestamp, char forced, char immediate) {
	return;
}

void haxserv_pseudoclient_handle_set_cert(struct string from, struct user_info *user, struct string cert, struct string source) {
	return;
}

void haxserv_pseudoclient_handle_post_rename_user(struct string from, struct user_info *user, struct string nick, size_t old_timestamp, char forced, char immediate) {
	return;
}

int haxserv_pseudoclient_help_command(struct string from, struct string sender, struct string original_message, struct string respond_to, size_t argc, struct string *argv) {
	notice(SID, HAXSERV_UID, respond_to, STRING("Command list:"));
	for (size_t i = 0; i < haxserv_pseudoclient_commands.len; i++) {
		struct command_def *cmd = haxserv_pseudoclient_commands.array[i].ptr;

		struct string msg_parts[] = {
			STRING("        "),
			HAXSERV_COMMAND_PREFIX,
			cmd->aligned_name,
			STRING("\x0F"),
			cmd->summary,
		};

		struct string full_msg;
		if (str_combine(&full_msg, sizeof(msg_parts)/sizeof(*msg_parts), msg_parts) != 0) {
			notice(SID, HAXSERV_UID, respond_to, STRING("ERROR: Unable to create help message line."));
		} else {
			notice(SID, HAXSERV_UID, respond_to, full_msg);
			free(full_msg.data);
		}
	}

	notice(SID, HAXSERV_UID, respond_to, STRING("Prefix list:"));
	for (size_t i = 0; i < haxserv_pseudoclient_prefixes.len; i++) {
		struct command_def *cmd = haxserv_pseudoclient_prefixes.array[i].ptr;

		struct string msg_parts[] = {
			STRING("        "),
			HAXSERV_COMMAND_PREFIX,
			cmd->aligned_name,
			STRING("\x0F"),
			cmd->summary,
		};

		struct string full_msg;
		if (str_combine(&full_msg, sizeof(msg_parts)/sizeof(*msg_parts), msg_parts) != 0) {
			notice(SID, HAXSERV_UID, respond_to, STRING("ERROR: Unable to create help message line."));
		} else {
			notice(SID, HAXSERV_UID, respond_to, full_msg);
			free(full_msg.data);
		}
	}

	return 0;
}
struct command_def haxserv_pseudoclient_help_command_def = {
	.func = haxserv_pseudoclient_help_command,
	.summary = STRING("Shows a list of commands."),
	.aligned_name = STRING("help        "),
	.name = STRING("help"),
};

struct kill_or_msg {
	char type;
	struct string msg;
} haxserv_pseudoclient_sus_actions[] = {
	{0, STRING("DuckServ is very sus.")},
	{0, STRING("I was the impostor, but you only know because I killed you.")},
	{0, STRING("\\x1b(0")},
	{1, STRING("Ejected (1 Impostor remains)")},
	{1, STRING("Ejected, and the crewmates have won.")},
}, haxserv_pseudoclient_cr_actions[] = {
	{0, STRING("You are now a cruxian toxicpod, kill the sharded crewmates.")},
	{0, STRING("You are now a cruxian omura, kill the sharded crewmates.")},
	{0, STRING("You are now a cruxian oct, but you can out of reactors.")},
	{1, STRING("Eliminated (You became a cruxian eclipse, but were drawn to my bait reactor)")},
	{0, STRING("You attempted to change into a cruxian navanax, but were caught in the act.")},
};

int haxserv_pseudoclient_sus_command(struct string from, struct string sender, struct string original_message, struct string respond_to, size_t argc, struct string *argv) {
	size_t index = (size_t)random() % (sizeof(haxserv_pseudoclient_sus_actions) / sizeof(*haxserv_pseudoclient_sus_actions));

	if (haxserv_pseudoclient_sus_actions[index].type) {
		struct user_info *user = get_table_index(user_list, sender);
		if (!user)
			return 0;

		kill_user(SID, HAXSERV_UID, user, haxserv_pseudoclient_sus_actions[index].msg);
	} else {
		privmsg(SID, HAXSERV_UID, respond_to, haxserv_pseudoclient_sus_actions[index].msg);
	}

	return 0;
}
struct command_def haxserv_pseudoclient_sus_command_def = {
	.func = haxserv_pseudoclient_sus_command,
	.summary = STRING("You seem a bit sus today."),
	.aligned_name = STRING("sus         "),
	.name = STRING("sus"),
};

int haxserv_pseudoclient_cr_command(struct string from, struct string sender, struct string original_message, struct string respond_to, size_t argc, struct string *argv) {
	size_t index = (size_t)random() % (sizeof(haxserv_pseudoclient_cr_actions) / sizeof(*haxserv_pseudoclient_cr_actions));

	if (haxserv_pseudoclient_cr_actions[index].type) {
		struct user_info *user = get_table_index(user_list, sender);
		if (!user)
			return 0;

		kill_user(SID, HAXSERV_UID, user, haxserv_pseudoclient_cr_actions[index].msg);
	} else {
		privmsg(SID, HAXSERV_UID, respond_to, haxserv_pseudoclient_cr_actions[index].msg);
	}

	return 0;
}
struct command_def haxserv_pseudoclient_cr_command_def = {
	.func = haxserv_pseudoclient_cr_command,
	.summary = STRING("Join the crux side."),
	.aligned_name = STRING("cr          "),
	.name = STRING("cr"),
};

int haxserv_pseudoclient_clear_command(struct string from, struct string sender, struct string original_message, struct string respond_to, size_t argc, struct string *argv) {
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
struct command_def haxserv_pseudoclient_clear_command_def = {
	.func = haxserv_pseudoclient_clear_command,
	.summary = STRING("Clears a channel."),
	.aligned_name = STRING("clear       "),
	.name = STRING("clear"),
};

#ifdef USE_INSPIRCD2_PROTOCOL
int haxserv_pseudoclient_raw_inspircd2_command(struct string from, struct string sender, struct string original_message, struct string respond_to, size_t argc, struct string *argv) {
	protocols[INSPIRCD2_PROTOCOL].propagate(SID, original_message);
	protocols[INSPIRCD2_PROTOCOL].propagate(SID, STRING("\n"));

	return 0;
}
struct command_def haxserv_pseudoclient_raw_inspircd2_command_def = {
	.func = haxserv_pseudoclient_raw_inspircd2_command,
	.summary = STRING("Sends a raw message to all InspIRCd v2 links."),
	.aligned_name = STRING(":           "),
	.name = STRING(":"),
};
#endif

// TODO: Kill reason as an argument
int haxserv_pseudoclient_kill_command(struct string from, struct string sender, struct string original_message, struct string respond_to, size_t argc, struct string *argv) {
	if (argc < 1) {
		notice(SID, HAXSERV_UID, respond_to, STRING("Insufficient parameters."));
		return 0;
	}

	struct user_info *user = get_table_index(user_list, argv[0]);
	if (user) {
		kill_user(SID, HAXSERV_UID, user, STRING("Impostor removed."));
		return 0;
	}

	for (size_t i = 0; i < user_list.len; i++) {
		struct user_info *user = user_list.array[i].ptr;
		if (STRING_EQ(user->nick, argv[0])) {
			kill_user(SID, HAXSERV_UID, user_list.array[i].ptr, STRING("Impostor removed."));
			return 0;
		}
	}

	return 0;
}
struct command_def haxserv_pseudoclient_kill_command_def = {
	.func = haxserv_pseudoclient_kill_command,
	.summary = STRING("Kills a user."),
	.aligned_name = STRING("kill        "),
	.name = STRING("kill"),
};

int haxserv_pseudoclient_spam_command(struct string from, struct string sender, struct string original_message, struct string respond_to, size_t argc, struct string *argv) {
	if (argc < 2) {
		notice(SID, HAXSERV_UID, respond_to, STRING("Insufficient parameters."));
		return 0;
	}

	char err;
	size_t count = str_to_unsigned(argv[0], &err);
	if (err) {
		notice(SID, HAXSERV_UID, respond_to, STRING("Unknown number."));
		return 0;
	} else if (count > 1048576) {
		notice(SID, HAXSERV_UID, respond_to, STRING("Number exceeds the limit."));
		return 0;
	}

	size_t offset = (size_t)(argv[1].data - original_message.data);
	original_message.data += offset;
	original_message.len -= offset;

	struct command_def *cmd;

	struct string case_str = {.len = argv[1].len};
	case_str.data = malloc(case_str.len);
	if (case_str.data) {
		for (size_t i = 0; i < case_str.len; i++)
			case_str.data[i] = CASEMAP(argv[1].data[i]);

		cmd = get_table_index(haxserv_pseudoclient_commands, case_str);

		free(case_str.data);
	} else {
		cmd = get_table_index(haxserv_pseudoclient_commands, argv[1]);
	}

	if (cmd) {
		original_message.data += argv[1].len;
		original_message.len -= argv[1].len;
		if (original_message.len > 1) {
			original_message.data++;
			original_message.len--;
		}
	} else {
		case_str.len = original_message.len;
		case_str.data = malloc(case_str.len);
		if (case_str.data) {
			for (size_t i = 0; i < case_str.len; i++)
				case_str.data[i] = CASEMAP(original_message.data[i]);

			cmd = get_table_prefix(haxserv_pseudoclient_prefixes, case_str);

			free(case_str.data);
		} else {
			cmd = get_table_prefix(haxserv_pseudoclient_prefixes, original_message);
		}
	}

	if (cmd) {
		if (cmd->privs.len != 0 && !(!has_table_index(user_list, sender) && has_table_index(server_list, sender))) {
			struct user_info *user = get_table_index(user_list, sender);
			// TODO: Multiple privilege levels
			if (!STRING_EQ(user->oper_type, cmd->privs)) {
				notice(SID, HAXSERV_UID, respond_to, STRING("You are not authorized to execute this command."));
				return 0;
			}
		}

		if (cmd->func == haxserv_pseudoclient_spam_command) {
			notice(SID, HAXSERV_UID, respond_to, STRING("Spam recursion is not allowed. The limit is for your own sake, please do not violate it."));
			return 0;
		}

		for (size_t i = 0; i < count; i++)
			cmd->func(from, sender, original_message, respond_to, argc - 2, &(argv[2]));
	} else {
		struct string msg_parts[] = {
			STRING("Unknown command: "),
			argv[1],
		};

		struct string full_msg;
		if (str_combine(&full_msg, sizeof(msg_parts)/sizeof(*msg_parts), msg_parts) != 0)
			return 0;

		notice(SID, HAXSERV_UID, respond_to, full_msg);

		free(full_msg.data);
	}

	return 0;
}
struct command_def haxserv_pseudoclient_spam_command_def = {
	.func = haxserv_pseudoclient_spam_command,
	.summary = STRING("Repeats a command a specified amount of times."),
	.aligned_name = STRING("spam        "),
	.name = STRING("spam"),
};

int haxserv_pseudoclient_reload_command(struct string from, struct string sender, struct string original_message, struct string respond_to, size_t argc, struct string *argv) {
	reload_pseudoclients[HAXSERV_PSEUDOCLIENT] = 1;
#ifdef USE_SERVICES_PSEUDOCLIENT
	reload_pseudoclients[SERVICES_PSEUDOCLIENT] = 1;
#endif

	return 0;
}
struct command_def haxserv_pseudoclient_reload_command_def = {
	.func = haxserv_pseudoclient_reload_command,
	.summary = STRING("Reloads a module."),
	.aligned_name = STRING("reload      "),
	.name = STRING("reload"),
};

int haxserv_pseudoclient_allow_command(struct string from, struct string sender, struct string original_message, struct string respond_to, size_t argc, struct string *argv) {
	if (argc < 1) {
		notice(SID, HAXSERV_UID, respond_to, STRING("Insufficient parameters."));
		return 0;
	}

	struct user_info *user = get_table_index(user_list, argv[0]);
	if (!user) {
		char found = 0;
		for (size_t i = 0; i < user_list.len; i++) {
			user = user_list.array[i].ptr;
			if (STRING_EQ(user->nick, argv[0])) {
				found = 1;
				break;
			}
		}
		if (!found) {
			notice(SID, HAXSERV_UID, respond_to, STRING("This user doesn't exist, so is thereby already denied access."));
			return 0;
		}
	}

	if (oper_user(SID, user, HAXSERV_REQUIRED_OPER_TYPE, HAXSERV_UID) != 0) {
		notice(SID, HAXSERV_UID, respond_to, STRING("Failed to oper target."));
		return 0;
	}

	struct string msg_parts[] = {
		STRING("User `"),
		user->nick,
		STRING("' is now considered an oper."),
	};
	struct string msg;
	if (str_combine(&msg, sizeof(msg_parts)/sizeof(*msg_parts), msg_parts) == 0) {
		notice(SID, HAXSERV_UID, respond_to, msg);
	} else {
		notice(SID, HAXSERV_UID, respond_to, STRING("User is now considered an oper."));
	}

	return 0;
}
struct command_def haxserv_pseudoclient_allow_command_def = {
	.func = haxserv_pseudoclient_allow_command,
	.summary = STRING("Grants a user access to the extended command set."),
	.aligned_name = STRING("allow       "),
	.name = STRING("allow"),
};

int haxserv_pseudoclient_deny_command(struct string from, struct string sender, struct string original_message, struct string respond_to, size_t argc, struct string *argv) {
	if (argc < 1) {
		notice(SID, HAXSERV_UID, respond_to, STRING("Insufficient parameters."));
		return 0;
	}

	struct user_info *user = get_table_index(user_list, argv[0]);
	if (!user) {
		char found = 0;
		for (size_t i = 0; i < user_list.len; i++) {
			user = user_list.array[i].ptr;
			if (STRING_EQ(user->nick, argv[0])) {
				found = 1;
				break;
			}
		}
		if (!found)
			return 0;
	}

	if (oper_user(SID, user, STRING(""), HAXSERV_UID) != 0) {
		notice(SID, HAXSERV_UID, respond_to, STRING("Failed to deoper target."));
		return 0;
	}

	struct string msg_parts[] = {
		STRING("User `"),
		user->nick,
		STRING("' is no longer an oper."),
	};
	struct string msg;
	if (str_combine(&msg, sizeof(msg_parts)/sizeof(*msg_parts), msg_parts) == 0) {
		notice(SID, HAXSERV_UID, respond_to, msg);
	} else {
		notice(SID, HAXSERV_UID, respond_to, STRING("User is no longer an oper."));
	}

	return 0;
}
struct command_def haxserv_pseudoclient_deny_command_def = {
	.func = haxserv_pseudoclient_deny_command,
	.summary = STRING("Denies a user access to the extended command set."),
	.aligned_name = STRING("deny        "),
	.name = STRING("deny"),
};

int haxserv_pseudoclient_reconnect_command(struct string from, struct string sender, struct string original_message, struct string respond_to, size_t argc, struct string *argv) {
	for (size_t i = 0; i < self->connected_to.len; i++) {
		struct server_info *adjacent = self->connected_to.array[i].ptr;
		networks[adjacent->net].shutdown(adjacent->handle);
	}

	return 0;
}
struct command_def haxserv_pseudoclient_reconnect_command_def = {
	.func = haxserv_pseudoclient_reconnect_command,
	.summary = STRING("Resets all connections."),
	.aligned_name = STRING("reconnect   "),
	.name = STRING("reconnect"),
};

int haxserv_pseudoclient_sanick_command(struct string from, struct string sender, struct string original_message, struct string respond_to, size_t argc, struct string *argv) {
	// TODO: Implement this later

	return 0;
}
struct command_def haxserv_pseudoclient_sanick_command_def = {
	.func = haxserv_pseudoclient_sanick_command,
	.summary = STRING("Changes a user's nick, without violating protocols."),
	.aligned_name = STRING("sanick      "),
	.name = STRING("sanick"),
};

int haxserv_pseudoclient_get_command(struct string from, struct string sender, struct string original_message, struct string respond_to, size_t argc, struct string *argv) {
	if (argc < 1) {
		notice(SID, HAXSERV_UID, respond_to, STRING("Missing argument."));
		return 0;
	}

	if (STRING_EQ(argv[0], STRING("help"))) {
		notice(SID, HAXSERV_UID, respond_to, STRING("Valid parameters: [uid | nick | info]"));
	} else if (STRING_EQ(argv[0], STRING("uid"))) {
		if (argc < 2) {
			notice(SID, HAXSERV_UID, respond_to, STRING("Missing arguments."));
			return 0;
		}

		for (size_t i = 0; i < user_list.len; i++) {
			struct user_info *user = user_list.array[i].ptr;
			if (STRING_EQ(argv[1], user->nick)) {
				notice(SID, HAXSERV_UID, respond_to, user->uid);
				return 0;
			}
		}

		notice(SID, HAXSERV_UID, respond_to, STRING("User is unknown."));
	} else if (STRING_EQ(argv[0], STRING("nick"))) {
		if (argc < 2) {
			notice(SID, HAXSERV_UID, respond_to, STRING("Missing arguments."));
			return 0;
		}

		struct user_info *user = get_table_index(user_list, argv[1]);
		if (user) {
			notice(SID, HAXSERV_UID, respond_to, user->nick);
		} else {
			notice(SID, HAXSERV_UID, respond_to, STRING("User is unknown."));
		}
	} else if (STRING_EQ(argv[0], STRING("info")) || STRING_EQ(argv[0], STRING("l_info"))) {
		if (argc < 2) {
			notice(SID, HAXSERV_UID, respond_to, STRING("Missing arguments."));
			return 0;
		}

		struct user_info *user = get_table_index(user_list, argv[1]);
		if (!user) {
			char found = 0;
			for (size_t i = 0; i < user_list.len; i++) {
				user = user_list.array[i].ptr;
				if (STRING_EQ(argv[1], user->nick)) {
					found = 1;
					break;
				}
			}
			if (!found) {
				notice(SID, HAXSERV_UID, respond_to, STRING("User is unknown."));
				return 0;
			}
		}

		{
			struct string msg_parts[] = {
				STRING("UID:            "),
				user->uid,
			};

			struct string full_msg;
			if (str_combine(&full_msg, sizeof(msg_parts)/sizeof(*msg_parts), msg_parts) == 0) {
				notice(SID, HAXSERV_UID, respond_to, full_msg);
				free(full_msg.data);
			} else {
				notice(SID, HAXSERV_UID, respond_to, STRING("<Allocation failure>"));
			}
		}

		{
			struct string msg_parts[] = {
				STRING("Nick:           "),
				user->nick,
			};

			struct string full_msg;
			if (str_combine(&full_msg, sizeof(msg_parts)/sizeof(*msg_parts), msg_parts) == 0) {
				notice(SID, HAXSERV_UID, respond_to, full_msg);
				free(full_msg.data);
			} else {
				notice(SID, HAXSERV_UID, respond_to, STRING("<Allocation failure>"));
			}
		}

		{
			struct string msg_parts[] = {
				STRING("Fullname:       "),
				user->fullname,
			};

			struct string full_msg;
			if (str_combine(&full_msg, sizeof(msg_parts)/sizeof(*msg_parts), msg_parts) == 0) {
				notice(SID, HAXSERV_UID, respond_to, full_msg);
				free(full_msg.data);
			} else {
				notice(SID, HAXSERV_UID, respond_to, STRING("<Allocation failure>"));
			}
		}

		{
			struct string msg_parts[] = {
				STRING("Ident:          "),
				user->ident,
			};

			struct string full_msg;
			if (str_combine(&full_msg, sizeof(msg_parts)/sizeof(*msg_parts), msg_parts) == 0) {
				notice(SID, HAXSERV_UID, respond_to, full_msg);
				free(full_msg.data);
			} else {
				notice(SID, HAXSERV_UID, respond_to, STRING("<Allocation failure>"));
			}
		}

		{
			struct string msg_parts[] = {
				STRING("VHost:          "),
				user->vhost,
			};

			struct string full_msg;
			if (str_combine(&full_msg, sizeof(msg_parts)/sizeof(*msg_parts), msg_parts) == 0) {
				notice(SID, HAXSERV_UID, respond_to, full_msg);
				free(full_msg.data);
			} else {
				notice(SID, HAXSERV_UID, respond_to, STRING("<Allocation failure>"));
			}
		}

		if (STRING_EQ(argv[0], STRING("info"))) {
			struct string msg_parts[] = {
				STRING("Host:           "),
				user->host,
			};

			struct string full_msg;
			if (str_combine(&full_msg, sizeof(msg_parts)/sizeof(*msg_parts), msg_parts) == 0) {
				notice(SID, HAXSERV_UID, respond_to, full_msg);
				free(full_msg.data);
			} else {
				notice(SID, HAXSERV_UID, respond_to, STRING("<Allocation failure>"));
			}
		}

		if (STRING_EQ(argv[0], STRING("info"))) {
			struct string msg_parts[] = {
				STRING("Address:        "),
				user->address,
			};

			struct string full_msg;
			if (str_combine(&full_msg, sizeof(msg_parts)/sizeof(*msg_parts), msg_parts) == 0) {
				notice(SID, HAXSERV_UID, respond_to, full_msg);
				free(full_msg.data);
			} else {
				notice(SID, HAXSERV_UID, respond_to, STRING("<Allocation failure>"));
			}
		}

		{
			struct string msg_parts[] = {
				STRING("User timestamp: "),
				user->user_ts_str,
			};

			struct string full_msg;
			if (str_combine(&full_msg, sizeof(msg_parts)/sizeof(*msg_parts), msg_parts) == 0) {
				notice(SID, HAXSERV_UID, respond_to, full_msg);
				free(full_msg.data);
			} else {
				notice(SID, HAXSERV_UID, respond_to, STRING("<Allocation failure>"));
			}
		}

		{
			struct string msg_parts[] = {
				STRING("Nick timestamp: "),
				user->nick_ts_str,
			};

			struct string full_msg;
			if (str_combine(&full_msg, sizeof(msg_parts)/sizeof(*msg_parts), msg_parts) == 0) {
				notice(SID, HAXSERV_UID, respond_to, full_msg);
				free(full_msg.data);
			} else {
				notice(SID, HAXSERV_UID, respond_to, STRING("<Allocation failure>"));
			}
		}

		{
			struct string msg_parts[] = {
				STRING("Oper type:      "),
				user->oper_type,
			};

			struct string full_msg;
			if (str_combine(&full_msg, sizeof(msg_parts)/sizeof(*msg_parts), msg_parts) == 0) {
				notice(SID, HAXSERV_UID, respond_to, full_msg);
				free(full_msg.data);
			} else {
				notice(SID, HAXSERV_UID, respond_to, STRING("<Allocation failure>"));
			}
		}

		{
			struct string msg_parts[] = {
				STRING("Account name:   "),
				user->account_name,
			};

			struct string full_msg;
			if (str_combine(&full_msg, sizeof(msg_parts)/sizeof(*msg_parts), msg_parts) == 0) {
				notice(SID, HAXSERV_UID, respond_to, full_msg);
				free(full_msg.data);
			} else {
				notice(SID, HAXSERV_UID, respond_to, STRING("<Allocation failure>"));
			}
		}

		{
			struct string msg_parts[] = {
				STRING("TLS Cert:       "),
				user->cert,
			};

			struct string full_msg;
			if (str_combine(&full_msg, sizeof(msg_parts)/sizeof(*msg_parts), msg_parts) == 0) {
				notice(SID, HAXSERV_UID, respond_to, full_msg);
				free(full_msg.data);
			} else {
				notice(SID, HAXSERV_UID, respond_to, STRING("<Allocation failure>"));
			}
		}

		{
			struct string msg_parts[] = {
				STRING("Server:         "),
				user->server,
			};

			struct string full_msg;
			if (str_combine(&full_msg, sizeof(msg_parts)/sizeof(*msg_parts), msg_parts) == 0) {
				notice(SID, HAXSERV_UID, respond_to, full_msg);
				free(full_msg.data);
			} else {
				notice(SID, HAXSERV_UID, respond_to, STRING("<Allocation failure>"));
			}
		}
	}

	return 0;
}
struct command_def haxserv_pseudoclient_get_command_def = {
	.func = haxserv_pseudoclient_get_command,
	.summary = STRING("[uid | name | info | l_info] <target>"),
	.aligned_name = STRING("get         "),
	.name = STRING("get"),
};
