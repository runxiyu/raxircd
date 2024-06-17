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

#include "protocols.h"

#ifdef USE_INSPIRCD2_PROTOCOL
#include "protocols/inspircd2.h"
#endif
#ifdef USE_INSPIRCD3_PROTOCOL
#include "protocols/inspircd3.h"
#endif

struct protocol protocols[NUM_PROTOCOLS] = {
#ifdef USE_INSPIRCD2_PROTOCOL
	[INSPIRCD2_PROTOCOL] = {
		.init = init_inspircd2_protocol,
		.fail_init = init_inspircd2_protocol_fail,

		.handle_connection = inspircd2_protocol_connection,
		.autoconnect = inspircd2_protocol_autoconnect,
		.update_propagations = inspircd2_protocol_update_propagations,

		.propagate = inspircd2_protocol_propagate,

		.propagate_new_server = inspircd2_protocol_propagate_new_server,
		.propagate_unlink_server = inspircd2_protocol_propagate_unlink_server,

		.propagate_new_user = inspircd2_protocol_propagate_new_user,
		.propagate_rename_user = inspircd2_protocol_propagate_rename_user,
		.propagate_remove_user = inspircd2_protocol_propagate_remove_user,
		.propagate_kill_user = inspircd2_protocol_propagate_kill_user,
		.propagate_oper_user = inspircd2_protocol_propagate_oper_user,

		.propagate_set_channel = inspircd2_protocol_propagate_set_channel,
		.propagate_join_channel = inspircd2_protocol_propagate_join_channel,
		.propagate_part_channel = inspircd2_protocol_propagate_part_channel,
		.propagate_kick_channel = inspircd2_protocol_propagate_kick_channel,

		.propagate_privmsg = inspircd2_protocol_propagate_privmsg,
		.propagate_notice = inspircd2_protocol_propagate_notice,

		.handle_new_server = inspircd2_protocol_handle_new_server,
		.handle_unlink_server = inspircd2_protocol_handle_unlink_server,

		.handle_new_user = inspircd2_protocol_handle_new_user,
		.handle_rename_user = inspircd2_protocol_handle_rename_user,
		.handle_remove_user = inspircd2_protocol_handle_remove_user,
		.handle_kill_user = inspircd2_protocol_handle_kill_user,
		.handle_oper_user = inspircd2_protocol_handle_oper_user,

		.handle_set_channel = inspircd2_protocol_handle_set_channel,
		.handle_join_channel = inspircd2_protocol_handle_join_channel,
		.handle_part_channel = inspircd2_protocol_handle_part_channel,
		.handle_kick_channel = inspircd2_protocol_handle_kick_channel,

		.fail_new_server = inspircd2_protocol_fail_new_server,

		.fail_new_user = inspircd2_protocol_fail_new_user,
		.fail_rename_user = inspircd2_protocol_fail_rename_user,
		.fail_oper_user = inspircd2_protocol_fail_oper_user,

		.fail_set_channel = inspircd2_protocol_fail_set_channel,
		.fail_join_channel = inspircd2_protocol_fail_join_channel,

		.do_unlink = inspircd2_protocol_do_unlink,
	},
#endif
#ifdef USE_INSPIRCD3_PROTOCOL
	[INSPIRCD3_PROTOCOL] = {
		.init = init_inspircd3_protocol,
		.fail_init = init_inspircd3_protocol_fail,

		.handle_connection = inspircd3_protocol_connection,
		.autoconnect = inspircd3_protocol_autoconnect,
		.update_propagations = inspircd3_protocol_update_propagations,

		.propagate = inspircd3_protocol_propagate,

		.propagate_new_server = inspircd3_protocol_propagate_new_server,
		.propagate_unlink_server = inspircd3_protocol_propagate_unlink_server,

		.propagate_new_user = inspircd3_protocol_propagate_new_user,
		.propagate_rename_user = inspircd3_protocol_propagate_rename_user,
		.propagate_remove_user = inspircd3_protocol_propagate_remove_user,
		.propagate_kill_user = inspircd3_protocol_propagate_kill_user,
		.propagate_oper_user = inspircd3_protocol_propagate_oper_user,

		.propagate_set_channel = inspircd3_protocol_propagate_set_channel,
		.propagate_join_channel = inspircd3_protocol_propagate_join_channel,
		.propagate_part_channel = inspircd3_protocol_propagate_part_channel,
		.propagate_kick_channel = inspircd3_protocol_propagate_kick_channel,

		.propagate_privmsg = inspircd3_protocol_propagate_privmsg,
		.propagate_notice = inspircd3_protocol_propagate_notice,

		.handle_new_server = inspircd3_protocol_handle_new_server,
		.handle_unlink_server = inspircd3_protocol_handle_unlink_server,

		.handle_new_user = inspircd3_protocol_handle_new_user,
		.handle_rename_user = inspircd3_protocol_handle_rename_user,
		.handle_remove_user = inspircd3_protocol_handle_remove_user,
		.handle_kill_user = inspircd3_protocol_handle_kill_user,
		.handle_oper_user = inspircd3_protocol_handle_oper_user,

		.handle_set_channel = inspircd3_protocol_handle_set_channel,
		.handle_join_channel = inspircd3_protocol_handle_join_channel,
		.handle_part_channel = inspircd3_protocol_handle_part_channel,
		.handle_kick_channel = inspircd3_protocol_handle_kick_channel,

		.fail_new_server = inspircd3_protocol_fail_new_server,

		.fail_new_user = inspircd3_protocol_fail_new_user,
		.fail_rename_user = inspircd3_protocol_fail_rename_user,
		.fail_oper_user = inspircd3_protocol_fail_oper_user,

		.fail_set_channel = inspircd3_protocol_fail_set_channel,
		.fail_join_channel = inspircd3_protocol_fail_join_channel,

		.do_unlink = inspircd3_protocol_do_unlink,
	},
#endif
};

char active_protocols[NUM_PROTOCOLS] = {
#ifdef USE_INSPIRCD2_PROTOCOL
	[INSPIRCD2_PROTOCOL] = 1,
#endif
#ifdef USE_INSPIRCD3_PROTOCOL
	[INSPIRCD3_PROTOCOL] = 1,
#endif
};

int protocols_init(void) {
	size_t i;
	for (i = 0; i < NUM_PROTOCOLS; i++) {
		if (!active_protocols[i])
			continue;
		if (protocols[i].init() != 0)
			goto protocols_init_fail;
	}

	return 0;

	protocols_init_fail:
	while (i > 0) {
		i--;
		if (!active_protocols[i])
			continue;
		protocols[i].fail_init();
	}

	return 1;
}

void protocols_update_propagations(void) {
	for (size_t i = 0; i < NUM_PROTOCOLS; i++) {
		if (!active_protocols[i])
			continue;
		protocols[i].update_propagations();
	}
}

void protocols_propagate_new_server(struct string from, struct string attached_to, struct server_info *info) {
	for (size_t i = 0; i < NUM_PROTOCOLS; i++) {
		if (!active_protocols[i])
			continue;
		protocols[i].propagate_new_server(from, attached_to, info);
	}
}
void protocols_propagate_unlink_server(struct string from, struct server_info *a, struct server_info *b, size_t protocol) {
	for (size_t i = 0; i < NUM_PROTOCOLS; i++) {
		if (!active_protocols[i])
			continue;
		protocols[i].propagate_unlink_server(from, a, b, protocol);
	}
}

void protocols_propagate_new_user(struct string from, struct user_info *info) {
	for (size_t i = 0; i < NUM_PROTOCOLS; i++) {
		if (!active_protocols[i])
			continue;
		protocols[i].propagate_new_user(from, info);
	}
}

void protocols_propagate_rename_user(struct string from, struct user_info *info, struct string nick, size_t timestamp, struct string timestamp_str) {
	for (size_t i = 0; i < NUM_PROTOCOLS; i++) {
		if (!active_protocols[i])
			continue;
		protocols[i].propagate_rename_user(from, info, nick, timestamp, timestamp_str);
	}
}

void protocols_propagate_remove_user(struct string from, struct user_info *info, struct string reason) {
	for (size_t i = 0; i < NUM_PROTOCOLS; i++) {
		if (!active_protocols[i])
			continue;
		protocols[i].propagate_remove_user(from, info, reason);
	}
}

void protocols_propagate_kill_user(struct string from, struct string source, struct user_info *info, struct string reason) {
	for (size_t i = 0; i < NUM_PROTOCOLS; i++) {
		if (!active_protocols[i])
			continue;
		protocols[i].propagate_kill_user(from, source, info, reason);
	}
}

void protocols_propagate_oper_user(struct string from, struct user_info *info, struct string type) {
	for (size_t i = 0; i < NUM_PROTOCOLS; i++) {
		if (!active_protocols[i])
			continue;
		protocols[i].propagate_oper_user(from, info, type);
	}
}

void protocols_propagate_set_channel(struct string from, struct channel_info *channel, char is_new_channel, size_t user_count, struct user_info **users) {
	for (size_t i = 0; i < NUM_PROTOCOLS; i++) {
		if (!active_protocols[i])
			continue;
		protocols[i].propagate_set_channel(from, channel, is_new_channel, user_count, users);
	}
}

void protocols_propagate_join_channel(struct string from, struct channel_info *channel, size_t user_count, struct user_info **users, char propagate) {
	for (size_t i = 0; i < NUM_PROTOCOLS; i++) {
		if (!active_protocols[i])
			continue;
		protocols[i].propagate_join_channel(from, channel, user_count, users);
	}
}

void protocols_propagate_part_channel(struct string from, struct channel_info *channel, struct user_info *user, struct string reason) {
	for (size_t i = 0; i < NUM_PROTOCOLS; i++) {
		if (!active_protocols[i])
			continue;
		protocols[i].propagate_part_channel(from, channel, user, reason);
	}
}

void protocols_propagate_kick_channel(struct string from, struct string source, struct channel_info *channel, struct user_info *user, struct string reason) {
	for (size_t i = 0; i < NUM_PROTOCOLS; i++) {
		if (!active_protocols[i])
			continue;
		protocols[i].propagate_kick_channel(from, source, channel, user, reason);
	}
}

void protocols_propagate_privmsg(struct string from, struct string source, struct string target, struct string msg) {
	for (size_t i = 0; i < NUM_PROTOCOLS; i++) {
		if (!active_protocols[i])
			continue;
		protocols[i].propagate_privmsg(from, source, target, msg);
	}
}

void protocols_propagate_notice(struct string from, struct string source, struct string target, struct string msg) {
	for (size_t i = 0; i < NUM_PROTOCOLS; i++) {
		if (!active_protocols[i])
			continue;
		protocols[i].propagate_notice(from, source, target, msg);
	}
}

int protocols_handle_new_server(struct string from, struct string attached_to, struct server_info *info) {
	size_t i;
	for (i = 0; i < NUM_PROTOCOLS; i++) {
		if (!active_protocols[i])
			continue;
		if (protocols[i].handle_new_server(from, attached_to, info) != 0)
			goto protocols_handle_new_server_fail;
	}

	return 0;

	protocols_handle_new_server_fail:
	while (i > 0) {
		i--;
		if (!active_protocols[i])
			continue;
		protocols[i].fail_new_server(from, attached_to, info);
	}

	return 1;
}

void protocols_handle_unlink_server(struct string from, struct server_info *a, struct server_info *b, size_t protocol) {
	for (size_t i = 0; i < NUM_PROTOCOLS; i++) {
		if (!active_protocols[i])
			continue;
		protocols[i].handle_unlink_server(from, a, b, protocol);
	}
}

int protocols_handle_new_user(struct string from, struct user_info *info) {
	size_t i;
	for (i = 0; i < NUM_PROTOCOLS; i++) {
		if (!active_protocols[i])
			continue;
		if (protocols[i].handle_new_user(from, info) != 0)
			goto protocols_handle_new_user_fail;
	}

	return 0;

	protocols_handle_new_user_fail:
	while (i > 0) {
		i--;
		if (!active_protocols[i])
			continue;
		protocols[i].fail_new_user(from, info);
	}

	return 1;
}

int protocols_handle_rename_user(struct string from, struct user_info *info, struct string nick, size_t timestamp, struct string timestamp_str) {
	size_t i;
	for (i = 0; i < NUM_PROTOCOLS; i++) {
		if (!active_protocols[i])
			continue;
		if (protocols[i].handle_rename_user(from, info, nick, timestamp, timestamp_str) != 0)
			goto protocols_handle_rename_user_fail;
	}

	return 0;

	protocols_handle_rename_user_fail:
	while (i > 0) {
		i--;
		if (!active_protocols[i])
			continue;
		protocols[i].fail_rename_user(from, info, nick, timestamp, timestamp_str);
	}

	return 1;
}

void protocols_handle_remove_user(struct string from, struct user_info *info, struct string reason, char propagate) {
	for (size_t i = 0; i < NUM_PROTOCOLS; i++) {
		if (!active_protocols[i])
			continue;
		protocols[i].handle_remove_user(from, info, reason, propagate);
	}
}

void protocols_handle_kill_user(struct string from, struct string source, struct user_info *info, struct string reason) {
	for (size_t i = 0; i < NUM_PROTOCOLS; i++) {
		if (!active_protocols[i])
			continue;
		protocols[i].handle_kill_user(from, source, info, reason);
	}
}

int protocols_handle_oper_user(struct string from, struct user_info *info, struct string type) {
	size_t i;
	for (i = 0; i < NUM_PROTOCOLS; i++) {
		if (!active_protocols[i])
			continue;
		if (protocols[i].handle_oper_user(from, info, type) != 0)
			goto protocols_handle_oper_user_fail;
	}

	return 0;

	protocols_handle_oper_user_fail:
	while (i > 0) {
		i--;
		if (!active_protocols[i])
			continue;
		protocols[i].fail_oper_user(from, info, type);
	}

	return 1;
}

int protocols_handle_set_channel(struct string from, struct channel_info *channel, char is_new_channel, size_t user_count, struct user_info **users) {
	size_t i;
	for (i = 0; i < NUM_PROTOCOLS; i++) {
		if (!active_protocols[i])
			continue;
		if (protocols[i].handle_set_channel(from, channel, is_new_channel, user_count, users) != 0)
			goto protocols_handle_set_channel_fail;
	}

	return 0;

	protocols_handle_set_channel_fail:
	while (i > 0) {
		i--;
		if (!active_protocols[i])
			continue;
		protocols[i].fail_set_channel(from, channel, is_new_channel, user_count, users);
	}

	return 1;
}

int protocols_handle_join_channel(struct string from, struct channel_info *channel, size_t user_count, struct user_info **users, char propagate) {
	size_t i;
	for (i = 0; i < NUM_PROTOCOLS; i++) {
		if (!active_protocols[i])
			continue;
		if (protocols[i].handle_join_channel(from, channel, user_count, users, propagate) != 0)
			goto protocols_handle_join_channel_fail;
	}

	return 0;

	protocols_handle_join_channel_fail:
	while (i > 0) {
		i--;
		if (!active_protocols[i])
			continue;
		protocols[i].fail_join_channel(from, channel, user_count, users, propagate);
	}

	return 1;
}

void protocols_handle_part_channel(struct string from, struct channel_info *channel, struct user_info *user, struct string reason) {
	for (size_t i = 0; i < NUM_PROTOCOLS; i++) {
		if (!active_protocols[i])
			continue;
		protocols[i].handle_part_channel(from, channel, user, reason);
	}
}

void protocols_handle_kick_channel(struct string from, struct string source, struct channel_info *channel, struct user_info *user, struct string reason) {
	for (size_t i = 0; i < NUM_PROTOCOLS; i++) {
		if (!active_protocols[i])
			continue;
		protocols[i].handle_kick_channel(from, source, channel, user, reason);
	}
}

void protocols_fail_new_server(struct string from, struct string attached_to, struct server_info *info) {
	for (size_t i = 0; i < NUM_PROTOCOLS; i++) {
		if (!active_protocols[i])
			continue;
		protocols[i].fail_new_server(from, attached_to, info);
	}
}

void protocols_fail_new_user(struct string from, struct user_info *info) {
	for (size_t i = 0; i < NUM_PROTOCOLS; i++) {
		if (!active_protocols[i])
			continue;
		protocols[i].fail_new_user(from, info);
	}
}

void protocols_fail_rename_user(struct string from, struct user_info *info, struct string nick, size_t timestamp, struct string timestamp_str) {
	for (size_t i = 0; i < NUM_PROTOCOLS; i++) {
		if (!active_protocols[i])
			continue;
		protocols[i].fail_rename_user(from, info, nick, timestamp, timestamp_str);
	}
}

void protocols_fail_oper_user(struct string from, struct user_info *info, struct string type) {
	for (size_t i = 0; i < NUM_PROTOCOLS; i++) {
		if (!active_protocols[i])
			continue;
		protocols[i].fail_oper_user(from, info, type);
	}
}

void protocols_fail_set_channel(struct string from, struct channel_info *channel, char is_new_channel, size_t user_count, struct user_info **users) {
	for (size_t i = 0; i < NUM_PROTOCOLS; i++) {
		if (!active_protocols[i])
			continue;
		protocols[i].fail_set_channel(from, channel, is_new_channel, user_count, users);
	}
}

void protocols_fail_join_channel(struct string from, struct channel_info *channel, size_t user_count, struct user_info **users, char propagate) {
	for (size_t i = 0; i < NUM_PROTOCOLS; i++) {
		if (!active_protocols[i])
			continue;
		protocols[i].fail_join_channel(from, channel, user_count, users, propagate);
	}
}
