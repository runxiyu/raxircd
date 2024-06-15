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

		.do_unlink = inspircd2_protocol_do_unlink,
	},
#endif
#ifdef USE_INSPIRCD3_PROTOCOL
	[INSPIRCD3_PROTOCOL] = {
		.init = init_inspircd3_protocol,

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

		.do_unlink = inspircd3_protocol_do_unlink,
	},
#endif
};

int protocols_init(void) {
#ifdef USE_INSPIRCD2_PROTOCOL
	if (protocols[INSPIRCD2_PROTOCOL].init() != 0)
		return 1;
#endif
#ifdef USE_INSPIRCD3_PROTOCOL
	if (protocols[INSPIRCD3_PROTOCOL].init() != 0)
		return 1;
#endif

	return 0;
}

void protocols_update_propagations(void) {
#ifdef USE_INSPIRCD2_PROTOCOL
	protocols[INSPIRCD2_PROTOCOL].update_propagations();
#endif
#ifdef USE_INSPIRCD3_PROTOCOL
	protocols[INSPIRCD3_PROTOCOL].update_propagations();
#endif
}

void protocols_propagate_new_server(struct string from, struct string attached_to, struct server_info *info) {
#ifdef USE_INSPIRCD2_PROTOCOL
	protocols[INSPIRCD2_PROTOCOL].propagate_new_server(from, attached_to, info);
#endif
#ifdef USE_INSPIRCD3_PROTOCOL
	protocols[INSPIRCD3_PROTOCOL].propagate_new_server(from, attached_to, info);
#endif
}
void protocols_propagate_unlink_server(struct string from, struct server_info *a, struct server_info *b, size_t protocol) {
#ifdef USE_INSPIRCD2_PROTOCOL
	protocols[INSPIRCD2_PROTOCOL].propagate_unlink_server(from, a, b, protocol);
#endif
#ifdef USE_INSPIRCD3_PROTOCOL
	protocols[INSPIRCD3_PROTOCOL].propagate_unlink_server(from, a, b, protocol);
#endif
}

void protocols_propagate_new_user(struct string from, struct user_info *info) {
#ifdef USE_INSPIRCD2_PROTOCOL
	protocols[INSPIRCD2_PROTOCOL].propagate_new_user(from, info);
#endif
#ifdef USE_INSPIRCD3_PROTOCOL
	protocols[INSPIRCD3_PROTOCOL].propagate_new_user(from, info);
#endif
}

void protocols_propagate_rename_user(struct string from, struct user_info *info, struct string nick, size_t timestamp, struct string timestamp_str) {
#ifdef USE_INSPIRCD2_PROTOCOL
	protocols[INSPIRCD2_PROTOCOL].propagate_rename_user(from, info, nick, timestamp, timestamp_str);
#endif
#ifdef USE_INSPIRCD3_PROTOCOL
	protocols[INSPIRCD3_PROTOCOL].propagate_rename_user(from, info, nick, timestamp, timestamp_str);
#endif
}

void protocols_propagate_remove_user(struct string from, struct user_info *info, struct string reason) {
#ifdef USE_INSPIRCD2_PROTOCOL
	protocols[INSPIRCD2_PROTOCOL].propagate_remove_user(from, info, reason);
#endif
#ifdef USE_INSPIRCD3_PROTOCOL
	protocols[INSPIRCD3_PROTOCOL].propagate_remove_user(from, info, reason);
#endif
}

void protocols_propagate_kill_user(struct string from, struct string source, struct user_info *info, struct string reason) {
#ifdef USE_INSPIRCD2_PROTOCOL
	protocols[INSPIRCD2_PROTOCOL].propagate_kill_user(from, source, info, reason);
#endif
#ifdef USE_INSPIRCD3_PROTOCOL
	protocols[INSPIRCD3_PROTOCOL].propagate_kill_user(from, source, info, reason);
#endif
}

void protocols_propagate_oper_user(struct string from, struct user_info *info, struct string type) {
#ifdef USE_INSPIRCD2_PROTOCOL
	protocols[INSPIRCD2_PROTOCOL].propagate_oper_user(from, info, type);
#endif
#ifdef USE_INSPIRCD3_PROTOCOL
	protocols[INSPIRCD3_PROTOCOL].propagate_oper_user(from, info, type);
#endif
}

void protocols_propagate_set_channel(struct string from, struct channel_info *channel, char is_new_channel, size_t user_count, struct user_info **users) {
#ifdef USE_INSPIRCD2_PROTOCOL
	protocols[INSPIRCD2_PROTOCOL].propagate_set_channel(from, channel, is_new_channel, user_count, users);
#endif
#ifdef USE_INSPIRCD3_PROTOCOL
	protocols[INSPIRCD3_PROTOCOL].propagate_set_channel(from, channel, is_new_channel, user_count, users);
#endif
}

void protocols_propagate_join_channel(struct string from, struct channel_info *channel, size_t user_count, struct user_info **users) {
#ifdef USE_INSPIRCD2_PROTOCOL
	protocols[INSPIRCD2_PROTOCOL].propagate_join_channel(from, channel, user_count, users);
#endif
#ifdef USE_INSPIRCD3_PROTOCOL
	protocols[INSPIRCD3_PROTOCOL].propagate_join_channel(from, channel, user_count, users);
#endif
}

void protocols_propagate_part_channel(struct string from, struct channel_info *channel, struct user_info *user, struct string reason) {
#ifdef USE_INSPIRCD2_PROTOCOL
	protocols[INSPIRCD2_PROTOCOL].propagate_part_channel(from, channel, user, reason);
#endif
#ifdef USE_INSPIRCD3_PROTOCOL
	protocols[INSPIRCD3_PROTOCOL].propagate_part_channel(from, channel, user, reason);
#endif
}

void protocols_propagate_kick_channel(struct string from, struct string source, struct channel_info *channel, struct user_info *user, struct string reason) {
#ifdef USE_INSPIRCD2_PROTOCOL
	protocols[INSPIRCD2_PROTOCOL].propagate_kick_channel(from, source, channel, user, reason);
#endif
#ifdef USE_INSPIRCD3_PROTOCOL
	protocols[INSPIRCD3_PROTOCOL].propagate_kick_channel(from, source, channel, user, reason);
#endif
}

void protocols_propagate_privmsg(struct string from, struct string source, struct string target, struct string msg) {
#ifdef USE_INSPIRCD2_PROTOCOL
	protocols[INSPIRCD2_PROTOCOL].propagate_privmsg(from, source, target, msg);
#endif
#ifdef USE_INSPIRCD3_PROTOCOL
	protocols[INSPIRCD3_PROTOCOL].propagate_privmsg(from, source, target, msg);
#endif
}

void protocols_propagate_notice(struct string from, struct string source, struct string target, struct string msg) {
#ifdef USE_INSPIRCD2_PROTOCOL
	protocols[INSPIRCD2_PROTOCOL].propagate_notice(from, source, target, msg);
#endif
#ifdef USE_INSPIRCD3_PROTOCOL
	protocols[INSPIRCD3_PROTOCOL].propagate_notice(from, source, target, msg);
#endif
}
