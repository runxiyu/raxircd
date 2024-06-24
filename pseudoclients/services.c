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

#include "../config.h"
#include "../haxstring.h"
#include "../general_network.h"
#include "../pseudoclients.h"
#include "services.h"

int services_pseudoclient_init(void) {
	return services_pseudoclient_post_reload();
}

int services_pseudoclient_post_reload(void) {
	size_t now;
	{
		time_t tmp = time(0);
		if (tmp < 0) {
			WRITES(2, STRING("Please check your clock.\r\n"));
			return 1;
		}

		now = (size_t)tmp;
	}

	if (!has_table_index(user_list, NICKSERV_UID)) {
		if (add_user(SID, SID, NICKSERV_UID, NICKSERV_NICK, NICKSERV_FULLNAME, NICKSERV_IDENT, NICKSERV_VHOST, NICKSERV_HOST, NICKSERV_ADDRESS, now, now, 0, 0, 0, 1, SERVICES_PSEUDOCLIENT) != 0)
			return 1;
		struct user_info *user = get_table_index(user_list, NICKSERV_UID);
		if (set_channel(SID, SERVICES_CHANNEL, now, 1, &user) != 0)
			return 1;
	}

	pseudoclients[SERVICES_PSEUDOCLIENT].init = services_pseudoclient_init;

	pseudoclients[SERVICES_PSEUDOCLIENT].post_reload = services_pseudoclient_post_reload;
	pseudoclients[SERVICES_PSEUDOCLIENT].pre_reload = services_pseudoclient_pre_reload;

	pseudoclients[SERVICES_PSEUDOCLIENT].allow_kill = services_pseudoclient_allow_kill;
	pseudoclients[SERVICES_PSEUDOCLIENT].allow_kick = services_pseudoclient_allow_kick;

	pseudoclients[SERVICES_PSEUDOCLIENT].handle_privmsg = services_pseudoclient_handle_privmsg;

	return 0;
}

int services_pseudoclient_pre_reload(void) {
	return 0;
}

int services_pseudoclient_allow_kill(struct string from, struct string source, struct user_info *user, struct string reason) {
	return 0;
}

int services_pseudoclient_allow_kick(struct string from, struct string source, struct channel_info *channel, struct user_info *user, struct string reason) {
	return 0;
}

void services_pseudoclient_handle_privmsg(struct string from, struct string source, struct string target, struct string msg) {
}
