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

#pragma once

#include "../haxstring.h"
#include "../general_network.h"

struct command_def {
	int (*func)(struct string from, struct string sender, struct string original_message, struct string respond_to, size_t argc, struct string *argv);
	struct string privs;
	struct string summary;
	struct string aligned_name;
	struct string name;
};

int haxserv_pseudoclient_init(void);

int haxserv_pseudoclient_post_reload(void);
int haxserv_pseudoclient_pre_reload(void);

int haxserv_pseudoclient_allow_kill(struct string from, struct string source, struct user_info *user, struct string reason);
int haxserv_pseudoclient_allow_kick(struct string from, struct string source, struct channel_info *channel, struct user_info *user, struct string reason);

void haxserv_pseudoclient_handle_privmsg(struct string from, struct string source, struct string target, struct string msg);
void haxserv_pseudoclient_handle_rename_user(struct string from, struct user_info *user, struct string nick, size_t timestamp, char forced, char immediate);
void haxserv_pseudoclient_handle_set_cert(struct string from, struct user_info *user, struct string cert, struct string source);

void haxserv_pseudoclient_handle_post_rename_user(struct string from, struct user_info *user, struct string nick, size_t old_timestamp, char forced, char immediate);

extern struct table haxserv_pseudoclient_commands;

extern struct command_def haxserv_pseudoclient_help_command_def;
extern struct command_def haxserv_pseudoclient_sus_command_def;
extern struct command_def haxserv_pseudoclient_cr_command_def;
extern struct command_def haxserv_pseudoclient_clear_command_def;
#ifdef USE_INSPIRCD2_PROTOCOL
extern struct command_def haxserv_pseudoclient_raw_inspircd2_command_def;
#endif
#ifdef USE_INSPIRCD3_PROTOCOL
extern struct command_def haxserv_pseudoclient_raw_inspircd3_command_def;
#endif
extern struct command_def haxserv_pseudoclient_kill_command_def;
extern struct command_def haxserv_pseudoclient_spam_command_def;
extern struct command_def haxserv_pseudoclient_reload_command_def;
extern struct command_def haxserv_pseudoclient_allow_command_def;
extern struct command_def haxserv_pseudoclient_deny_command_def;
extern struct command_def haxserv_pseudoclient_reconnect_command_def;
extern struct command_def haxserv_pseudoclient_sanick_command_def;
extern struct command_def haxserv_pseudoclient_get_command_def;
