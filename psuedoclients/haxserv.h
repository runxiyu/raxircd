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
	struct string name;
};

int haxserv_psuedoclient_init(void);

int haxserv_psuedoclient_allow_kill(struct string from, struct string source, struct user_info *user, struct string reason);
int haxserv_psuedoclient_allow_kick(struct string from, struct string source, struct channel_info *channel, struct user_info *user, struct string reason);

void haxserv_psuedoclient_handle_privmsg(struct string from, struct string source, struct string target, struct string msg);

extern struct table haxserv_psuedoclient_commands;

extern struct command_def haxserv_psuedoclient_help_command_def;
extern struct command_def haxserv_psuedoclient_sus_command_def;
extern struct command_def haxserv_psuedoclient_cr_command_def;
extern struct command_def haxserv_psuedoclient_clear_command_def;
#ifdef USE_INSPIRCD2_PROTOCOL
extern struct command_def haxserv_psuedoclient_raw_inspircd2_command_def;
#endif
