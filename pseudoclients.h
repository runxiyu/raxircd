// Pseudoclient interface
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

#include "hax_string.h"
#include "general_network.h"

struct pseudoclient {
	char active;

	void *dl_handle;

	int (*init)(void);

	int (*pre_reload)(void);
	int (*post_reload)(void);

	int (*allow_kill)(struct string from, struct string source, struct user_info *user, struct string reason);
	int (*allow_kick)(struct string from, struct string source, struct channel_info *channel, struct user_info *user, struct string reason);

	void (*handle_privmsg)(struct string from, struct string source, struct string target, struct string msg);

	void (*handle_rename_user)(struct string from, struct user_info *user, struct string nick, size_t timestamp, char forced, char immediate);

	void (*handle_set_cert)(struct string from, struct user_info *user, struct string cert, struct string source);

	void (*handle_post_rename_user)(struct string from, struct user_info *user, struct string nick, size_t timestamp, char forced, char immediate);
};

int init_pseudoclients(void);

#ifdef USE_HAXSERV_PSEUDOCLIENT
#define HAXSERV_PSEUDOCLIENT 0
#endif
#ifdef USE_SERVICES_PSEUDOCLIENT
#define SERVICES_PSEUDOCLIENT 1
#endif

#define NUM_PSEUDOCLIENTS 2

extern struct pseudoclient pseudoclients[NUM_PSEUDOCLIENTS];

extern char reload_pseudoclients[NUM_PSEUDOCLIENTS];

void pseudoclients_handle_privmsg(struct string from, struct string source, struct string target, struct string msg);
void pseudoclients_handle_rename_user(struct string from, struct user_info *user, struct string nick, size_t timestamp, char forced, char immediate);
void pseudoclients_handle_set_cert(struct string from, struct user_info *user, struct string cert, struct string source);

void pseudoclients_handle_post_rename_user(struct string from, struct user_info *user, struct string nick, size_t timestamp, char forced, char immediate);
