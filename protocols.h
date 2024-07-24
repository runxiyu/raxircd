// s2s protocol interface
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

#include <stddef.h>

#include "haxstring.h"
#include "general_network.h"
#include "protocol_numbers.h"
#include "server_network.h"

struct protocol {
	int (*init)(void);
	void (*fail_init)(void);

	void * (*handle_connection)(void *info);
	void * (*autoconnect)(void *config);
	void (*update_propagations)(void);

	void (*propagate)(struct string from, struct string msg);

	void (*propagate_new_server)(struct string from, struct string attached_to, struct server_info *info);
	void (*propagate_remove_server)(struct string from, struct server_info *server, struct string reason);
	void (*propagate_unlink_server)(struct string from, struct server_info *a, struct server_info *b, size_t protocol);

	void (*propagate_new_user)(struct string from, struct user_info *info);
	void (*propagate_rename_user)(struct string from, struct user_info *info, struct string nick, size_t timestamp, struct string timestamp_str, char forced, char immediate);
	void (*propagate_remove_user)(struct string from, struct user_info *info, struct string reason);
	void (*propagate_kill_user)(struct string from, struct string source, struct user_info *info, struct string reason);
	void (*propagate_oper_user)(struct string from, struct user_info *info, struct string type, struct string reason);

	void (*propagate_set_account)(struct string from, struct user_info *info, struct string account, struct string source);
	void (*propagate_set_cert)(struct string from, struct user_info *info, struct string cert, struct string source);

	void (*propagate_set_channel)(struct string from, struct channel_info *channel, char is_new_channel, size_t user_count, struct user_info **users);
	void (*propagate_join_channel)(struct string from, struct channel_info *channel, size_t user_count, struct user_info **users);
	void (*propagate_part_channel)(struct string from, struct channel_info *channel, struct user_info *user, struct string reason);
	void (*propagate_kick_channel)(struct string from, struct string source, struct channel_info *channel, struct user_info *user, struct string reason);

	void (*propagate_privmsg)(struct string from, struct string source, struct string target, struct string msg);
	void (*propagate_notice)(struct string from, struct string source, struct string target, struct string msg);

	// Do whatever required with protocol-specific data here
	int (*handle_new_server)(struct string from, struct string attached_to, struct server_info *info);
	void (*handle_unlink_server)(struct string from, struct server_info *a, struct server_info *b, size_t protocol);

	int (*handle_new_user)(struct string from, struct user_info *info);
	int (*handle_rename_user)(struct string from, struct user_info *info, struct string nick, size_t timestamp, struct string timestamp_str, char forced, char immediate);
	void (*handle_remove_user)(struct string from, struct user_info *info, struct string reason, char propagate);
	void (*handle_kill_user)(struct string from, struct string source, struct user_info *info, struct string reason);
	int (*handle_oper_user)(struct string from, struct user_info *info, struct string type, struct string reason);

	int (*handle_set_account)(struct string from, struct user_info *info, struct string account, struct string source);
	int (*handle_set_cert)(struct string from, struct user_info *info, struct string cert, struct string source);

	int (*handle_set_channel)(struct string from, struct channel_info *channel, char is_new_channel, size_t user_count, struct user_info **users);
	int (*handle_join_channel)(struct string from, struct channel_info *channel, size_t user_count, struct user_info **users, char propagate);
	void (*handle_part_channel)(struct string from, struct channel_info *channel, struct user_info *user, struct string reason);
	void (*handle_kick_channel)(struct string from, struct string source, struct channel_info *channel, struct user_info *user, struct string reason);
	// ^^^^

	// If some other protocol failed above after ours ran, these get called to clean up
	void (*fail_new_server)(struct string from, struct string attached_to, struct server_info *info);

	void (*fail_new_user)(struct string from, struct user_info *info);
	void (*fail_rename_user)(struct string from, struct user_info *info, struct string nick, size_t timestamp, struct string timestamp_str, char forced, char immediate);
	void (*fail_oper_user)(struct string from, struct user_info *info, struct string type, struct string source);

	void (*fail_set_account)(struct string from, struct user_info *info, struct string account, struct string source);
	void (*fail_set_cert)(struct string from, struct user_info *info, struct string cert, struct string source);

	void (*fail_set_channel)(struct string from, struct channel_info *channel, char is_new_channel, size_t user_count, struct user_info **users);
	void (*fail_join_channel)(struct string from, struct channel_info *channel, size_t user_count, struct user_info **users, char propagate);
	// ^^^^

	void (*do_unlink)(struct string from, struct server_info *a, struct server_info *b);
};

int protocols_init(void);

void protocols_update_propagations(void);

void protocols_propagate_new_server(struct string from, struct string attached_to, struct server_info *info);
void protocols_propagate_remove_server(struct string from, struct server_info *server, struct string reason);
void protocols_propagate_unlink_server(struct string from, struct server_info *a, struct server_info *b, size_t protocol);

void protocols_propagate_new_user(struct string from, struct user_info *info);
void protocols_propagate_rename_user(struct string from, struct user_info *info, struct string nick, size_t timestamp, struct string timestamp_str, char forced, char immediate);
void protocols_propagate_remove_user(struct string from, struct user_info *info, struct string reason);
void protocols_propagate_kill_user(struct string from, struct string source, struct user_info *info, struct string reason);
void protocols_propagate_oper_user(struct string from, struct user_info *info, struct string type, struct string source);

void protocols_propagate_set_account(struct string from, struct user_info *info, struct string account, struct string source);
void protocols_propagate_set_cert(struct string from, struct user_info *info, struct string cert, struct string source);

void protocols_propagate_set_channel(struct string from, struct channel_info *channel, char is_new_channel, size_t user_count, struct user_info **users);
void protocols_propagate_join_channel(struct string from, struct channel_info *channel, size_t user_count, struct user_info **users, char propagate);
void protocols_propagate_part_channel(struct string from, struct channel_info *channel, struct user_info *user, struct string reason);
void protocols_propagate_kick_channel(struct string from, struct string source, struct channel_info *channel, struct user_info *user, struct string reason);

void protocols_propagate_privmsg(struct string from, struct string source, struct string target, struct string msg);
void protocols_propagate_notice(struct string from, struct string source, struct string target, struct string msg);

int protocols_handle_new_server(struct string from, struct string attached_to, struct server_info *info);
void protocols_handle_unlink_server(struct string from, struct server_info *a, struct server_info *b, size_t protocol);

int protocols_handle_new_user(struct string from, struct user_info *info);
int protocols_handle_rename_user(struct string from, struct user_info *info, struct string nick, size_t timestamp, struct string timestamp_str, char forced, char immediate);
void protocols_handle_remove_user(struct string from, struct user_info *info, struct string reason, char propagate);
void protocols_handle_kill_user(struct string from, struct string source, struct user_info *info, struct string reason);
int protocols_handle_oper_user(struct string from, struct user_info *info, struct string type, struct string source);

int protocols_handle_set_account(struct string from, struct user_info *info, struct string account, struct string source);
int protocols_handle_set_cert(struct string from, struct user_info *info, struct string cert, struct string source);

int protocols_handle_set_channel(struct string from, struct channel_info *channel, char is_new_channel, size_t user_count, struct user_info **users);
int protocols_handle_join_channel(struct string from, struct channel_info *channel, size_t user_count, struct user_info **users, char propagate);
void protocols_handle_part_channel(struct string from, struct channel_info *channel, struct user_info *user, struct string reason);
void protocols_handle_kick_channel(struct string from, struct string source, struct channel_info *channel, struct user_info *user, struct string reason);

void protocols_fail_new_server(struct string from, struct string attached_to, struct server_info *info);

void protocols_fail_new_user(struct string from, struct user_info *info);
void protocols_fail_rename_user(struct string from, struct user_info *info, struct string nick, size_t timestamp, struct string timestamp_str, char forced, char immediate);
void protocols_fail_oper_user(struct string from, struct user_info *info, struct string type, struct string source);

void protocols_fail_set_account(struct string from, struct user_info *info, struct string account, struct string source);
void protocols_fail_set_cert(struct string from, struct user_info *info, struct string cert, struct string source);

void protocols_fail_set_channel(struct string from, struct channel_info *channel, char is_new_channel, size_t user_count, struct user_info **users);
void protocols_fail_join_channel(struct string from, struct channel_info *channel, size_t user_count, struct user_info **users, char propagate);

extern struct protocol protocols[NUM_PROTOCOLS];
extern char active_protocols[NUM_PROTOCOLS];
