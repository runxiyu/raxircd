// InspIRCd v4 / InspIRCd 1206 protocol support
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

#include "../config.h"
#include "../haxstring.h"
#include "../general_network.h"
#include "../table.h"

struct inspircd4_protocol_specific_user {
	struct table memberships;
};

struct inspircd4_protocol_member_id {
	struct string id_str;
	size_t id;
};

extern struct table inspircd4_protocol_init_commands;
extern struct table inspircd4_protocol_commands;

int init_inspircd4_protocol(void);
void init_inspircd4_protocol_fail(void);

void * inspircd4_protocol_connection(void *type);
void * inspircd4_protocol_autoconnect(void *type);
void inspircd4_protocol_update_propagations(void);

void inspircd4_protocol_propagate(struct string from, struct string msg);

void inspircd4_protocol_propagate_new_server(struct string from, struct string attached_to, struct server_info *info);
void inspircd4_protocol_propagate_unlink_server(struct string from, struct server_info *a, struct server_info *b, size_t protocol);

void inspircd4_protocol_propagate_new_user(struct string from, struct user_info *info);
void inspircd4_protocol_propagate_rename_user(struct string from, struct user_info *info, struct string nick, size_t timestamp, struct string timestamp_str, char forced, char immediate);
void inspircd4_protocol_propagate_remove_user(struct string from, struct user_info *info, struct string reason);
void inspircd4_protocol_propagate_kill_user(struct string from, struct string source, struct user_info *info, struct string reason);
void inspircd4_protocol_propagate_oper_user(struct string from, struct user_info *user, struct string type, struct string source);

void inspircd4_protocol_propagate_set_account(struct string from, struct user_info *user, struct string account, struct string source);
void inspircd4_protocol_propagate_set_cert(struct string from, struct user_info *user, struct string cert, struct string source);

void inspircd4_protocol_propagate_set_channel(struct string from, struct channel_info *channel, char is_new_channel, size_t user_count, struct user_info **users);
void inspircd4_protocol_propagate_join_channel(struct string from, struct channel_info *channel, size_t user_count, struct user_info **users);
void inspircd4_protocol_propagate_part_channel(struct string from, struct channel_info *channel, struct user_info *user, struct string reason);
void inspircd4_protocol_propagate_kick_channel(struct string from, struct string source, struct channel_info *channel, struct user_info *user, struct string reason);

void inspircd4_protocol_propagate_privmsg(struct string from, struct string source, struct string target, struct string msg);
void inspircd4_protocol_propagate_notice(struct string from, struct string source, struct string target, struct string msg);

int inspircd4_protocol_handle_new_server(struct string from, struct string attached_to, struct server_info *info);
void inspircd4_protocol_handle_unlink_server(struct string from, struct server_info *a, struct server_info *b, size_t protocol);

int inspircd4_protocol_handle_new_user(struct string from, struct user_info *info);
int inspircd4_protocol_handle_rename_user(struct string from, struct user_info *info, struct string nick, size_t timestamp, struct string timestamp_str, char forced, char immediate);
void inspircd4_protocol_handle_remove_user(struct string from, struct user_info *info, struct string reason, char propagate);
void inspircd4_protocol_handle_kill_user(struct string from, struct string source, struct user_info *info, struct string reason);
int inspircd4_protocol_handle_oper_user(struct string from, struct user_info *info, struct string type, struct string source);

int inspircd4_protocol_handle_set_account(struct string from, struct user_info *user, struct string account, struct string source);
int inspircd4_protocol_handle_set_cert(struct string from, struct user_info *user, struct string cert, struct string source);

int inspircd4_protocol_handle_set_channel(struct string from, struct channel_info *channel, char is_new_channel, size_t user_count, struct user_info **users);
int inspircd4_protocol_handle_join_channel(struct string from, struct channel_info *channel, size_t user_count, struct user_info **users, char propagate);
void inspircd4_protocol_handle_part_channel(struct string from, struct channel_info *channel, struct user_info *user, struct string reason);
void inspircd4_protocol_handle_kick_channel(struct string from, struct string source, struct channel_info *channel, struct user_info *user, struct string reason);

void inspircd4_protocol_fail_new_server(struct string from, struct string attached_to, struct server_info *info);

void inspircd4_protocol_fail_new_user(struct string from, struct user_info *info);
void inspircd4_protocol_fail_rename_user(struct string from, struct user_info *info, struct string nick, size_t timestamp, struct string timestamp_str, char forced, char immediate);
void inspircd4_protocol_fail_oper_user(struct string from, struct user_info *info, struct string type, struct string source);

void inspircd4_protocol_fail_set_account(struct string from, struct user_info *user, struct string account, struct string source);
void inspircd4_protocol_fail_set_cert(struct string from, struct user_info *user, struct string cert, struct string source);

void inspircd4_protocol_fail_set_channel(struct string from, struct channel_info *channel, char is_new_channel, size_t user_count, struct user_info **users);
void inspircd4_protocol_fail_join_channel(struct string from, struct channel_info *channel, size_t user_count, struct user_info **users, char propagate);

void inspircd4_protocol_do_unlink(struct string from, struct server_info *a, struct server_info *b);

void inspircd4_protocol_update_propagations_inner(struct server_info *source);

void inspircd4_protocol_do_unlink_inner(struct string from, struct server_info *source, struct string reason);

int inspircd4_protocol_init_handle_server(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config **config, char is_incoming);
int inspircd4_protocol_init_handle_capab(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config **config, char is_incoming);

int inspircd4_protocol_handle_ping(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming);
int inspircd4_protocol_handle_pong(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming);

int inspircd4_protocol_handle_server(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming);
int inspircd4_protocol_handle_squit(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming);
int inspircd4_protocol_handle_rsquit(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming);

int inspircd4_protocol_handle_uid(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming);
int inspircd4_protocol_handle_nick(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming);
int inspircd4_protocol_handle_quit(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming);
int inspircd4_protocol_handle_kill(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming);
int inspircd4_protocol_handle_opertype(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming);

int inspircd4_protocol_handle_fjoin(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming);
int inspircd4_protocol_handle_ijoin(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming);
int inspircd4_protocol_handle_part(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming);
int inspircd4_protocol_handle_kick(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming);

int inspircd4_protocol_handle_squery(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming);
int inspircd4_protocol_handle_privmsg(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming);
int inspircd4_protocol_handle_notice(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming);

int inspircd4_protocol_handle_mode(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming);
int inspircd4_protocol_handle_fmode(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming);

int inspircd4_protocol_handle_metadata(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming);

extern char inspircd4_protocol_user_mode_types[UCHAR_MAX+1];
extern char inspircd4_protocol_channel_mode_types[UCHAR_MAX+1];
