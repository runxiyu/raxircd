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

extern struct table inspircd2_protocol_init_commands;
extern struct table inspircd2_protocol_commands;

int init_inspircd2_protocol(void);

void * inspircd2_protocol_connection(void *type);
void * inspircd2_protocol_autoconnect(void *type);
void inspircd2_protocol_update_propagations(void);

void inspircd2_protocol_propagate(struct string from, struct string msg);

void inspircd2_protocol_propagate_new_server(struct string from, struct string attached_to, struct server_info *info);
void inspircd2_protocol_propagate_unlink_server(struct string from, struct server_info *a, struct server_info *b, size_t protocol);

void inspircd2_protocol_propagate_new_user(struct string from, struct user_info *info);
void inspircd2_protocol_propagate_rename_user(struct string from, struct user_info *info, struct string nick, size_t timestamp, struct string timestamp_str);
void inspircd2_protocol_propagate_remove_user(struct string from, struct user_info *info, struct string reason);
void inspircd2_protocol_propagate_kill_user(struct string from, struct string source, struct user_info *info, struct string reason);
void inspircd2_protocol_propagate_oper_user(struct string from, struct user_info *info, struct string type);

void inspircd2_protocol_propagate_set_channel(struct string from, struct channel_info *channel, char is_new_channel, size_t user_count, struct user_info **users);
void inspircd2_protocol_propagate_join_channel(struct string from, struct channel_info *channel, size_t user_count, struct user_info **users);
void inspircd2_protocol_propagate_part_channel(struct string from, struct channel_info *channel, struct user_info *user, struct string reason);
void inspircd2_protocol_propagate_kick_channel(struct string from, struct string source, struct channel_info *channel, struct user_info *user, struct string reason);

void inspircd2_protocol_propagate_privmsg(struct string from, struct string source, struct string target, struct string msg);
void inspircd2_protocol_propagate_notice(struct string from, struct string source, struct string target, struct string msg);

void inspircd2_protocol_do_unlink(struct string from, struct server_info *a, struct server_info *b);

void inspircd2_protocol_update_propagations_inner(struct server_info *source);

void inspircd2_protocol_do_unlink_inner(struct string from, struct server_info *source, struct string reason);

int inspircd2_protocol_init_handle_server(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config **config, char is_incoming);
int inspircd2_protocol_init_handle_capab(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config **config, char is_incoming);

int inspircd2_protocol_handle_ping(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming);
int inspircd2_protocol_handle_pong(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming);

int inspircd2_protocol_handle_server(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming);
int inspircd2_protocol_handle_squit(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming);
int inspircd2_protocol_handle_rsquit(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming);

int inspircd2_protocol_handle_uid(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming);
int inspircd2_protocol_handle_nick(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming);
int inspircd2_protocol_handle_quit(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming);
int inspircd2_protocol_handle_kill(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming);
int inspircd2_protocol_handle_opertype(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming);

int inspircd2_protocol_handle_fjoin(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming);
int inspircd2_protocol_handle_part(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming);
int inspircd2_protocol_handle_kick(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming);

int inspircd2_protocol_handle_privmsg(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming);
int inspircd2_protocol_handle_notice(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming);

int inspircd2_protocol_handle_dump(struct string source, size_t argc, struct string *argv, size_t net, void *handle, struct server_config *config, char is_incoming);

extern char inspircd2_protocol_user_mode_types[UCHAR_MAX+1];
extern char inspircd2_protocol_channel_mode_types[UCHAR_MAX+1];
