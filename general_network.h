// Header for generic IRC behavior and general networking usage
//
// Written by: Test_User <hax@runxiyu.org>
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

#include <limits.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/time.h>

#include "hax_string.h"
#include "protocol_numbers.h"
#include "hax_table.h"

#ifdef ENONET
#define RETRY_ACCEPT (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK || errno == ENETDOWN || errno == EPROTO || errno == ENOPROTOOPT || errno == EHOSTDOWN || errno == ENONET || errno == EHOSTUNREACH || errno == EOPNOTSUPP || errno == ENETUNREACH)
#else
#define RETRY_ACCEPT (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK || errno == ENETDOWN || errno == EPROTO || errno == ENOPROTOOPT || errno == EHOSTDOWN || errno == EHOSTUNREACH || errno == EOPNOTSUPP || errno == ENETUNREACH)
#endif

struct network {
	int (*send)(void *handle, struct string msg);
	size_t (*recv)(void *handle, char *data, size_t len, char *err);

	int (*connect)(void **handle, struct string address, struct string port, struct string *addr_out);
	int (*accept)(int listen_fd, void **handle, struct string *addr);

	void (*shutdown)(void *handle);
	void (*close)(int fd, void *handle);
};

struct server_info {
	struct string sid;
	struct string name;
	struct string fullname;

	struct string next; // Self for self, else which server we should send a message to to get to this server

	struct table connected_to; // List of servers that this server is connected to

	struct table user_list;

	void *protocol_specific[NUM_PROTOCOLS];

	void *handle;

	size_t protocol;
	size_t net;

	size_t distance;

	struct timeval latency;
	struct timeval last_ping;
	char awaiting_pong;
	char latency_valid;
};

struct user_info {
	struct string uid;
	struct string nick;
	struct string fullname;

	struct string ident;

	struct string vhost;
	struct string host;
	struct string address;

	struct string user_ts_str;
	struct string nick_ts_str;
	size_t user_ts;
	size_t nick_ts;

	struct string oper_type;
	struct string account_name;

	struct string cert;
	char cert_ready;

	struct string server;

	struct table channel_list;

	void *protocol_specific[NUM_PROTOCOLS];

	void *handle;

	size_t protocol;
	size_t net;

	struct timeval latency;
	struct timeval last_ping;
	char awaiting_pong;
	char latency_ready;

	char is_pseudoclient;
	size_t pseudoclient;
};

struct channel_info {
	struct string name;

	struct string channel_ts_str;
	size_t channel_ts;

	struct table user_list;

	void *protocol_specific[NUM_PROTOCOLS];
};

int resolve(struct string address, struct string port, struct sockaddr *sockaddr, socklen_t *len, int *family);

int init_general_network(void);

int add_user(struct string from, struct string attached_to, struct string uid, struct string nick, struct string fullname, struct string ident, struct string vhost, struct string host, struct string address, size_t user_ts, size_t nick_ts, void *handle, size_t protocol, size_t net, char is_pseudoclient, size_t pseudoclient);
int rename_user(struct string from, struct user_info *user, struct string nick, size_t timestamp, char forced, char immediate);
void remove_user(struct string from, struct user_info *user, struct string reason, char propagate);
int kill_user(struct string from, struct string source, struct user_info *user, struct string reason);
int oper_user(struct string from, struct user_info *user, struct string type, struct string source);

int set_account(struct string from, struct user_info *user, struct string account, struct string source);
int set_cert(struct string from, struct user_info *user, struct string cert, struct string source);

int set_channel(struct string from, struct string name, size_t timestamp, size_t user_count, struct user_info **users);
int join_channel(struct string from, struct channel_info *channel, size_t user_count, struct user_info **users, char propagate);
void part_channel(struct string from, struct channel_info *channel, struct user_info *user, struct string reason, char propagate);
int kick_channel(struct string from, struct string source, struct channel_info *channel, struct user_info *user, struct string reason);

int privmsg(struct string from, struct string sender, struct string target, struct string msg);
int notice(struct string from, struct string sender, struct string target, struct string msg);

int do_trivial_reloads(void);

extern int case_string_eq(struct string x, struct string y);

extern char casemap[UCHAR_MAX+1];
#define CASEMAP(x) (casemap[(unsigned char)x])

#ifdef USE_PLAINTEXT_NETWORK
#define NET_TYPE_PLAINTEXT 0
#endif
#ifdef USE_GNUTLS_NETWORK
#define NET_TYPE_GNUTLS 1
#endif
#ifdef USE_OPENSSL_NETWORK
#define NET_TYPE_OPENSSL 2
#endif
#ifdef USE_PLAINTEXT_BUFFERED_NETWORK
#define NET_TYPE_PLAINTEXT_BUFFERED 3
#endif
#ifdef USE_GNUTLS_BUFFERED_NETWORK
#define NET_TYPE_GNUTLS_BUFFERED 4
#endif
#ifdef USE_OPENSSL_BUFFERED_NETWORK
#define NET_TYPE_OPENSSL_BUFFERED 5
#endif

#define NUM_NET_TYPES 6

#define MODE_TYPE_UNKNOWN 0
#define MODE_TYPE_NOARGS 1
#define MODE_TYPE_REPLACE 2
#define MODE_TYPE_MULTIPLE 3

// Channel modes only, goes away when the related user leaves
#define MODE_TYPE_USERS 4

// Used for e.g. snomasks
#define MODE_TYPE_MODE 5

extern struct network networks[NUM_NET_TYPES];

extern struct table server_list;
extern struct table user_list;
extern struct table channel_list;

extern struct server_info *self;
