// One of the headers for HaxServ
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

#include <time.h>

#include "general_network.h"
#include "protocols.h"

// #define K * 1024LU
// #define M * (1024LU K)
// #define G * (1024LU M)

#ifdef USE_SERVER
struct server_config {
	struct string name; // = STRING("hax.example.org"),
	struct string sid; // = STRING("100"),

	struct string in_pass; // = STRING("blah blah blah"),
	struct string out_pass; // = STRING("some other thing"),

	size_t protocol; // = HAXIRCD_PROTOCOL,

	char autoconnect; // = 1;
	size_t autoconnect_type; // = NET_TYPE_GNUTLS,

	char ignore_remote_unlinks;
	char ignore_remote_kills;
	char ignore_local_kills;

	// autoconnect only
	struct string address; // = "haxnet.org",
	struct string port; // = "4321",
};
extern struct server_config SERVER_CONFIG[]; // = {{...}, ...};
extern size_t SERVER_CONFIG_LEN; // = sizeof(SERVER_CONFIG)/sizeof(*SERVER_CONFIG);
#endif

extern struct string SID; // = STRING("200");
extern struct string SERVER_NAME; // = STRING("me.example.org");
extern struct string SERVER_FULLNAME; // = STRING("My random server");

extern time_t PING_INTERVAL; // = 60;

#ifdef USE_GNUTLS
extern char GNUTLS_USE_SYSTEM_TRUST; // = 1;
extern char *GNUTLS_CERT_PATH; // = "/etc/keys/crt.pem", or 0
extern char *GNUTLS_KEY_PATH; // = "/etc/keys/key.pem", or 0
#endif

#ifdef USE_OPENSSL
extern char OPENSSL_USE_SYSTEM_TRUST; // = 1;
extern char *OPENSSL_CERT_PATH; // = "/etc/keys/crt.pem", or 0
extern char *OPENSSL_KEY_PATH; // = "/etc/keys/key.pem", or 0
#endif

#ifdef USE_PLAINTEXT_BUFFERED
extern size_t PLAINTEXT_BUFFERED_LEN; // = 1 M
#endif

#ifdef USE_GNUTLS_BUFFERED
extern size_t GNUTLS_BUFFERED_LEN; // = 1 M
#endif

#ifdef USE_OPENSSL_BUFFERED
extern size_t OPENSSL_BUFFERED_LEN; // = 1 M
#endif

#ifdef USE_SERVER
extern unsigned short SERVER_PORTS[NUM_NET_TYPES][NUM_PROTOCOLS]; // = {7000, ...};
extern size_t SERVER_LISTEN[NUM_NET_TYPES][NUM_PROTOCOLS]; // = {16, ...};
extern char SERVER_INCOMING[NUM_NET_TYPES][NUM_PROTOCOLS]; // = {1, ...};
#endif

#ifdef USE_HAXSERV_PSEUDOCLIENT
extern struct string HAXSERV_UID; // = STRING("200000000");
extern struct string HAXSERV_NICK; // = STRING("HaxServ");
extern struct string HAXSERV_FULLNAME; // = STRING("Hax Services");
extern struct string HAXSERV_IDENT; // = STRING("HaxServ");
extern struct string HAXSERV_VHOST; // = STRING("services/hax");
extern struct string HAXSERV_HOST; // = STRING("localhost");
extern struct string HAXSERV_ADDRESS; // = STRING("/dev/null");

extern struct string HAXSERV_PREJOIN_CHANNELS[]; // = {STRING("#services"), ...};
extern size_t HAXSERV_NUM_PREJOIN_CHANNELS; // = sizeof(HAXSERV_PREJOIN_CHANNELS) / sizeof(*HAXSERV_PREJOIN_CHANNELS);

extern struct string HAXSERV_COMMAND_PREFIX; // = STRING("HaxServ: ");

extern struct string HAXSERV_REQUIRED_OPER_TYPE; // = STRING("Admin");

extern struct string HAXSERV_LOG_CHANNEL; // = STRING("#services");
#endif

#ifdef USE_SERVICES_PSEUDOCLIENT
extern struct string NICKSERV_UID; // = STRING("200000001");
extern struct string NICKSERV_NICK; // = STRING("NickServ");
extern struct string NICKSERV_FULLNAME; // = STRING("Nickname Services");
extern struct string NICKSERV_IDENT; // = STRING("NickServ");
extern struct string NICKSERV_VHOST; // = STRING("services/NickServ");
extern struct string NICKSERV_HOST; // = STRING("localhost");
extern struct string NICKSERV_ADDRESS; // = STRING("/dev/null");

extern struct string SERVICES_CHANNEL; // = STRING("#services");

extern size_t SERVICES_DB_MAX_SIZE; // = 100 M;
#endif
