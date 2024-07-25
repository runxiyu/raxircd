// Actual "Main" file for HaxIRCd, just does the required setup
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

#include <signal.h>
#include <pthread.h>

#include "config.h"
#include "general_network.h"
#include "main.h"
#include "mutex.h"

#ifdef USE_PLAINTEXT_NETWORK
#include "networks/plaintext.h"
#endif
#ifdef USE_GNUTLS_NETWORK
#include "networks/gnutls.h"
#endif
#ifdef USE_OPENSSL_NETWORK
#include "networks/openssl.h"
#endif
#ifdef USE_PLAINTEXT_BUFFERED_NETWORK
#include "networks/plaintext_buffered.h"
#endif
#ifdef USE_GNUTLS_BUFFERED_NETWORK
#include "networks/gnutls_buffered.h"
#endif
#ifdef USE_OPENSSL_BUFFERED_NETWORK
#include "networks/openssl_buffered.h"
#endif

#ifdef USE_SERVER
#include "server_network.h"
#endif
#ifdef USE_CLIENT
#include "client_network.h"
#endif

#ifdef USE_PSEUDOCLIENTS
#include "pseudoclients.h"
#endif

#ifdef USE_HAXSERV_PSEUDOCLIENT
#include "pseudoclients/haxserv.h"
#endif

pthread_attr_t pthread_attr;

MUTEX_TYPE state_lock;

int real_main(void) {
	mutex_init(&state_lock);

	if (init_general_network() != 0)
		return 1;

#ifdef USE_PLAINTEXT_NETWORK
	if (init_plaintext_network() != 0) // there's not really anything to do ahead of time with plain tcp networking, this is just here for consistency
		return 1;
#endif

#ifdef USE_GNUTLS_NETWORK
	if (init_gnutls_network() != 0)
		return 1;
#endif

#ifdef USE_OPENSSL_NETWORK
	if (init_openssl_network() != 0)
		return 1;
#endif

#ifdef USE_PLAINTEXT_BUFFERED_NETWORK
	if (init_plaintext_buffered_network() != 0)
		return 1;
#endif

#ifdef USE_GNUTLS_BUFFERED_NETWORK
	if (init_gnutls_buffered_network() != 0)
		return 1;
#endif

#ifdef USE_OPENSSL_BUFFERED_NETWORK
	if (init_openssl_buffered_network() != 0)
		return 1;
#endif

#ifdef USE_SERVER
	if (init_server_network() != 0)
		return 1;
#endif

#ifdef USE_CLIENT
	if (init_client_network() != 0)
		return 1;
#endif

#ifdef USE_PSEUDOCLIENTS
	if (init_pseudoclients() != 0)
		return 1;
#endif

	{
		struct sigaction tmp = {
			.sa_handler = SIG_IGN,
		};
		sigaction(SIGPIPE, &tmp, 0);
	}

	if (pthread_attr_init(&pthread_attr) != 0)
		return 1;

	if (pthread_attr_setdetachstate(&pthread_attr, PTHREAD_CREATE_DETACHED) != 0) // shouldn't actually happen
		return 1;

#ifdef USE_CLIENT
	if (start_client_network() != 0)
		return 1;
#endif

#ifdef USE_SERVER
	if (start_server_network() != 0)
		return 1;
#endif

	pthread_exit(0);

	return 0;
}
