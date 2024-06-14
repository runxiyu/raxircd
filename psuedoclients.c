// One of the code files for HaxServ
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

#include "haxstring.h"
#include "psuedoclients.h"

#ifdef USE_HAXSERV_PSUEDOCLIENT
#include "psuedoclients/haxserv.h"
#endif

struct psuedoclient psuedoclients[NUM_PSUEDOCLIENTS] = {
#ifdef USE_HAXSERV_PSUEDOCLIENT
	[HAXSERV_PSUEDOCLIENT] = {
		.init = haxserv_psuedoclient_init,

		.allow_kill = haxserv_psuedoclient_allow_kill,
		.allow_kick = haxserv_psuedoclient_allow_kick,

		.handle_privmsg = haxserv_psuedoclient_handle_privmsg,
	},
#endif
};

int init_psuedoclients(void) {
#ifdef USE_HAXSERV_PSUEDOCLIENT
	if (psuedoclients[HAXSERV_PSUEDOCLIENT].init() != 0)
		return 1;
#endif

	return 0;
}
