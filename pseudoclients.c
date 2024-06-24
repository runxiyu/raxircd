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

#include <dlfcn.h>
#include <stdio.h>

#include "haxstring.h"
#include "pseudoclients.h"

struct pseudoclient pseudoclients[NUM_PSEUDOCLIENTS] = {0};

char reload_pseudoclients[NUM_PSEUDOCLIENTS] = {0};

int init_pseudoclients(void) {
#ifdef USE_HAXSERV_PSEUDOCLIENT
	{
		void *dl_handle = dlopen("pseudoclients/haxserv.so", RTLD_NOW | RTLD_LOCAL);
		if (!dl_handle) {
			puts(dlerror());
			return 1;
		}

		pseudoclients[HAXSERV_PSEUDOCLIENT].dl_handle = dl_handle;
		pseudoclients[HAXSERV_PSEUDOCLIENT].init = dlsym(dl_handle, "haxserv_pseudoclient_init");

		if (pseudoclients[HAXSERV_PSEUDOCLIENT].init() != 0)
			return 1;
	}
#endif
#ifdef USE_SERVICES_PSEUDOCLIENT
	{
		void *dl_handle = dlopen("pseudoclients/services.so", RTLD_NOW | RTLD_LOCAL);
		if (!dl_handle) {
			puts(dlerror());
			return 1;
		}

		pseudoclients[SERVICES_PSEUDOCLIENT].dl_handle = dl_handle;
		pseudoclients[SERVICES_PSEUDOCLIENT].init = dlsym(dl_handle, "services_pseudoclient_init");

		if (pseudoclients[SERVICES_PSEUDOCLIENT].init() != 0)
			return 1;
	}
#endif

	return 0;
}
