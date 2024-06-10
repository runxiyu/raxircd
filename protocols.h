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

#include "server_network.h"

struct protocol {
	void * (*handle_connection)(void *info);
	void * (*autoconnect)(void *config);
	void (*update_propagations)(void);

	void (*propagate_new_server)(struct string from, struct string attached_to, struct string sid, struct server_info *info);
	void (*propagate_unlink)(struct string from, struct server_info *a, struct server_info *b, size_t protocol);

	void (*do_unlink)(struct server_info *a, struct server_info *b);
};

#ifdef USE_HAXIRCD_PROTOCOL
#define HAXIRCD_PROTOCOL 0
#endif
#ifdef USE_INSPIRCD2_PROTOCOL
#define INSPIRCD2_PROTOCOL 1
#endif

#define NUM_PROTOCOLS 2

extern struct protocol protocols[NUM_PROTOCOLS];
