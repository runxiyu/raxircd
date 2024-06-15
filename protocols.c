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

#include "protocols.h"

#ifdef USE_INSPIRCD2_PROTOCOL
#include "protocols/inspircd2.h"
#endif

struct protocol protocols[NUM_PROTOCOLS] = {
#ifdef USE_INSPIRCD2_PROTOCOL
	[INSPIRCD2_PROTOCOL] = {
		.init = init_inspircd2_protocol,

		.handle_connection = inspircd2_protocol_connection,
		.autoconnect = inspircd2_protocol_autoconnect,
		.update_propagations = inspircd2_protocol_update_propagations,

		.propagate = inspircd2_protocol_propagate,

		.propagate_new_server = inspircd2_protocol_propagate_new_server,
		.propagate_unlink_server = inspircd2_protocol_propagate_unlink_server,

		.propagate_new_user = inspircd2_protocol_propagate_new_user,
		.propagate_rename_user = inspircd2_protocol_propagate_rename_user,
		.propagate_remove_user = inspircd2_protocol_propagate_remove_user,
		.propagate_kill_user = inspircd2_protocol_propagate_kill_user,
		.propagate_oper_user = inspircd2_protocol_propagate_oper_user,

		.propagate_set_channel = inspircd2_protocol_propagate_set_channel,
		.propagate_join_channel = inspircd2_protocol_propagate_join_channel,
		.propagate_part_channel = inspircd2_protocol_propagate_part_channel,
		.propagate_kick_channel = inspircd2_protocol_propagate_kick_channel,

		.propagate_privmsg = inspircd2_protocol_propagate_privmsg,
		.propagate_notice = inspircd2_protocol_propagate_notice,

		.do_unlink = inspircd2_protocol_do_unlink,
	},
#endif
};
