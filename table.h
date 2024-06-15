// Header for my table library thing
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

#include "haxstring.h"

struct table_index {
	struct string name;
	void *ptr;
};

struct table {
	struct table_index *array;
	size_t len;
};

extern int set_table_index(struct table *tbl, struct string name, void *ptr);
extern void * get_table_index(struct table tbl, struct string name);
extern char has_table_index(struct table tbl, struct string name);
extern void * remove_table_index(struct table *tbl, struct string name); // returns same as get_table_index
extern void clear_table(struct table *tbl);
extern size_t get_table_offset(struct table tbl, struct string name, char *exists);

// Longest index that <name> starts with
extern void * get_table_prefix(struct table tbl, struct string name);
