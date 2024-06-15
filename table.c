// My table library thing
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

#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include "haxstring.h"
#include "table.h"

// currently going with a binary lookup...

static inline int compare(struct string a, struct string b) {
	size_t len;
	if (a.len > b.len)
		len = b.len;
	else
		len = a.len;

	int val = memcmp(a.data, b.data, len);

	if (val == 0) {
		if (a.len < b.len)
			return -1;
		else if (a.len > b.len)
			return 1;
	}

	return val;
}

static inline size_t search(struct table tbl, struct string name, char *exists) {
	if (tbl.len == 0) {
		*exists = 0;
		return 0;
	}

	size_t low = 0, high = tbl.len - 1;

	size_t mid = high/2;

	while (low != high) {
		int val = compare(tbl.array[mid].name, name);

		if (val == 0) {
			*exists = 1;
			return mid;
		} else if (val > 0) {
			low = mid + 1;
			if (mid > low)
				break;
			if (low > high)
				low = high;
		} else {
			high = mid - 1;
			if (mid < high)
				break;
			if (high < low)
				high = low;
		}

		mid = low + ((high-low)/2);
	}

	int val = compare(tbl.array[mid].name, name);
	if (val > 0) {
		*exists = 0;
		return mid+1;
	} else if (val == 0) {
		*exists = 1;
		return mid;
	} else {
		*exists = 0;
		return mid;
	}
}

int set_table_index(struct table *tbl, struct string name, void *ptr) {
	char exists;
	size_t index = search(*tbl, name, &exists);

	if (!exists) {
		void *tmp = realloc(tbl->array, sizeof(*(tbl->array)) * (tbl->len+1));
		if (tmp == 0)
			return 1;

		tbl->array = tmp;

		memmove(&(tbl->array[index+1]), &(tbl->array[index]), (tbl->len - index) * sizeof(*(tbl->array)));
		tbl->len++;
	} else {
		tbl->array[index].ptr = ptr;

		return 0; // don't overwrite old allocated name
	}

	char *data = malloc(name.len);
	if (data == 0)
		return 1;

	memcpy(data, name.data, name.len);

	tbl->array[index] = (struct table_index){{data, name.len}, ptr};

	return 0;
}

void * get_table_index(struct table tbl, struct string name) {
	char exists;
	size_t index = search(tbl, name, &exists);
	if (!exists)
		return 0;

	return tbl.array[index].ptr;
}

char has_table_index(struct table tbl, struct string name) {
	char exists;
	search(tbl, name, &exists);
	return exists;
}

void * remove_table_index(struct table *tbl, struct string name) {
	char exists;
	size_t index = search(*tbl, name, &exists);

	if (!exists)
		return 0;

	void *ptr = tbl->array[index].ptr;
	free(tbl->array[index].name.data);

	memmove(&(tbl->array[index]), &(tbl->array[index+1]), (tbl->len - index - 1) * sizeof(*(tbl->array)));
	tbl->len--;

	void *tmp = realloc(tbl->array, sizeof(*(tbl->array)) * tbl->len);
	if (tmp || (tbl->len == 0))
		tbl->array = tmp;
	// else: realloc failed on shrinking... so now we have a table that's allocated a bit too big, not much of an issue

	return ptr;
}

void clear_table(struct table *tbl) {
	for (size_t i = 0; i < tbl->len; i++)
		free(tbl->array[i].name.data);

	tbl->array = realloc(tbl->array, 0);
	tbl->len = 0;
}

size_t get_table_offset(struct table tbl, struct string name, char *exists) {
	return search(tbl, name, exists);
}

// TODO: Proper lookup
void * get_table_prefix(struct table tbl, struct string name) {
	for (size_t i = 0; i < tbl.len; i++)
		if (tbl.array[i].name.len <= name.len && memcmp(tbl.array[i].name.data, name.data, tbl.array[i].name.len) == 0)
			return tbl.array[i].ptr;

	return 0;
}
