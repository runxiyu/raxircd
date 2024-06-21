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

#ifdef USE_FUTEX

#include <unistd.h>
#include <sys/syscall.h>
#include <stdint.h>
#include <linux/futex.h>

#define MUTEX_TYPE uint32_t

inline void mutex_init(uint32_t *futex) {
	*futex = 0;
}

inline void mutex_lock(uint32_t *futex) {
	if ((__sync_fetch_and_or(futex, 0x1) & 0x1) == 0)
		return;

	__sync_fetch_and_add(futex, 0x2);

	uint32_t val;
	while ((val = __sync_fetch_and_or(futex, 0x1)) & 0x1)
		syscall(SYS_futex, futex, FUTEX_PRIVATE_FLAG | FUTEX_WAIT, val | 0x1, NULL, 0, 0);

	__sync_fetch_and_sub(futex, 0x2);
}

inline void mutex_unlock(uint32_t *futex) {
	if (__sync_and_and_fetch(futex, 0xFFFFFFFE))
		syscall(SYS_futex, futex, FUTEX_PRIVATE_FLAG | FUTEX_WAKE, 1, NULL, 0, 0);
}

inline void mutex_destroy(uint32_t *futex) {
	return;
}

#else

#include <semaphore.h>

#define MUTEX_TYPE sem_t

inline void mutex_init(sem_t *mutex) {
	sem_init(mutex, 0, 1);
}

inline void mutex_lock(sem_t *mutex) {
	while (sem_wait(mutex) == -1);
}

inline void mutex_unlock(sem_t *mutex) {
	sem_trywait(mutex);
	sem_post(mutex);
}

inline void mutex_destroy(sem_t *mutex) {
	sem_destroy(mutex);
}

#endif
