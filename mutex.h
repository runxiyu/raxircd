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

#define SETUP_MUTEX() 0
#define MUTEX_TYPE uint32_t

inline int mutex_init(uint32_t *futex) {
	*futex = 0;
	return 0;
}

inline void mutex_lock(uint32_t *futex) {
	if (__sync_fetch_and_or(futex, 0x1) == 0)
		return;

	while (__sync_fetch_and_or(futex, 0x3) != 0)
		syscall(SYS_futex, futex, FUTEX_PRIVATE_FLAG | FUTEX_WAIT, 3, 0, 0, 0);
}

inline void mutex_unlock(uint32_t *futex) {
	if (__sync_fetch_and_and(futex, 0) & 0x2)
		syscall(SYS_futex, futex, FUTEX_PRIVATE_FLAG | FUTEX_WAKE, 1, 0, 0, 0);
}

inline void mutex_destroy(uint32_t *futex) {
	return;
}

#else

#include <pthread.h>

#define SETUP_MUTEX() pthread_mutexattr_init(&pthread_mutexattr)
#define MUTEX_TYPE pthread_mutex_t

extern pthread_mutexattr_t pthread_mutexattr;
inline int mutex_init(pthread_mutex_t *mutex) {
	return pthread_mutex_init(mutex, &pthread_mutexattr);
}

inline void mutex_lock(pthread_mutex_t *mutex) {
	pthread_mutex_lock(mutex);
}

inline void mutex_unlock(pthread_mutex_t *mutex) {
	pthread_mutex_unlock(mutex);
}

inline void mutex_destroy(pthread_mutex_t *mutex) {
	pthread_mutex_destroy(mutex);
}

#endif
