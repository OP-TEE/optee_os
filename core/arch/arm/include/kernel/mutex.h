/*
 * Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef KERNEL_MUTEX_H
#define KERNEL_MUTEX_H

#include <types_ext.h>
#include <sys/queue.h>
#include <kernel/wait_queue.h>

enum mutex_value {
	MUTEX_VALUE_UNLOCKED,
	MUTEX_VALUE_LOCKED,
};

/*
 * Positive owner ids signifies actual threads, negative ids has special
 * meanings according to the defines below. Note that only the first of the
 * defines is allowed in struct mutex::owener_id.
 */
#define MUTEX_OWNER_ID_NONE		-1
#define MUTEX_OWNER_ID_CONDVAR_SLEEP	-2
#define MUTEX_OWNER_ID_MUTEX_UNLOCK	-3

struct mutex {
	enum mutex_value value;
	unsigned spin_lock;	/* used when operating on this struct */
	struct wait_queue wq;
	int owner_id;
	TAILQ_ENTRY(mutex) link;
};
#define MUTEX_INITIALIZER \
	{ .value = MUTEX_VALUE_UNLOCKED, .owner_id = MUTEX_OWNER_ID_NONE, \
	  .wq = WAIT_QUEUE_INITIALIZER, }

TAILQ_HEAD(mutex_head, mutex);

void mutex_init(struct mutex *m);
void mutex_destroy(struct mutex *m);

#ifdef CFG_MUTEX_DEBUG
void mutex_unlock_debug(struct mutex *m, const char *fname, int lineno);
#define mutex_unlock(m) mutex_unlock_debug((m), __FILE__, __LINE__)

void mutex_lock_debug(struct mutex *m, const char *fname, int lineno);
#define mutex_lock(m) mutex_lock_debug((m), __FILE__, __LINE__)

bool mutex_trylock_debug(struct mutex *m, const char *fname, int lineno);
#define mutex_trylock(m) mutex_trylock_debug((m), __FILE__, __LINE__)

#else
void mutex_unlock(struct mutex *m);
void mutex_lock(struct mutex *m);
bool mutex_trylock(struct mutex *m);
#endif


struct condvar {
	unsigned spin_lock;
	struct mutex *m;
};
#define CONDVAR_INITIALIZER { .m = NULL }

void condvar_init(struct condvar *cv);
void condvar_destroy(struct condvar *cv);

#ifdef CFG_MUTEX_DEBUG
void condvar_signal_debug(struct condvar *cv, const char *fname, int lineno);
#define condvar_signal(cv) condvar_signal_debug((cv), __FILE__, __LINE__)

void condvar_broadcast_debug(struct condvar *cv, const char *fname, int lineno);
#define condvar_broadcast(cv) condvar_broadcast_debug((cv), __FILE__, __LINE__)

void condvar_wait_debug(struct condvar *cv, struct mutex *m,
			const char *fname, int lineno);
#define condvar_wait(cv, m) condvar_wait_debug((cv), (m), __FILE__, __LINE__)
#else
void condvar_signal(struct condvar *cv);
void condvar_broadcast(struct condvar *cv);
void condvar_wait(struct condvar *cv, struct mutex *m);
#endif

#endif /*KERNEL_MUTEX_H*/

