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
#include <kernel/wait_queue.h>

enum mutex_value {
	MUTEX_VALUE_UNLOCKED,
	MUTEX_VALUE_LOCKED,
};

struct mutex {
	enum mutex_value value;
	unsigned spin_lock;	/* used when operating on this struct */
	struct wait_queue wq;
};

#define MUTEX_INITIALIZER	{ .value = MUTEX_VALUE_UNLOCKED, \
				  .wq = WAIT_QUEUE_INITIALIZER, }

void mutex_init(struct mutex *m);
void mutex_lock(struct mutex *m);
void mutex_unlock(struct mutex *m);
bool mutex_trylock(struct mutex *m);
void mutex_destroy(struct mutex *m);


struct condvar {
	unsigned spin_lock;
	struct mutex *m;
};
#define CONDVAR_INITIALIZER { .m = NULL }

void condvar_init(struct condvar *cv);
void condvar_destroy(struct condvar *cv);
void condvar_signal(struct condvar *cv);
void condvar_broadcast(struct condvar *cv);
void condvar_wait(struct condvar *cv, struct mutex *m);

#endif /*KERNEL_MUTEX_H*/

