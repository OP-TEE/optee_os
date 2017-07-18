/*
 * Copyright (c) 2015, Linaro Limited
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
#ifndef KERNEL_WAIT_QUEUE_H
#define KERNEL_WAIT_QUEUE_H

#include <types_ext.h>
#include <sys/queue.h>

struct wait_queue_elem;
SLIST_HEAD(wait_queue, wait_queue_elem);

#define WAIT_QUEUE_INITIALIZER { .slh_first = NULL }

struct condvar;
struct wait_queue_elem {
	short handle;
	bool done;
	struct condvar *cv;
	SLIST_ENTRY(wait_queue_elem) link;
};

/*
 * Initializes a wait queue
 */
void wq_init(struct wait_queue *wq);

/*
 * Initializes a wait queue element and adds it to the wait queue.  This
 * function is supposed to be called before the lock that protects the
 * resource we need to wait for is released.
 *
 * One call to this function must be followed by one call to wq_wait_final()
 * on the same wait queue element.
 */
void wq_wait_init_condvar(struct wait_queue *wq, struct wait_queue_elem *wqe,
			struct condvar *cv);

static inline void wq_wait_init(struct wait_queue *wq,
			struct wait_queue_elem *wqe)
{
	wq_wait_init_condvar(wq, wqe, NULL);
}

/* Waits for the wait queue element to the awakened. */
void wq_wait_final(struct wait_queue *wq, struct wait_queue_elem *wqe,
		   const void *sync_obj, int owner, const char *fname,
		   int lineno);

/* Wakes up the first wait queue element in the wait queue, if there is one */
void wq_wake_one(struct wait_queue *wq, const void *sync_obj,
		const char *fname, int lineno);

/* Returns true if the wait queue doesn't contain any elements */
bool wq_is_empty(struct wait_queue *wq);

void wq_promote_condvar(struct wait_queue *wq, struct condvar *cv,
			bool only_one, const void *sync_obj, const char *fname,
			int lineno);
bool wq_have_condvar(struct wait_queue *wq, struct condvar *cv);

void __wq_rpc(uint32_t func, int id, const void *sync_obj, int owner,
	      const char *fname, int lineno);

#endif /*KERNEL_WAIT_QUEUE_H*/

