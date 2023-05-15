/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015, Linaro Limited
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
	bool wait_read;
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
			struct condvar *cv, bool wait_read);

static inline void wq_wait_init(struct wait_queue *wq,
			struct wait_queue_elem *wqe, bool wait_read)
{
	wq_wait_init_condvar(wq, wqe, NULL, wait_read);
}

/* Waits for the wait queue element to the awakened. */
void wq_wait_final(struct wait_queue *wq, struct wait_queue_elem *wqe,
		   const void *sync_obj, const char *fname, int lineno);

/* Wakes up the first wait queue element in the wait queue, if there is one */
void wq_wake_next(struct wait_queue *wq, const void *sync_obj,
		const char *fname, int lineno);

/* Returns true if the wait queue doesn't contain any elements */
bool wq_is_empty(struct wait_queue *wq);

void wq_promote_condvar(struct wait_queue *wq, struct condvar *cv,
			bool only_one, const void *sync_obj, const char *fname,
			int lineno);
bool wq_have_condvar(struct wait_queue *wq, struct condvar *cv);

#endif /*KERNEL_WAIT_QUEUE_H*/

