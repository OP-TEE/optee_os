// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015-2021, Linaro Limited
 */

#include <compiler.h>
#include <kernel/notif.h>
#include <kernel/spinlock.h>
#include <kernel/thread.h>
#include <kernel/wait_queue.h>
#include <optee_rpc_cmd.h>
#include <string.h>
#include <tee_api_defines.h>
#include <trace.h>
#include <types_ext.h>

static unsigned wq_spin_lock;


void wq_init(struct wait_queue *wq)
{
	*wq = (struct wait_queue)WAIT_QUEUE_INITIALIZER;
}

static void do_notif(TEE_Result (*fn)(uint32_t), int id,
		     const char *cmd_str __maybe_unused,
		     const void *sync_obj __maybe_unused,
		     const char *fname, int lineno __maybe_unused)
{
	TEE_Result res = TEE_SUCCESS;

	if (fname)
		DMSG("%s thread %d %p %s:%d", cmd_str, id,
		     sync_obj, fname, lineno);
	else
		DMSG("%s thread %d %p", cmd_str, id, sync_obj);

	res = fn(id + NOTIF_SYNC_VALUE_BASE);
	if (res)
		DMSG("%s thread %d res %#"PRIx32, cmd_str, id, res);
}

static void slist_add_tail(struct wait_queue *wq, struct wait_queue_elem *wqe)
{
	struct wait_queue_elem *wqe_iter;

	/* Add elem to end of wait queue */
	wqe_iter = SLIST_FIRST(wq);
	if (wqe_iter) {
		while (SLIST_NEXT(wqe_iter, link))
			wqe_iter = SLIST_NEXT(wqe_iter, link);
		SLIST_INSERT_AFTER(wqe_iter, wqe, link);
	} else
		SLIST_INSERT_HEAD(wq, wqe, link);
}

void wq_wait_init_condvar(struct wait_queue *wq, struct wait_queue_elem *wqe,
		struct condvar *cv, bool wait_read)
{
	uint32_t old_itr_status;

	wqe->handle = thread_get_id();
	wqe->done = false;
	wqe->wait_read = wait_read;
	wqe->cv = cv;

	old_itr_status = cpu_spin_lock_xsave(&wq_spin_lock);

	slist_add_tail(wq, wqe);

	cpu_spin_unlock_xrestore(&wq_spin_lock, old_itr_status);
}

void wq_wait_final(struct wait_queue *wq, struct wait_queue_elem *wqe,
		   const void *sync_obj, const char *fname, int lineno)
{
	uint32_t old_itr_status;
	unsigned done;

	do {
		do_notif(notif_wait, wqe->handle,
			 "sleep", sync_obj, fname, lineno);

		old_itr_status = cpu_spin_lock_xsave(&wq_spin_lock);

		done = wqe->done;
		if (done)
			SLIST_REMOVE(wq, wqe, wait_queue_elem, link);

		cpu_spin_unlock_xrestore(&wq_spin_lock, old_itr_status);
	} while (!done);
}

void wq_wake_next(struct wait_queue *wq, const void *sync_obj,
			const char *fname, int lineno)
{
	uint32_t old_itr_status;
	struct wait_queue_elem *wqe;
	int handle = -1;
	bool do_wakeup = false;
	bool wake_type_assigned = false;
	bool wake_read = false; /* avoid gcc warning */

	/*
	 * If next type is wait_read wakeup all wqe with wait_read true.
	 * If next type isn't wait_read wakeup only the first wqe which isn't
	 * done.
	 */

	while (true) {
		old_itr_status = cpu_spin_lock_xsave(&wq_spin_lock);

		SLIST_FOREACH(wqe, wq, link) {
			if (wqe->cv)
				continue;
			if (wqe->done)
				continue;
			if (!wake_type_assigned) {
				wake_read = wqe->wait_read;
				wake_type_assigned = true;
			}

			if (wqe->wait_read != wake_read)
				continue;

			wqe->done = true;
			handle = wqe->handle;
			do_wakeup = true;
			break;
		}

		cpu_spin_unlock_xrestore(&wq_spin_lock, old_itr_status);

		if (do_wakeup)
			do_notif(notif_send_sync, handle,
				 "wake ", sync_obj, fname, lineno);

		if (!do_wakeup || !wake_read)
			break;
		do_wakeup = false;
	}
}

void wq_promote_condvar(struct wait_queue *wq, struct condvar *cv,
			bool only_one, const void *sync_obj __unused,
			const char *fname, int lineno __maybe_unused)
{
	uint32_t old_itr_status;
	struct wait_queue_elem *wqe;

	if (!cv)
		return;

	old_itr_status = cpu_spin_lock_xsave(&wq_spin_lock);

	/*
	 * Find condvar waiter(s) and promote each to an active waiter.
	 * This is a bit unfair to eventual other active waiters as a
	 * condvar waiter is added to the queue when waiting for the
	 * condvar.
	 */
	SLIST_FOREACH(wqe, wq, link) {
		if (wqe->cv == cv) {
			if (fname)
				FMSG("promote thread %u %p %s:%d",
				     wqe->handle, (void *)cv->m, fname, lineno);
			else
				FMSG("promote thread %u %p",
				     wqe->handle, (void *)cv->m);

			wqe->cv = NULL;
			if (only_one)
				break;
		}
	}

	cpu_spin_unlock_xrestore(&wq_spin_lock, old_itr_status);
}

bool wq_have_condvar(struct wait_queue *wq, struct condvar *cv)
{
	uint32_t old_itr_status;
	struct wait_queue_elem *wqe;
	bool rc = false;

	old_itr_status = cpu_spin_lock_xsave(&wq_spin_lock);

	SLIST_FOREACH(wqe, wq, link) {
		if (wqe->cv == cv) {
			rc = true;
			break;
		}
	}

	cpu_spin_unlock_xrestore(&wq_spin_lock, old_itr_status);

	return rc;
}

bool wq_is_empty(struct wait_queue *wq)
{
	uint32_t old_itr_status;
	bool ret;

	old_itr_status = cpu_spin_lock_xsave(&wq_spin_lock);

	ret = SLIST_EMPTY(wq);

	cpu_spin_unlock_xrestore(&wq_spin_lock, old_itr_status);

	return ret;
}
