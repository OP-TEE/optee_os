/*
 * Copyright (c) 2015-2016, Linaro Limited
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
#include <compiler.h>
#include <types_ext.h>
#include <tee_api_defines.h>
#include <string.h>
#include <optee_msg.h>
#include <kernel/spinlock.h>
#include <kernel/wait_queue.h>
#include <kernel/thread.h>
#include <trace.h>

static unsigned wq_spin_lock;


void wq_init(struct wait_queue *wq)
{
	*wq = (struct wait_queue)WAIT_QUEUE_INITIALIZER;
}

/*
 * Note: this function is weak just to make it possible to exclude it from
 * the unpaged area.
 */
void __weak __wq_rpc(uint32_t func, int id, const void *sync_obj __maybe_unused,
		     int owner __maybe_unused, const char *fname,
		     int lineno __maybe_unused)
{
	uint32_t ret;
	struct optee_msg_param params;
	const char *cmd_str __maybe_unused =
	     func == OPTEE_MSG_RPC_WAIT_QUEUE_SLEEP ? "sleep" : "wake ";

	if (fname)
		DMSG("%s thread %u %p %d %s:%d", cmd_str, id,
		     sync_obj, owner, fname, lineno);
	else
		DMSG("%s thread %u %p %d", cmd_str, id, sync_obj, owner);

	memset(&params, 0, sizeof(params));
	params.attr = OPTEE_MSG_ATTR_TYPE_VALUE_INPUT;
	params.u.value.a = func;
	params.u.value.b = id;

	ret = thread_rpc_cmd(OPTEE_MSG_RPC_CMD_WAIT_QUEUE, 1, &params);
	if (ret != TEE_SUCCESS)
		DMSG("%s thread %u ret 0x%x", cmd_str, id, ret);
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
		struct condvar *cv)
{
	uint32_t old_itr_status;

	wqe->handle = thread_get_id();
	wqe->done = false;
	wqe->cv = cv;

	old_itr_status = cpu_spin_lock_xsave(&wq_spin_lock);

	slist_add_tail(wq, wqe);

	cpu_spin_unlock_xrestore(&wq_spin_lock, old_itr_status);
}

void wq_wait_final(struct wait_queue *wq, struct wait_queue_elem *wqe,
		   const void *sync_obj, int owner, const char *fname,
		   int lineno)
{
	uint32_t old_itr_status;
	unsigned done;

	do {
		__wq_rpc(OPTEE_MSG_RPC_WAIT_QUEUE_SLEEP, wqe->handle,
			 sync_obj, owner, fname, lineno);

		old_itr_status = cpu_spin_lock_xsave(&wq_spin_lock);

		done = wqe->done;
		if (done)
			SLIST_REMOVE(wq, wqe, wait_queue_elem, link);

		cpu_spin_unlock_xrestore(&wq_spin_lock, old_itr_status);
	} while (!done);
}

void wq_wake_one(struct wait_queue *wq, const void *sync_obj,
			const char *fname, int lineno)
{
	uint32_t old_itr_status;
	struct wait_queue_elem *wqe;
	int handle = -1;
	bool do_wakeup = false;

	old_itr_status = cpu_spin_lock_xsave(&wq_spin_lock);

	SLIST_FOREACH(wqe, wq, link) {
		if (!wqe->cv) {
			do_wakeup = !wqe->done;
			wqe->done = true;
			handle = wqe->handle;
			break;
		}
	}

	cpu_spin_unlock_xrestore(&wq_spin_lock, old_itr_status);

	if (do_wakeup)
		__wq_rpc(OPTEE_MSG_RPC_WAIT_QUEUE_WAKEUP, handle,
			 sync_obj, MUTEX_OWNER_ID_MUTEX_UNLOCK, fname, lineno);
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
	 * condvar waiter is added the the queue when waiting for the
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
