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
#include <types_ext.h>
#include <sm/teesmc.h>
#include <kernel/tz_proc.h>
#include <kernel/wait_queue.h>
#include <kernel/tee_ta_manager.h>
#include <kernel/thread.h>
#include <kernel/tee_rpc.h>
#include <trace.h>

static unsigned wq_spin_lock;


void wq_init(struct wait_queue *wq)
{
	*wq = (struct wait_queue)WAIT_QUEUE_INITIALIZER;
}

static void wq_rpc(uint32_t cmd, int id, const void *sync_obj __maybe_unused,
			const char *fname, int lineno __maybe_unused)
{
	uint32_t ret;
	struct tee_ta_session *sess = NULL;
	struct teesmc32_param params[2];
	const char *cmd_str __maybe_unused =
		cmd == TEE_RPC_WAIT_QUEUE_SLEEP ? "sleep" : "wake";

	if (fname)
		DMSG("%s thread %u %p %s:%d", cmd_str, id,
		     sync_obj, fname, lineno);
	else
		DMSG("%s thread %u %p", cmd_str, id, sync_obj);

	tee_ta_get_current_session(&sess);
	if (sess)
		tee_ta_set_current_session(NULL);

	memset(params, 0, sizeof(params));
	params[0].attr = TEESMC_ATTR_TYPE_VALUE_INPUT;
	params[1].attr = TEESMC_ATTR_TYPE_NONE;
	params[0].u.value.a = id;

	ret = thread_rpc_cmd(cmd, 2, params);
	if (ret != TEE_SUCCESS)
		DMSG("%s thread %u ret 0x%x", cmd_str, id, ret);

	if (sess)
		tee_ta_set_current_session(sess);
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

	old_itr_status = thread_mask_exceptions(THREAD_EXCP_ALL);
	cpu_spin_lock(&wq_spin_lock);

	slist_add_tail(wq, wqe);

	cpu_spin_unlock(&wq_spin_lock);
	thread_unmask_exceptions(old_itr_status);
}

void wq_wait_final(struct wait_queue *wq, struct wait_queue_elem *wqe,
			const void *sync_obj, const char *fname, int lineno)
{
	uint32_t old_itr_status;
	unsigned done;

	do {
		wq_rpc(TEE_RPC_WAIT_QUEUE_SLEEP, wqe->handle,
		       sync_obj, fname, lineno);

		old_itr_status = thread_mask_exceptions(THREAD_EXCP_ALL);
		cpu_spin_lock(&wq_spin_lock);

		done = wqe->done;
		if (done)
			SLIST_REMOVE(wq, wqe, wait_queue_elem, link);

		cpu_spin_unlock(&wq_spin_lock);
		thread_unmask_exceptions(old_itr_status);
	} while (!done);
}

void wq_wake_one(struct wait_queue *wq, const void *sync_obj,
			const char *fname, int lineno)
{
	uint32_t old_itr_status;
	struct wait_queue_elem *wqe;
	int handle = -1;
	bool do_wakeup = false;

	old_itr_status = thread_mask_exceptions(THREAD_EXCP_ALL);
	cpu_spin_lock(&wq_spin_lock);

	SLIST_FOREACH(wqe, wq, link) {
		if (!wqe->cv) {
			do_wakeup = !wqe->done;
			wqe->done = true;
			handle = wqe->handle;
			break;
		}
	}

	cpu_spin_unlock(&wq_spin_lock);
	thread_unmask_exceptions(old_itr_status);

	if (do_wakeup)
		wq_rpc(TEE_RPC_WAIT_QUEUE_WAKEUP, handle,
		       sync_obj, fname, lineno);
}

void wq_promote_condvar(struct wait_queue *wq, struct condvar *cv,
			bool only_one, const void *sync_obj __unused,
			const char *fname, int lineno __maybe_unused)
{
	uint32_t old_itr_status;
	struct wait_queue_elem *wqe;

	if (!cv)
		return;

	old_itr_status = thread_mask_exceptions(THREAD_EXCP_ALL);
	cpu_spin_lock(&wq_spin_lock);

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

	cpu_spin_unlock(&wq_spin_lock);
	thread_unmask_exceptions(old_itr_status);
}

bool wq_have_condvar(struct wait_queue *wq, struct condvar *cv)
{
	uint32_t old_itr_status;
	struct wait_queue_elem *wqe;
	bool rc = false;

	old_itr_status = thread_mask_exceptions(THREAD_EXCP_ALL);
	cpu_spin_lock(&wq_spin_lock);

	SLIST_FOREACH(wqe, wq, link) {
		if (wqe->cv == cv) {
			rc = true;
			break;
		}
	}

	cpu_spin_unlock(&wq_spin_lock);
	thread_unmask_exceptions(old_itr_status);

	return rc;
}

bool wq_is_empty(struct wait_queue *wq)
{
	uint32_t old_itr_status;
	bool ret;

	old_itr_status = thread_mask_exceptions(THREAD_EXCP_ALL);
	cpu_spin_lock(&wq_spin_lock);

	ret = SLIST_EMPTY(wq);

	cpu_spin_unlock(&wq_spin_lock);
	thread_unmask_exceptions(old_itr_status);

	return ret;
}
