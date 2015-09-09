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
#include <kernel/mutex.h>
#include <kernel/tz_proc.h>
#include <kernel/thread.h>
#include <kernel/tee_common_unpg.h>
#include <trace.h>

void mutex_init(struct mutex *m)
{
	*m = (struct mutex)MUTEX_INITIALIZER;
}

void mutex_lock(struct mutex *m)
{
	while (true) {
		uint32_t old_itr_status;
		enum mutex_value old_value;
		struct wait_queue_elem wqe;

		/*
		 * If the mutex is locked we need to initialize the wqe
		 * before releasing the spinlock to guarantee that we don't
		 * miss the wakeup from mutex_unlock().
		 *
		 * If the mutex is unlocked we don't need to use the wqe at
		 * all.
		 */

		old_itr_status = thread_mask_exceptions(THREAD_EXCP_ALL);
		cpu_spin_lock(&m->spin_lock);

		old_value = m->value;
		if (old_value == MUTEX_VALUE_LOCKED) {
			wq_wait_init(&m->wq, &wqe);
		} else {
			m->value = MUTEX_VALUE_LOCKED;
		}

		cpu_spin_unlock(&m->spin_lock);
		thread_unmask_exceptions(old_itr_status);

		if (old_value == MUTEX_VALUE_LOCKED) {
			/*
			 * Someone else is holding the lock, wait in normal
			 * world for the lock to become available.
			 */
			wq_wait_final(&m->wq, &wqe);
		} else
			return;
	}
}

void mutex_unlock(struct mutex *m)
{
	uint32_t old_itr_status;

	old_itr_status = thread_mask_exceptions(THREAD_EXCP_ALL);
	cpu_spin_lock(&m->spin_lock);

	TEE_ASSERT(m->value == MUTEX_VALUE_LOCKED);
	m->value = MUTEX_VALUE_UNLOCKED;

	cpu_spin_unlock(&m->spin_lock);
	thread_unmask_exceptions(old_itr_status);

	wq_wake_one(&m->wq);
}

bool mutex_trylock(struct mutex *m)
{
	uint32_t old_itr_status;
	enum mutex_value old_value;

	old_itr_status = thread_mask_exceptions(THREAD_EXCP_ALL);
	cpu_spin_lock(&m->spin_lock);

	old_value = m->value;
	if (old_value == MUTEX_VALUE_UNLOCKED)
		m->value = MUTEX_VALUE_LOCKED;

	cpu_spin_unlock(&m->spin_lock);
	thread_unmask_exceptions(old_itr_status);

	return old_value == MUTEX_VALUE_UNLOCKED;
}

void mutex_destroy(struct mutex *m)
{
	/*
	 * Caller guarantees that no one will try to take the mutex so
	 * there's no need to take the spinlock before accessing it.
	 */
	TEE_ASSERT(m->value == MUTEX_VALUE_UNLOCKED);
	TEE_ASSERT(wq_is_empty(&m->wq));
}

void condvar_init(struct condvar *cv)
{
	*cv = (struct condvar)CONDVAR_INITIALIZER;
}

void condvar_destroy(struct condvar *cv)
{
	if (cv->m)
		TEE_ASSERT(!wq_have_condvar(&cv->m->wq, cv));
	condvar_init(cv);
}

static void cv_signal(struct condvar *cv, bool only_one)
{
	uint32_t old_itr_status;
	struct mutex *m;

	old_itr_status = thread_mask_exceptions(THREAD_EXCP_ALL);
	cpu_spin_lock(&cv->spin_lock);
	m = cv->m;
	cpu_spin_unlock(&cv->spin_lock);
	thread_unmask_exceptions(old_itr_status);

	if (m)
		wq_promote_condvar(&m->wq, cv, only_one);

}

void condvar_signal(struct condvar *cv)
{
	cv_signal(cv, true /* only one */);
}

void condvar_broadcast(struct condvar *cv)
{
	cv_signal(cv, false /* all */);
}

void condvar_wait(struct condvar *cv, struct mutex *m)
{
	uint32_t old_itr_status;
	struct wait_queue_elem wqe;

	old_itr_status = thread_mask_exceptions(THREAD_EXCP_ALL);

	/* Link this condvar to this mutex until reinitialized */
	cpu_spin_lock(&cv->spin_lock);
	TEE_ASSERT(!cv->m || cv->m == m);
	cv->m = m;
	cpu_spin_unlock(&cv->spin_lock);

	cpu_spin_lock(&m->spin_lock);

	/* Add to mutex wait queue as a condvar waiter */
	wq_wait_init_condvar(&m->wq, &wqe, cv);

	/* Unlock the mutex */
	TEE_ASSERT(m->value == MUTEX_VALUE_LOCKED);
	m->value = MUTEX_VALUE_UNLOCKED;

	cpu_spin_unlock(&m->spin_lock);

	thread_unmask_exceptions(old_itr_status);

	/* Wake eventual waiters */
	wq_wake_one(&m->wq);

	wq_wait_final(&m->wq, &wqe);

	mutex_lock(m);
}
