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
#include <kernel/panic.h>
#include <kernel/spinlock.h>
#include <kernel/thread.h>
#include <trace.h>

void mutex_init(struct mutex *m)
{
	*m = (struct mutex)MUTEX_INITIALIZER;
}

static void __mutex_lock(struct mutex *m, const char *fname, int lineno)
{
	assert_have_no_spinlock();
	assert(thread_get_id_may_fail() != -1);

	while (true) {
		uint32_t old_itr_status;
		enum mutex_value old_value;
		struct wait_queue_elem wqe;
		int owner = MUTEX_OWNER_ID_NONE;

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
			owner = m->owner_id;
			assert(owner != thread_get_id_may_fail());
		} else {
			m->value = MUTEX_VALUE_LOCKED;
			thread_add_mutex(m);
		}

		cpu_spin_unlock(&m->spin_lock);
		thread_unmask_exceptions(old_itr_status);

		if (old_value == MUTEX_VALUE_LOCKED) {
			/*
			 * Someone else is holding the lock, wait in normal
			 * world for the lock to become available.
			 */
			wq_wait_final(&m->wq, &wqe, m, owner, fname, lineno);
		} else
			return;
	}
}

static void __mutex_unlock(struct mutex *m, const char *fname, int lineno)
{
	uint32_t old_itr_status;

	assert_have_no_spinlock();
	assert(thread_get_id_may_fail() != -1);

	old_itr_status = thread_mask_exceptions(THREAD_EXCP_ALL);
	cpu_spin_lock(&m->spin_lock);

	if (m->value != MUTEX_VALUE_LOCKED)
		panic();

	thread_rem_mutex(m);
	m->value = MUTEX_VALUE_UNLOCKED;

	cpu_spin_unlock(&m->spin_lock);
	thread_unmask_exceptions(old_itr_status);

	wq_wake_one(&m->wq, m, fname, lineno);
}

static bool __mutex_trylock(struct mutex *m, const char *fname __unused,
			int lineno __unused)
{
	uint32_t old_itr_status;
	enum mutex_value old_value;

	assert_have_no_spinlock();
	assert(thread_get_id_may_fail() != -1);

	old_itr_status = thread_mask_exceptions(THREAD_EXCP_ALL);
	cpu_spin_lock(&m->spin_lock);

	old_value = m->value;
	if (old_value == MUTEX_VALUE_UNLOCKED) {
		m->value = MUTEX_VALUE_LOCKED;
		thread_add_mutex(m);
	}

	cpu_spin_unlock(&m->spin_lock);
	thread_unmask_exceptions(old_itr_status);

	return old_value == MUTEX_VALUE_UNLOCKED;
}

#ifdef CFG_MUTEX_DEBUG
void mutex_unlock_debug(struct mutex *m, const char *fname, int lineno)
{
	__mutex_unlock(m, fname, lineno);
}

void mutex_lock_debug(struct mutex *m, const char *fname, int lineno)
{
	__mutex_lock(m, fname, lineno);
}

bool mutex_trylock_debug(struct mutex *m, const char *fname, int lineno)
{
	return __mutex_trylock(m, fname, lineno);
}
#else
void mutex_unlock(struct mutex *m)
{
	__mutex_unlock(m, NULL, -1);
}

void mutex_lock(struct mutex *m)
{
	__mutex_lock(m, NULL, -1);
}

bool mutex_trylock(struct mutex *m)
{
	return __mutex_trylock(m, NULL, -1);
}
#endif



void mutex_destroy(struct mutex *m)
{
	/*
	 * Caller guarantees that no one will try to take the mutex so
	 * there's no need to take the spinlock before accessing it.
	 */
	if (m->value != MUTEX_VALUE_UNLOCKED)
		panic();
	if (!wq_is_empty(&m->wq))
		panic("waitqueue not empty");
}

void condvar_init(struct condvar *cv)
{
	*cv = (struct condvar)CONDVAR_INITIALIZER;
}

void condvar_destroy(struct condvar *cv)
{
	if (cv->m && wq_have_condvar(&cv->m->wq, cv))
		panic();

	condvar_init(cv);
}

static void cv_signal(struct condvar *cv, bool only_one, const char *fname,
			int lineno)
{
	uint32_t old_itr_status;
	struct mutex *m;

	old_itr_status = thread_mask_exceptions(THREAD_EXCP_ALL);
	cpu_spin_lock(&cv->spin_lock);
	m = cv->m;
	cpu_spin_unlock(&cv->spin_lock);
	thread_unmask_exceptions(old_itr_status);

	if (m)
		wq_promote_condvar(&m->wq, cv, only_one, m, fname, lineno);

}

#ifdef CFG_MUTEX_DEBUG
void condvar_signal_debug(struct condvar *cv, const char *fname, int lineno)
{
	cv_signal(cv, true /* only one */, fname, lineno);
}

void condvar_broadcast_debug(struct condvar *cv, const char *fname, int lineno)
{
	cv_signal(cv, false /* all */, fname, lineno);
}

#else
void condvar_signal(struct condvar *cv)
{
	cv_signal(cv, true /* only one */, NULL, -1);
}

void condvar_broadcast(struct condvar *cv)
{
	cv_signal(cv, false /* all */, NULL, -1);
}
#endif /*CFG_MUTEX_DEBUG*/

static void __condvar_wait(struct condvar *cv, struct mutex *m,
			const char *fname, int lineno)
{
	uint32_t old_itr_status;
	struct wait_queue_elem wqe;

	old_itr_status = thread_mask_exceptions(THREAD_EXCP_ALL);

	/* Link this condvar to this mutex until reinitialized */
	cpu_spin_lock(&cv->spin_lock);
	if (cv->m && cv->m != m)
		panic("invalid mutex");

	cv->m = m;
	cpu_spin_unlock(&cv->spin_lock);

	cpu_spin_lock(&m->spin_lock);

	/* Add to mutex wait queue as a condvar waiter */
	wq_wait_init_condvar(&m->wq, &wqe, cv);

	/* Unlock the mutex */
	if (m->value != MUTEX_VALUE_LOCKED)
		panic();

	thread_rem_mutex(m);
	m->value = MUTEX_VALUE_UNLOCKED;

	cpu_spin_unlock(&m->spin_lock);

	thread_unmask_exceptions(old_itr_status);

	/* Wake eventual waiters */
	wq_wake_one(&m->wq, m, fname, lineno);

	wq_wait_final(&m->wq, &wqe,
		      m, MUTEX_OWNER_ID_CONDVAR_SLEEP, fname, lineno);

	mutex_lock(m);
}

#ifdef CFG_MUTEX_DEBUG
void condvar_wait_debug(struct condvar *cv, struct mutex *m,
			const char *fname, int lineno)
{
	__condvar_wait(cv, m, fname, lineno);
}
#else
void condvar_wait(struct condvar *cv, struct mutex *m)
{
	__condvar_wait(cv, m, NULL, -1);
}
#endif
