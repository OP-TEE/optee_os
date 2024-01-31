// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015-2017, Linaro Limited
 */

#include <kernel/mutex.h>
#include <kernel/mutex_pm_aware.h>
#include <kernel/panic.h>
#include <kernel/refcount.h>
#include <kernel/spinlock.h>
#include <kernel/thread.h>
#include <trace.h>

#include "mutex_lockdep.h"

void mutex_init(struct mutex *m)
{
	*m = (struct mutex)MUTEX_INITIALIZER;
}

void mutex_init_recursive(struct recursive_mutex *m)
{
	*m = (struct recursive_mutex)RECURSIVE_MUTEX_INITIALIZER;
}

static void __mutex_lock(struct mutex *m, const char *fname, int lineno)
{
	assert_have_no_spinlock();
	assert(thread_get_id_may_fail() != THREAD_ID_INVALID);
	assert(thread_is_in_normal_mode());

	mutex_lock_check(m);

	while (true) {
		uint32_t old_itr_status;
		bool can_lock;
		struct wait_queue_elem wqe;

		/*
		 * If the mutex is locked we need to initialize the wqe
		 * before releasing the spinlock to guarantee that we don't
		 * miss the wakeup from mutex_unlock().
		 *
		 * If the mutex is unlocked we don't need to use the wqe at
		 * all.
		 */

		old_itr_status = cpu_spin_lock_xsave(&m->spin_lock);

		can_lock = !m->state;
		if (!can_lock) {
			wq_wait_init(&m->wq, &wqe, false /* wait_read */);
		} else {
			m->state = -1; /* write locked */
		}

		cpu_spin_unlock_xrestore(&m->spin_lock, old_itr_status);

		if (!can_lock) {
			/*
			 * Someone else is holding the lock, wait in normal
			 * world for the lock to become available.
			 */
			wq_wait_final(&m->wq, &wqe, 0, m, fname, lineno);
		} else
			return;
	}
}

static void __mutex_lock_recursive(struct recursive_mutex *m, const char *fname,
				   int lineno)
{
	short int ct = thread_get_id();

	assert_have_no_spinlock();
	assert(thread_is_in_normal_mode());

	if (atomic_load_short(&m->owner) == ct) {
		if (!refcount_inc(&m->lock_depth))
			panic();
		return;
	}

	__mutex_lock(&m->m, fname, lineno);

	assert(m->owner == THREAD_ID_INVALID);
	atomic_store_short(&m->owner, ct);
	refcount_set(&m->lock_depth, 1);
}

static void __mutex_unlock(struct mutex *m, const char *fname, int lineno)
{
	uint32_t old_itr_status;

	assert_have_no_spinlock();
	assert(thread_get_id_may_fail() != THREAD_ID_INVALID);

	mutex_unlock_check(m);

	old_itr_status = cpu_spin_lock_xsave(&m->spin_lock);

	if (!m->state)
		panic();

	m->state = 0;

	cpu_spin_unlock_xrestore(&m->spin_lock, old_itr_status);

	wq_wake_next(&m->wq, m, fname, lineno);
}

static void __mutex_unlock_recursive(struct recursive_mutex *m,
				     const char *fname, int lineno)
{
	assert_have_no_spinlock();
	assert(m->owner == thread_get_id());

	if (refcount_dec(&m->lock_depth)) {
		/*
		 * Do an atomic store to match the atomic load in
		 * __mutex_lock_recursive()
		 */
		atomic_store_short(&m->owner, THREAD_ID_INVALID);
		__mutex_unlock(&m->m, fname, lineno);
	}
}

static bool __mutex_trylock(struct mutex *m, const char *fname __unused,
			int lineno __unused)
{
	uint32_t old_itr_status;
	bool can_lock_write;

	assert_have_no_spinlock();
	assert(thread_get_id_may_fail() != THREAD_ID_INVALID);

	old_itr_status = cpu_spin_lock_xsave(&m->spin_lock);

	can_lock_write = !m->state;
	if (can_lock_write)
		m->state = -1;

	cpu_spin_unlock_xrestore(&m->spin_lock, old_itr_status);

	if (can_lock_write)
		mutex_trylock_check(m);

	return can_lock_write;
}

static void __mutex_read_unlock(struct mutex *m, const char *fname, int lineno)
{
	uint32_t old_itr_status;
	short new_state;

	assert_have_no_spinlock();
	assert(thread_get_id_may_fail() != THREAD_ID_INVALID);

	old_itr_status = cpu_spin_lock_xsave(&m->spin_lock);

	if (m->state <= 0)
		panic();
	m->state--;
	new_state = m->state;

	cpu_spin_unlock_xrestore(&m->spin_lock, old_itr_status);

	/* Wake eventual waiters if the mutex was unlocked */
	if (!new_state)
		wq_wake_next(&m->wq, m, fname, lineno);
}

static void __mutex_read_lock(struct mutex *m, const char *fname, int lineno)
{
	assert_have_no_spinlock();
	assert(thread_get_id_may_fail() != THREAD_ID_INVALID);
	assert(thread_is_in_normal_mode());

	while (true) {
		uint32_t old_itr_status;
		bool can_lock;
		struct wait_queue_elem wqe;

		/*
		 * If the mutex is locked we need to initialize the wqe
		 * before releasing the spinlock to guarantee that we don't
		 * miss the wakeup from mutex_unlock().
		 *
		 * If the mutex is unlocked we don't need to use the wqe at
		 * all.
		 */

		old_itr_status = cpu_spin_lock_xsave(&m->spin_lock);

		can_lock = m->state != -1;
		if (!can_lock) {
			wq_wait_init(&m->wq, &wqe, true /* wait_read */);
		} else {
			m->state++; /* read_locked */
		}

		cpu_spin_unlock_xrestore(&m->spin_lock, old_itr_status);

		if (!can_lock) {
			/*
			 * Someone else is holding the lock, wait in normal
			 * world for the lock to become available.
			 */
			wq_wait_final(&m->wq, &wqe, 0, m, fname, lineno);
		} else
			return;
	}
}

static bool __mutex_read_trylock(struct mutex *m, const char *fname __unused,
				 int lineno __unused)
{
	uint32_t old_itr_status;
	bool can_lock;

	assert_have_no_spinlock();
	assert(thread_get_id_may_fail() != THREAD_ID_INVALID);
	assert(thread_is_in_normal_mode());

	old_itr_status = cpu_spin_lock_xsave(&m->spin_lock);

	can_lock = m->state != -1;
	if (can_lock)
		m->state++;

	cpu_spin_unlock_xrestore(&m->spin_lock, old_itr_status);

	return can_lock;
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

void mutex_read_unlock_debug(struct mutex *m, const char *fname, int lineno)
{
	__mutex_read_unlock(m, fname, lineno);
}

void mutex_read_lock_debug(struct mutex *m, const char *fname, int lineno)
{
	__mutex_read_lock(m, fname, lineno);
}

bool mutex_read_trylock_debug(struct mutex *m, const char *fname, int lineno)
{
	return __mutex_read_trylock(m, fname, lineno);
}

void mutex_unlock_recursive_debug(struct recursive_mutex *m, const char *fname,
				  int lineno)
{
	__mutex_unlock_recursive(m, fname, lineno);
}

void mutex_lock_recursive_debug(struct recursive_mutex *m, const char *fname,
				int lineno)
{
	__mutex_lock_recursive(m, fname, lineno);
}
#else
void mutex_unlock(struct mutex *m)
{
	__mutex_unlock(m, NULL, -1);
}

void mutex_unlock_recursive(struct recursive_mutex *m)
{
	__mutex_unlock_recursive(m, NULL, -1);
}

void mutex_lock(struct mutex *m)
{
	__mutex_lock(m, NULL, -1);
}

void mutex_lock_recursive(struct recursive_mutex *m)
{
	__mutex_lock_recursive(m, NULL, -1);
}

bool mutex_trylock(struct mutex *m)
{
	return __mutex_trylock(m, NULL, -1);
}

void mutex_read_unlock(struct mutex *m)
{
	__mutex_read_unlock(m, NULL, -1);
}

void mutex_read_lock(struct mutex *m)
{
	__mutex_read_lock(m, NULL, -1);
}

bool mutex_read_trylock(struct mutex *m)
{
	return __mutex_read_trylock(m, NULL, -1);
}
#endif

void mutex_destroy(struct mutex *m)
{
	/*
	 * Caller guarantees that no one will try to take the mutex so
	 * there's no need to take the spinlock before accessing it.
	 */
	if (m->state)
		panic();
	if (!wq_is_empty(&m->wq))
		panic("waitqueue not empty");
	mutex_destroy_check(m);
}

void mutex_destroy_recursive(struct recursive_mutex *m)
{
	mutex_destroy(&m->m);
}

unsigned int mutex_get_recursive_lock_depth(struct recursive_mutex *m)
{
	assert_have_no_spinlock();
	assert(m->owner == thread_get_id());

	return refcount_val(&m->lock_depth);
}

void mutex_pm_aware_init(struct mutex_pm_aware *m)
{
	*m = (struct mutex_pm_aware)MUTEX_PM_AWARE_INITIALIZER;
}

void mutex_pm_aware_destroy(struct mutex_pm_aware *m)
{
	mutex_destroy(&m->mutex);
}

void mutex_pm_aware_lock(struct mutex_pm_aware *m)
{
	if (thread_get_id_may_fail() == THREAD_ID_INVALID) {
		if (!cpu_spin_trylock(&m->lock) || m->mutex.state)
			panic();
	} else {
		mutex_lock(&m->mutex);
		if (!thread_spin_trylock(&m->lock))
			panic();
	}
}

void mutex_pm_aware_unlock(struct mutex_pm_aware *m)
{
	if (thread_get_id_may_fail() == THREAD_ID_INVALID) {
		assert(!m->mutex.state);
		cpu_spin_unlock(&m->lock);
	} else {
		thread_spin_unlock(&m->lock);
		mutex_unlock(&m->mutex);
	}
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

	old_itr_status = cpu_spin_lock_xsave(&cv->spin_lock);
	m = cv->m;
	cpu_spin_unlock_xrestore(&cv->spin_lock, old_itr_status);

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

static TEE_Result __condvar_wait_timeout(struct condvar *cv, struct mutex *m,
					 uint32_t timeout_ms, const char *fname,
					 int lineno)
{
	TEE_Result res = TEE_SUCCESS;
	uint32_t old_itr_status = 0;
	struct wait_queue_elem wqe = { };
	short old_state = 0;
	short new_state = 0;

	mutex_unlock_check(m);

	/* Link this condvar to this mutex until reinitialized */
	old_itr_status = cpu_spin_lock_xsave(&cv->spin_lock);
	if (cv->m && cv->m != m)
		panic("invalid mutex");

	cv->m = m;
	cpu_spin_unlock(&cv->spin_lock);

	cpu_spin_lock(&m->spin_lock);

	if (!m->state)
		panic();
	old_state = m->state;
	/* Add to mutex wait queue as a condvar waiter */
	wq_wait_init_condvar(&m->wq, &wqe, cv, m->state > 0);

	if (m->state > 1) {
		/* Multiple read locks, remove one */
		m->state--;
	} else {
		/* Only one lock (read or write), unlock the mutex */
		m->state = 0;
	}
	new_state = m->state;

	cpu_spin_unlock_xrestore(&m->spin_lock, old_itr_status);

	/* Wake eventual waiters if the mutex was unlocked */
	if (!new_state)
		wq_wake_next(&m->wq, m, fname, lineno);

	res = wq_wait_final(&m->wq, &wqe, timeout_ms, m, fname, lineno);

	if (old_state > 0)
		mutex_read_lock(m);
	else
		mutex_lock(m);

	return res;
}

#ifdef CFG_MUTEX_DEBUG
void condvar_wait_debug(struct condvar *cv, struct mutex *m,
			const char *fname, int lineno)
{
	__condvar_wait_timeout(cv, m, 0, fname, lineno);
}

TEE_Result condvar_wait_timeout_debug(struct condvar *cv, struct mutex *m,
				      uint32_t timeout_ms, const char *fname,
				      int lineno)
{
	return __condvar_wait_timeout(cv, m, timeout_ms, fname, lineno);
}
#else
void condvar_wait(struct condvar *cv, struct mutex *m)
{
	__condvar_wait_timeout(cv, m, 0, NULL, -1);
}

TEE_Result condvar_wait_timeout(struct condvar *cv, struct mutex *m,
				uint32_t timeout_ms)
{
	return __condvar_wait_timeout(cv, m, timeout_ms, NULL, -1);
}
#endif
