// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015-2017, Linaro Limited
 */

#include <kernel/mutex.h>
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

void mutex_init_recursive(struct mutex *m)
{
	*m = (struct mutex)RECURSIVE_MUTEX_INITIALIZER;
}

static void __mutex_lock(struct mutex *m, const char *fname, int lineno)
{
	assert_have_no_spinlock();
	assert(thread_get_id_may_fail() != -1);
	assert(thread_is_in_normal_mode());

	if (m->recursive && atomic_load_int(&m->owner) == thread_get_id()) {
		if (!refcount_inc(&m->lock_count))
			panic();
		return;
	}

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
			if (m->recursive) {
				assert(m->owner == THREAD_ID_INVALID);
				m->owner = thread_get_id();
				refcount_set(&m->lock_count, 1);
			}
		}

		cpu_spin_unlock_xrestore(&m->spin_lock, old_itr_status);

		if (!can_lock) {
			/*
			 * Someone else is holding the lock, wait in normal
			 * world for the lock to become available.
			 */
			wq_wait_final(&m->wq, &wqe, m, fname, lineno);
		} else
			return;
	}
}

static void __mutex_unlock(struct mutex *m, const char *fname, int lineno)
{
	uint32_t old_itr_status;

	assert_have_no_spinlock();
	assert(thread_get_id_may_fail() != -1);

	if (m->recursive) {
		if (refcount_dec(&m->lock_count)) {
			/*
			 * Do an atomic store to match the atomic load in
			 * __mutex_lock() and __mutex_trylock().
			 */
			atomic_store_int(&m->owner, THREAD_ID_INVALID);
			/* Proceed with unlock below */
		} else {
			/* The mutex is still write locked by this thread */
			return;
		}
	}

	mutex_unlock_check(m);

	old_itr_status = cpu_spin_lock_xsave(&m->spin_lock);

	if (!m->state)
		panic();

	m->state = 0;

	cpu_spin_unlock_xrestore(&m->spin_lock, old_itr_status);

	wq_wake_next(&m->wq, m, fname, lineno);
}

static bool __mutex_trylock(struct mutex *m, const char *fname __unused,
			int lineno __unused)
{
	uint32_t old_itr_status;
	bool can_lock_write;

	assert_have_no_spinlock();
	assert(thread_get_id_may_fail() != -1);

	if (m->recursive && atomic_load_int(&m->owner) == thread_get_id()) {
		if (!refcount_inc(&m->lock_count))
			panic();
		return true;
	}

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
	assert(thread_get_id_may_fail() != -1);

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
	assert(thread_get_id_may_fail() != -1);
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
			wq_wait_final(&m->wq, &wqe, m, fname, lineno);
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
	assert(thread_get_id_may_fail() != -1);
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

static void __condvar_wait(struct condvar *cv, struct mutex *m,
			const char *fname, int lineno)
{
	uint32_t old_itr_status;
	struct wait_queue_elem wqe;
	short old_state;
	short new_state;

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

	wq_wait_final(&m->wq, &wqe, m, fname, lineno);

	if (old_state > 0)
		mutex_read_lock(m);
	else
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
