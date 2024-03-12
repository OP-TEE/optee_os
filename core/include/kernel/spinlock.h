/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2016, Linaro Limited
 */

#ifndef __KERNEL_SPINLOCK_H
#define __KERNEL_SPINLOCK_H

#define SPINLOCK_LOCK       1
#define SPINLOCK_UNLOCK     0

#ifndef __ASSEMBLER__
#include <assert.h>
#include <compiler.h>
#include <stdbool.h>
#include <kernel/thread.h>

#ifdef CFG_TEE_CORE_DEBUG
void spinlock_count_incr(void);
void spinlock_count_decr(void);
bool have_spinlock(void);
static inline void __nostackcheck assert_have_no_spinlock(void)
{
	assert(!have_spinlock());
}
#else
static inline void spinlock_count_incr(void) { }
static inline void spinlock_count_decr(void) { }
static inline void __nostackcheck assert_have_no_spinlock(void) { }
#endif

void __cpu_spin_lock(unsigned int *lock);
void __cpu_spin_unlock(unsigned int *lock);
/* returns 0 on locking success, non zero on failure */
unsigned int __cpu_spin_trylock(unsigned int *lock);

static inline void cpu_spin_lock_no_dldetect(unsigned int *lock)
{
	assert(thread_foreign_intr_disabled());
	__cpu_spin_lock(lock);
	spinlock_count_incr();
}

static inline bool thread_spin_trylock(unsigned int *lock)
{
	assert(thread_get_id_may_fail() != THREAD_ID_INVALID);
	return !__cpu_spin_trylock(lock);
}

/*
 * To be used with lot of care: it is not recommended to spin in a thread
 * context without masking foreign interrupts
 */
static inline void thread_spin_lock(unsigned int *lock)
{
	assert(thread_get_id_may_fail() != THREAD_ID_INVALID);
	__cpu_spin_lock(lock);
}

static inline void thread_spin_unlock(unsigned int *lock)
{
	assert(thread_get_id_may_fail() != THREAD_ID_INVALID);
	__cpu_spin_unlock(lock);
}

#ifdef CFG_TEE_CORE_DEBUG
#define cpu_spin_lock(lock) \
	cpu_spin_lock_dldetect(__func__, __LINE__, lock)

static inline void cpu_spin_lock_dldetect(const char *func, const int line,
					  unsigned int *lock)
{
	unsigned int retries = 0;
	unsigned int reminder = 0;

	assert(thread_foreign_intr_disabled());

	while (__cpu_spin_trylock(lock)) {
		retries++;
		if (!retries) {
			/* wrapped, time to report */
			trace_printf(func, line, TRACE_ERROR, true,
				     "possible spinlock deadlock reminder %u",
				      reminder);
			if (reminder < UINT_MAX)
				reminder++;
		}
	}

	spinlock_count_incr();
}
#else
static inline void cpu_spin_lock(unsigned int *lock)
{
	cpu_spin_lock_no_dldetect(lock);
}
#endif

static inline bool cpu_spin_trylock(unsigned int *lock)
{
	unsigned int rc;

	assert(thread_foreign_intr_disabled());
	rc = __cpu_spin_trylock(lock);
	if (!rc)
		spinlock_count_incr();
	return !rc;
}

static inline void cpu_spin_unlock(unsigned int *lock)
{
	assert(thread_foreign_intr_disabled());
	__cpu_spin_unlock(lock);
	spinlock_count_decr();
}

static inline uint32_t __must_check
cpu_spin_lock_xsave_no_dldetect(unsigned int *lock)
{
	uint32_t exceptions = thread_mask_exceptions(THREAD_EXCP_ALL);

	cpu_spin_lock(lock);
	return exceptions;
}

#ifdef CFG_TEE_CORE_DEBUG
#define cpu_spin_lock_xsave(lock) \
	cpu_spin_lock_xsave_dldetect(__func__, __LINE__, lock)

static inline uint32_t __must_check
cpu_spin_lock_xsave_dldetect(const char *func, const int line,
			     unsigned int *lock)
{
	uint32_t exceptions = thread_mask_exceptions(THREAD_EXCP_ALL);

	cpu_spin_lock_dldetect(func, line, lock);
	return exceptions;
}
#else
static inline uint32_t __must_check cpu_spin_lock_xsave(unsigned int *lock)
{
	return cpu_spin_lock_xsave_no_dldetect(lock);
}
#endif

static inline void cpu_spin_unlock_xrestore(unsigned int *lock,
					    uint32_t exceptions)
{
	cpu_spin_unlock(lock);
	thread_unmask_exceptions(exceptions);
}
#endif /* __ASSEMBLER__ */

#endif /* __KERNEL_SPINLOCK_H */
