/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2016, Linaro Limited
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

#ifndef KERNEL_SPINLOCK_H
#define KERNEL_SPINLOCK_H

#define SPINLOCK_LOCK       1
#define SPINLOCK_UNLOCK     0

#ifndef ASM
#include <assert.h>
#include <compiler.h>
#include <stdbool.h>
#include <kernel/thread.h>

#ifdef CFG_TEE_CORE_DEBUG
void spinlock_count_incr(void);
void spinlock_count_decr(void);
bool have_spinlock(void);
static inline void assert_have_no_spinlock(void)
{
	assert(!have_spinlock());
}
#else
static inline void spinlock_count_incr(void) { }
static inline void spinlock_count_decr(void) { }
static inline void assert_have_no_spinlock(void) { }
#endif

void __cpu_spin_lock(unsigned int *lock);
void __cpu_spin_unlock(unsigned int *lock);
/* returns 0 on locking success, non zero on failure */
unsigned int __cpu_spin_trylock(unsigned int *lock);

static inline void cpu_spin_lock(unsigned int *lock)
{
	assert(thread_foreign_intr_disabled());
	__cpu_spin_lock(lock);
	spinlock_count_incr();
}

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

static inline uint32_t cpu_spin_lock_xsave(unsigned int *lock)
{
	uint32_t exceptions = thread_mask_exceptions(THREAD_EXCP_ALL);

	cpu_spin_lock(lock);
	return exceptions;
}

static inline void cpu_spin_unlock_xrestore(unsigned int *lock,
					    uint32_t exceptions)
{
	cpu_spin_unlock(lock);
	thread_unmask_exceptions(exceptions);
}
#endif /* ASM */

#endif /* KERNEL_SPINLOCK_H */
