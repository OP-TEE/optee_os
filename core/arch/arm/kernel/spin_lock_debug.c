// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016, Linaro Limited
 */

#include <assert.h>
#include <compiler.h>
#include <kernel/spinlock.h>
#include "thread_private.h"

void spinlock_count_incr(void)
{
	struct thread_core_local *l = thread_get_core_local();

	l->locked_count++;
	assert(l->locked_count);
}

void spinlock_count_decr(void)
{
	struct thread_core_local *l = thread_get_core_local();

	assert(l->locked_count);
	l->locked_count--;
}

bool __nostackcheck have_spinlock(void)
{
	struct thread_core_local *l;

	if (!thread_foreign_intr_disabled()) {
		/*
		 * Normally we can't be holding a spinlock since doing so would
		 * imply foreign interrupts are disabled (or the spinlock
		 * logic is flawed).
		 */
		return false;
	}

	l = thread_get_core_local();

	return !!l->locked_count;
}
