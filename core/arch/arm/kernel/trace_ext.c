// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, Linaro Limited
 */
#include <stdbool.h>
#include <trace.h>
#include <console.h>
#include <kernel/misc.h>
#include <kernel/spinlock.h>
#include <kernel/thread.h>
#include <mm/core_mmu.h>

const char trace_ext_prefix[] = "TC";
int trace_level __nex_data = TRACE_LEVEL;
static unsigned int puts_lock __nex_bss = SPINLOCK_UNLOCK;

void __weak plat_trace_ext_puts(const char *str __unused)
{
}

void trace_ext_puts(const char *str)
{
	uint32_t itr_status = thread_mask_exceptions(THREAD_EXCP_ALL);
	bool mmu_enabled = cpu_mmu_enabled();
	bool was_contended = false;
	const char *p;

	if (mmu_enabled && !cpu_spin_trylock(&puts_lock)) {
		was_contended = true;
		cpu_spin_lock_no_dldetect(&puts_lock);
	}

	plat_trace_ext_puts(str);

	console_flush();

	if (was_contended)
		console_putc('*');

	for (p = str; *p; p++)
		console_putc(*p);

	console_flush();

	if (mmu_enabled)
		cpu_spin_unlock(&puts_lock);

	thread_unmask_exceptions(itr_status);
}

int trace_ext_get_thread_id(void)
{
	return thread_get_id_may_fail();
}

int trace_ext_get_core_id(void)
{
	/* If foreign interrupts aren't masked we report invalid core ID */
	if (thread_get_exceptions() & THREAD_EXCP_FOREIGN_INTR)
		return get_core_pos();
	else
		return -1;
}
