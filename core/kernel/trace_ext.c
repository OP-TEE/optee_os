// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, Linaro Limited
 */
#include <stdbool.h>
#include <trace.h>
#include <console.h>
#include <config.h>
#include <kernel/misc.h>
#include <kernel/spinlock.h>
#include <kernel/thread.h>
#include <kernel/virtualization.h>
#include <mm/core_mmu.h>

const char trace_ext_prefix[] = "TC";
int trace_level __nex_data = TRACE_LEVEL;
static unsigned int puts_lock __nex_bss = SPINLOCK_UNLOCK;

/*
 * Atomic flags for sequencing concurrent messages
 * when CFG_CONSOLE_MASK_INTERRUPTS is disabled.
 * itr_trace_busy tracks context always uninterruptible
 * (when thread_is_in_normal_mode() returns false).
 */
static unsigned int thread_trace_busy;
static unsigned int itr_trace_busy;

static unsigned int *get_busy_state(void)
{
	if (thread_is_in_normal_mode())
		return &thread_trace_busy;
	else
		return &itr_trace_busy;
}

static bool wait_if_trace_contended(uint32_t *itr_status)
{
	bool was_contended = false;

	if (IS_ENABLED(CFG_CONSOLE_MASK_INTERRUPTS)) {
		*itr_status = thread_mask_exceptions(THREAD_EXCP_ALL);

		if (cpu_mmu_enabled() && !cpu_spin_trylock(&puts_lock)) {
			was_contended = true;
			cpu_spin_lock_no_dldetect(&puts_lock);
		}
	} else if (cpu_mmu_enabled()) {
		unsigned int trace_not_busy = 0;

		/* Don't mix thread traces, don't mix interrupt traces */
		while (!atomic_cas_uint(get_busy_state(), &trace_not_busy, 1)) {
			trace_not_busy = 0;
			was_contended = true;
		}

		/* Don't emit a thread trace inside an interrupt trace */
		if (thread_is_in_normal_mode())
			while (atomic_load_uint(&itr_trace_busy))
				was_contended = true;
	}

	return was_contended;
}

static void release_trace_contention(uint32_t itr_status)
{
	if (IS_ENABLED(CFG_CONSOLE_MASK_INTERRUPTS)) {
		if (cpu_mmu_enabled())
			cpu_spin_unlock(&puts_lock);

		thread_unmask_exceptions(itr_status);
	} else if (cpu_mmu_enabled()) {
		atomic_store_uint(get_busy_state(), 0);
	}
}

void __weak plat_trace_ext_puts(const char *str __unused)
{
}

void trace_ext_puts(const char *str)
{
	bool was_contended = false;
	uint32_t itr_status = 0;
	const char *p = NULL;

	was_contended = wait_if_trace_contended(&itr_status);

	plat_trace_ext_puts(str);

	console_flush();

	if (was_contended)
		console_putc('*');

	for (p = str; *p; p++)
		console_putc(*p);

	console_flush();

	release_trace_contention(itr_status);
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

int trace_ext_get_guest_id(void)
{
	return virt_get_current_guest_id();
}
