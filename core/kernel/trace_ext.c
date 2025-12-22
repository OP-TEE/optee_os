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
#include <kernel/virtualization.h>
#include <mm/core_mmu.h>

const char trace_ext_prefix[] = "TC";
int trace_level __nex_data = TRACE_LEVEL;

void __weak plat_trace_ext_puts(const char *str __unused)
{
}

void trace_ext_puts(const char *str)
{
	const char *p;

	plat_trace_ext_puts(str);

	console_flush();

	for (p = str; *p; p++)
		console_putc(*p);

	console_flush();
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
