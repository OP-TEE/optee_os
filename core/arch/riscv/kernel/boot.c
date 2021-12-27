// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015-2021, Linaro Limited
 * Copyright 2022 NXP
 */

#include <assert.h>
#include <compiler.h>
#include <config.h>
#include <console.h>
#include <keep.h>
#include <kernel/boot.h>
#include <kernel/linker.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <kernel/thread.h>
#include <riscv.h>
#include <stdio.h>
#include <trace.h>
#include <util.h>

#include <platform_config.h>

#define PADDR_INVALID               ULONG_MAX

uint32_t sem_cpu_sync[CFG_TEE_CORE_NB_CORE];

static void init_runtime(unsigned long pageable_part __unused)
{
}

void init_sec_mon(unsigned long nsec_entry __maybe_unused)
{
	assert(nsec_entry == PADDR_INVALID);
	/* Do nothing as we don't have a secure monitor */
}

static void init_primary(unsigned long pageable_part, unsigned long nsec_entry)
{
	/*
	 * Mask asynchronous exceptions before switch to the thread vector
	 * as the thread handler requires those to be masked while
	 * executing with the temporary stack. The thread subsystem also
	 * asserts that the foreign interrupts are blocked when using most of
	 * its functions.
	 */
	thread_set_exceptions(THREAD_EXCP_ALL);

	/*
	 * Pager: init_runtime() calls thread_kernel_enable_vfp() so we must
	 * set a current thread right now to avoid a chicken-and-egg problem
	 * (thread_init_boot_thread() sets the current thread but needs
	 * things set by init_runtime()).
	 */
	thread_get_core_local()->curr_thread = 0;
	init_runtime(pageable_part);

	if (IS_ENABLED(CFG_VIRTUALIZATION)) {
		/*
		 * Virtualization: We can't initialize threads right now because
		 * threads belong to "tee" part and will be initialized
		 * separately per each new virtual guest. So, we'll clear
		 * "curr_thread" and call it done.
		 */
		thread_get_core_local()->curr_thread = -1;
	} else {
		thread_init_boot_thread();
	}
	thread_init_primary();
	thread_init_per_cpu();
	init_sec_mon(nsec_entry);
}

/* May be overridden in plat-$(PLATFORM)/main.c */
__weak void plat_primary_init_early(void)
{
}
DECLARE_KEEP_PAGER(plat_primary_init_early);

/*
 * Note: this function is weak just to make it possible to exclude it from
 * the unpaged area so that it lies in the init area.
 */
void __weak boot_init_primary_early(unsigned long pageable_part __unused,
				    unsigned long nsec_entry __unused)
{
	unsigned long e = PADDR_INVALID;

	init_primary(pageable_part, e);
}

/*
 * Note: this function is weak just to make it possible to exclude it from
 * the unpaged area.
 */
void __weak boot_init_primary_late(unsigned long fdt __unused)
{
	IMSG("OP-TEE version: %s", core_v_str);
	if (IS_ENABLED(CFG_WARN_INSECURE)) {
		IMSG("WARNING: This OP-TEE configuration might be insecure!");
		IMSG("WARNING: Please check https://optee.readthedocs.io/en/latest/architecture/porting_guidelines.html");
	}
	IMSG("Primary CPU initializing");
	IMSG("Primary CPU switching to REE boot");
}

static void init_secondary_helper(unsigned long nsec_entry)
{
	size_t pos = get_core_pos();

	IMSG("Secondary CPU %zu initializing", pos);

	/*
	 * Mask asynchronous exceptions before switch to the thread vector
	 * as the thread handler requires those to be masked while
	 * executing with the temporary stack. The thread subsystem also
	 * asserts that the foreign interrupts are blocked when using most of
	 * its functions.
	 */
	thread_set_exceptions(THREAD_EXCP_ALL);

	thread_init_per_cpu();
	init_sec_mon(nsec_entry);

	IMSG("Secondary CPU %zu switching to REE boot", pos);
}

void boot_init_secondary(unsigned long nsec_entry __unused)
{
	init_secondary_helper(PADDR_INVALID);
}
