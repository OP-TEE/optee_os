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
#include <sbi.h>
#include <stdio.h>
#include <trace.h>
#include <util.h>

#include <platform_config.h>

#define PADDR_INVALID               ULONG_MAX

unsigned long _start_addr;

uint32_t sem_cpu_sync[CFG_TEE_CORE_NB_CORE];

void init_sec_mon(unsigned long nsec_entry __maybe_unused)
{
	assert(nsec_entry == PADDR_INVALID);
	/* Do nothing as we don't have a secure monitor */
}

#ifdef CFG_RISCV_S_MODE
static void start_secondary_cores(void)
{
	int ret;
	uint32_t i;
	size_t pos = get_core_pos();

	for (i = 0; i < CFG_TEE_CORE_NB_CORE; i++) {
		if (i != pos) {
#ifdef CFG_RISCV_SBI
			ret = sbi_boot_hart(i, _start_addr, (unsigned long)i);
#else
			ret = -1;
#endif /*CFG_RISCV_SBI*/
			if (ret != 0)
				EMSG("Error starting secondary hart %u", i);
		}
	}
}
#endif

static void init_primary(unsigned long pageable_part __unused,
			 unsigned long nsec_entry)
{
	/*
	 * Mask asynchronous exceptions before switch to the thread vector
	 * as the thread handler requires those to be masked while
	 * executing with the temporary stack. The thread subsystem also
	 * asserts that the foreign interrupts are blocked when using most of
	 * its functions.
	 */
	thread_set_exceptions(THREAD_EXCP_ALL);

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

/* May be overridden in plat-$(PLATFORM)/main.c */
__weak void main_init_plic(void)
{
}

/* May be overridden in plat-$(PLATFORM)/main.c */
__weak void main_secondary_init_plic(void)
{
}

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
	main_init_plic();
	IMSG("Primary CPU switching to REE boot");

#ifdef CFG_RISCV_S_MODE
	start_secondary_cores();
#endif
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
	main_secondary_init_plic();

	IMSG("Secondary CPU %zu switching to REE boot", pos);
}

void boot_init_secondary(unsigned long nsec_entry __unused)
{
	init_secondary_helper(PADDR_INVALID);
}
