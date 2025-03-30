// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2023 Andes Technology Corporation
 * Copyright 2022-2023 NXP
 */

#include <assert.h>
#include <compiler.h>
#include <config.h>
#include <console.h>
#include <keep.h>
#include <kernel/boot.h>
#include <kernel/dt.h>
#include <kernel/linker.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <kernel/thread.h>
#include <libfdt.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <mm/tee_mm.h>
#include <mm/tee_pager.h>
#include <platform_config.h>
#include <riscv.h>
#include <sbi.h>
#include <stdio.h>
#include <trace.h>
#include <util.h>

#define PADDR_INVALID               ULONG_MAX

paddr_t start_addr;

uint32_t sem_cpu_sync[CFG_TEE_CORE_NB_CORE];
uint32_t hartids[CFG_TEE_CORE_NB_CORE];

#if defined(CFG_DT)
static int mark_tddram_as_reserved(struct dt_descriptor *dt)
{
	return add_res_mem_dt_node(dt, "optee_core", CFG_TDDRAM_START,
				   CFG_TDDRAM_SIZE);
}

static void update_external_dt(void)
{
	struct dt_descriptor *dt = get_external_dt_desc();

	if (!dt || !dt->blob)
		return;

#ifdef CFG_CORE_RESERVED_SHM
	if (mark_static_shm_as_reserved(dt))
		panic("Failed to config non-secure memory");
#endif

	if (mark_tddram_as_reserved(dt))
		panic("Failed to config secure memory");
}
#else /*CFG_DT*/
static void update_external_dt(void)
{
}
#endif /*!CFG_DT*/

void init_sec_mon(unsigned long nsec_entry __maybe_unused)
{
	assert(nsec_entry == PADDR_INVALID);
	/* Do nothing as we don't have a secure monitor */
}

#ifdef CFG_RISCV_S_MODE
static void start_secondary_cores(void)
{
	uint32_t curr_hartid = thread_get_core_local()->hart_id;
	enum sbi_hsm_hart_state status = 0;
	uint32_t hartid = 0;
	int rc = 0;
	int i = 0;

	/* The primary CPU is always indexed by 0 */
	assert(get_core_pos() == 0);

	for (i = 0; i < CFG_TEE_CORE_NB_CORE; i++) {
		hartid = hartids[i];

		if (hartid == curr_hartid)
			continue;

		rc = sbi_hsm_hart_get_status(hartid, &status);
		/*
		 * Skip if the hartid is not an assigned hart
		 * of the trusted domain, or its HSM state is
		 * not stopped.
		 */
		if (rc || status != SBI_HSM_STATE_STOPPED)
			continue;

		DMSG("Bringing up secondary hart%"PRIu32, hartid);

		rc = sbi_hsm_hart_start(hartid, start_addr, 0 /* unused */);
		if (rc) {
			EMSG("Error starting secondary hart%"PRIu32, hartid);
			panic();
		}
	}
}
#endif

void init_tee_runtime(void)
{
	call_preinitcalls();
	call_early_initcalls();
	call_service_initcalls();

	/* Reinitialize canaries around the stacks with crypto_rng_read(). */
	thread_update_canaries();
}

static bool add_padding_to_pool(vaddr_t va, size_t len, void *ptr __unused)
{
	malloc_add_pool((void *)va, len);
	return true;
}

static void init_primary(unsigned long nsec_entry)
{
	vaddr_t va __maybe_unused = 0;

	thread_init_core_local_stacks();

	/*
	 * Mask asynchronous exceptions before switch to the thread vector
	 * as the thread handler requires those to be masked while
	 * executing with the temporary stack. The thread subsystem also
	 * asserts that the foreign interrupts are blocked when using most of
	 * its functions.
	 */
	thread_set_exceptions(THREAD_EXCP_ALL);

	malloc_add_pool(__heap1_start, __heap1_end - __heap1_start);
	IMSG_RAW("\n");

	core_mmu_save_mem_map();
	core_mmu_init_phys_mem();
	boot_mem_foreach_padding(add_padding_to_pool, NULL);
	va = boot_mem_release_unused();

	thread_init_boot_thread();
	thread_init_primary();
	thread_init_per_cpu();
	init_sec_mon(nsec_entry);
}

/* May be overridden in plat-$(PLATFORM)/main.c */
__weak void plat_primary_init_early(void)
{
}

/* May be overridden in plat-$(PLATFORM)/main.c */
__weak void boot_primary_init_intc(void)
{
}

/* May be overridden in plat-$(PLATFORM)/main.c */
__weak void boot_primary_init_core_ids(void)
{
#ifdef CFG_DT
	const void *fdt = get_external_dt();
	const fdt32_t *reg = NULL;
	int cpu_offset = 0;
	int offset = 0;
	int len = 0;
	int i = 0;

	offset = fdt_path_offset(fdt, "/cpus");
	if (offset < 0)
		panic("Failed to find /cpus node in the device tree");

	fdt_for_each_subnode(cpu_offset, fdt, offset) {
		/*
		 * Assume all TEE cores are enabled. The "reg"
		 * property in the CPU node indicates the hart ID.
		 */
		if (fdt_get_status(fdt, cpu_offset) == DT_STATUS_DISABLED)
			continue;

		reg = fdt_getprop(fdt, cpu_offset, "reg", &len);
		if (!reg) {
			EMSG("CPU node does not have 'reg' property");
			continue;
		}

		assert(i < CFG_TEE_CORE_NB_CORE);
		hartids[i++] = fdt32_to_cpu(*reg);
	}

	assert(i == CFG_TEE_CORE_NB_CORE);
#endif
}

/* May be overridden in plat-$(PLATFORM)/main.c */
__weak void boot_secondary_init_intc(void)
{
}

void boot_init_primary_early(void)
{
	unsigned long e = PADDR_INVALID;

	init_primary(e);
}

void boot_init_primary_late(unsigned long fdt,
			    unsigned long tos_fw_config __unused)
{
	size_t pos = get_core_pos();

	/* The primary CPU is always indexed by 0 */
	assert(pos == 0);

	init_external_dt(fdt, CFG_DTB_MAX_SIZE);
	discover_nsec_memory();
	update_external_dt();

	IMSG("OP-TEE version: %s", core_v_str);
	if (IS_ENABLED(CFG_INSECURE)) {
		IMSG("WARNING: This OP-TEE configuration might be insecure!");
		IMSG("WARNING: Please check https://optee.readthedocs.io/en/latest/architecture/porting_guidelines.html");
	}
	IMSG("Primary CPU0 (hart%"PRIu32") initializing",
	     thread_get_hartid_by_hartindex(pos));
	boot_primary_init_intc();
	boot_primary_init_core_ids();
	init_tee_runtime();
}

void __weak boot_init_primary_final(void)
{
	size_t pos = get_core_pos();

	boot_mem_release_tmp_alloc();

	call_driver_initcalls();
	call_finalcalls();
	IMSG("Primary CPU0 (hart%"PRIu32") initialized",
	     thread_get_hartid_by_hartindex(pos));

#ifdef CFG_RISCV_S_MODE
	start_secondary_cores();
#endif
}

static void init_secondary_helper(unsigned long nsec_entry)
{
	size_t pos = get_core_pos();

	IMSG("Secondary CPU%zu (hart%"PRIu32") initializing",
	     pos, thread_get_hartid_by_hartindex(pos));

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
	boot_secondary_init_intc();

	IMSG("Secondary CPU%zu (hart%"PRIu32") initialized",
	     pos, thread_get_hartid_by_hartindex(pos));
}

void boot_init_secondary(unsigned long nsec_entry __unused)
{
	init_secondary_helper(PADDR_INVALID);
}
