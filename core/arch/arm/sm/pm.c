// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2017 NXP
 *
 * Peng Fan <peng.fan@nxp.com>
 */

#include <arm32.h>
#include <console.h>
#include <drivers/imx_uart.h>
#include <io.h>
#include <kernel/cache_helpers.h>
#include <kernel/boot.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <kernel/thread.h>
#include <kernel/tlb_helpers.h>
#include <kernel/tz_ssvce_pl310.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <sm/optee_smc.h>
#include <sm/pm.h>
#include <sm/psci.h>
#include <sm/sm.h>
#include <stdint.h>

#if CFG_TEE_CORE_NB_CORE > 4
#error "Max support 4 cores in one cluster now"
#endif

void sm_pm_cpu_suspend_save(struct sm_pm_ctx *ctx, uint32_t sp)
{
	struct thread_core_local *p = thread_get_core_local();

	p->sm_pm_ctx_phys = virt_to_phys((void *)ctx);

	/* The content will be passed to sm_pm_cpu_do_resume as register sp */
	ctx->sp = sp;
	ctx->cpu_resume_addr =
		virt_to_phys((void *)(vaddr_t)sm_pm_cpu_do_resume);

	sm_pm_cpu_do_suspend(ctx->suspend_regs);

	dcache_op_level1(DCACHE_OP_CLEAN_INV);

#ifdef CFG_PL310
	arm_cl2_cleanbyway(core_mmu_get_va(PL310_BASE, MEM_AREA_IO_SEC, 1));
#endif
}
