// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2017 NXP
 *
 * Peng Fan <peng.fan@nxp.com>
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

#include <arm32.h>
#include <console.h>
#include <drivers/imx_uart.h>
#include <io.h>
#include <kernel/cache_helpers.h>
#include <kernel/generic_boot.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <kernel/pm_stubs.h>
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
	arm_cl2_cleanbyway(core_mmu_get_va(PL310_BASE, MEM_AREA_IO_SEC));
#endif
}
