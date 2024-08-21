// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2017 Timesys Corporation.
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

#include <io.h>
#include <kernel/boot.h>
#include <kernel/tz_ssvce_pl310.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <sama5d2.h>
#include <sam_sfr.h>
#include <sam_pl310.h>
#include <sm/optee_smc.h>
#include <types_ext.h>

/* L2 Cache Controller (L2CC) */
#define L2CC_DCR_DWB	BIT(1) /* Disable Write-back, Force Write-through */
#define L2CC_DCR_DCL	BIT(0) /* Disable Cache Linefill */

register_phys_mem_pgdir(MEM_AREA_IO_SEC, PL310_BASE, CORE_MMU_PGDIR_SIZE);

vaddr_t pl310_base(void)
{
	static void *va;

	if (cpu_mmu_enabled()) {
		if (!va)
			va = phys_to_virt(PL310_BASE, MEM_AREA_IO_SEC, 1);
		return (vaddr_t)va;
	}
	return PL310_BASE;
}

void arm_cl2_config(vaddr_t pl310_base)
{
	io_write32(pl310_base + PL310_CTRL, 0);
	io_write32(sam_sfr_base() + AT91_SFR_L2CC_HRAMC, 0x1);
	io_write32(pl310_base + PL310_AUX_CTRL, PL310_AUX_CTRL_INIT);
	io_write32(pl310_base + PL310_PREFETCH_CTRL, PL310_PREFETCH_CTRL_INIT);
	io_write32(pl310_base + PL310_POWER_CTRL, PL310_POWER_CTRL_INIT);

	/* invalidate all cache ways */
	arm_cl2_invbyway(pl310_base);
}

void arm_cl2_enable(vaddr_t pl310_base)
{
	/* Enable PL310 ctrl -> only set lsb bit */
	io_write32(pl310_base + PL310_CTRL, 1);
}

#ifdef CFG_PL310_SIP_PROTOCOL
TEE_Result pl310_enable(void)
{
	vaddr_t base = pl310_base();

	arm_cl2_config(base);
	arm_cl2_enable(base);

	return OPTEE_SMC_RETURN_OK;
}

TEE_Result pl310_disable(void)
{
	EMSG("not implemented");

	return OPTEE_SMC_RETURN_ENOTAVAIL;
}

TEE_Result pl310_enable_writeback(void)
{
	vaddr_t base = pl310_base();

	io_write32(base + PL310_DEBUG_CTRL, 0);

	return OPTEE_SMC_RETURN_OK;
}

TEE_Result pl310_disable_writeback(void)
{
	uint32_t val = L2CC_DCR_DWB | L2CC_DCR_DCL;
	vaddr_t base = pl310_base();

	io_write32(base + PL310_DEBUG_CTRL, val);

	return OPTEE_SMC_RETURN_OK;
}
#endif
