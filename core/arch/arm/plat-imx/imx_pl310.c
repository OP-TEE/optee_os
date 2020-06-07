// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2016 Freescale Semiconductor, Inc.
 *
 * Peng Fan <peng.fan@nxp.com>
 */

#include <arm32.h>
#include <io.h>
#include <kernel/boot.h>
#include <kernel/tz_ssvce_def.h>
#include <kernel/tz_ssvce_pl310.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <sm/optee_smc.h>
#include <platform_config.h>
#include <stdint.h>
#include "imx_pl310.h"

#define PL310_AUX_CTRL_FLZW			BIT(0)
#define PL310_DEBUG_CTRL_DISABLE_WRITEBACK	BIT(1)
#define PL310_DEBUG_CTRL_DISABLE_LINEFILL	BIT(0)

register_phys_mem_pgdir(MEM_AREA_IO_SEC, PL310_BASE, CORE_MMU_PGDIR_SIZE);

void arm_cl2_config(vaddr_t pl310_base)
{
	/* Disable PL310 */
	io_write32(pl310_base + PL310_CTRL, 0);

	io_write32(pl310_base + PL310_TAG_RAM_CTRL, PL310_TAG_RAM_CTRL_INIT);
	io_write32(pl310_base + PL310_DATA_RAM_CTRL, PL310_DATA_RAM_CTRL_INIT);
	io_write32(pl310_base + PL310_AUX_CTRL, PL310_AUX_CTRL_INIT);
	io_write32(pl310_base + PL310_PREFETCH_CTRL, PL310_PREFETCH_CTRL_INIT);
	io_write32(pl310_base + PL310_POWER_CTRL, PL310_POWER_CTRL_INIT);

	/* invalidate all cache ways */
	arm_cl2_invbyway(pl310_base);
}

void arm_cl2_enable(vaddr_t pl310_base)
{
	uint32_t val __maybe_unused;

	/* Enable PL310 ctrl -> only set lsb bit */
	io_write32(pl310_base + PL310_CTRL, 1);

#ifndef CFG_PL310_SIP_PROTOCOL
	/* if L2 FLZW enable, enable in L1 */
	val = io_read32(pl310_base + PL310_AUX_CTRL);
	if (val & PL310_AUX_CTRL_FLZW)
		write_actlr(read_actlr() | ACTLR_CA9_WFLZ);
#endif
}

vaddr_t pl310_base(void)
{
	return core_mmu_get_va(PL310_BASE, MEM_AREA_IO_SEC);
}

#ifdef CFG_PL310_SIP_PROTOCOL
uint32_t pl310_enable(void)
{
	vaddr_t base = pl310_base();

	arm_cl2_config(base);
	arm_cl2_enable(base);
	return OPTEE_SMC_RETURN_OK;
}

uint32_t pl310_disable(void)
{
	EMSG("not implemented");
	return OPTEE_SMC_RETURN_ENOTAVAIL;
}

uint32_t pl310_enable_writeback(void)
{
	vaddr_t base = pl310_base();

	io_write32(base + PL310_DEBUG_CTRL, 0);
	return OPTEE_SMC_RETURN_OK;
}

uint32_t pl310_disable_writeback(void)
{
	vaddr_t base = pl310_base();
	uint32_t val = PL310_DEBUG_CTRL_DISABLE_WRITEBACK |
		       PL310_DEBUG_CTRL_DISABLE_LINEFILL;

	io_write32(base + PL310_DEBUG_CTRL, val);
	return OPTEE_SMC_RETURN_OK;
}

uint32_t pl310_enable_wflz(void)
{
	write_actlr(read_actlr() | ACTLR_CA9_WFLZ);
	return OPTEE_SMC_RETURN_OK;
}
#endif
