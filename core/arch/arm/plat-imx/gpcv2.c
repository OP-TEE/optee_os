// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2017-2018 NXP
 *
 */

#include <imx.h>
#include <io.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <stdint.h>

static vaddr_t gpc_base(void)
{
	return core_mmu_get_va(GPC_BASE, MEM_AREA_IO_SEC);
}

static void imx_gpcv2_set_core_pgc(bool enable, uint32_t offset)
{
	uint32_t val = read32(gpc_base() + offset) & (~BM_GPC_PGC_nCTRL_PCR);

	if (enable) {
		val |= BM_GPC_PGC_nCTRL_PCR;
	}

	write32(val, gpc_base() + offset);
}

void imx_gpcv2_set_core1_pup_by_software(void)
{
	uint32_t val = read32(gpc_base() + GPC_CPU_PGC_SW_PUP_REQ);

	imx_gpcv2_set_core_pgc(true, GPC_PGC_A7CORE1_CTRL);

	val |= BM_GPC_CPU_PGC_SW_PUP_REQ_CORE1_A7_SW_PUP_REQ;

	write32(val, gpc_base() + GPC_CPU_PGC_SW_PUP_REQ);

	while ((read32(gpc_base() + GPC_CPU_PGC_SW_PUP_STATUS) &
	       BM_GPC_CPU_PGC_SW_PUP_STATUS_CORE1_A7_SW_PUP_STATUS) != 0) {
	}

	imx_gpcv2_set_core_pgc(false, GPC_PGC_A7CORE1_CTRL);
}

