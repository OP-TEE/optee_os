// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2017 NXP
 *
 * Peng Fan <peng.fan@nxp.com>
 */

#include <imx.h>
#include <io.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <stdint.h>

#define GPC_PGC_C1			0x840
#define GPC_PGC_C1_PUPSCR		0x844
#define GPC_PGC_PCG_MASK		BIT(0)

#define GPC_CPU_PGC_SW_PUP_REQ		0xf0
#define GPC_PU_PGC_SW_PUP_REQ		0xf8
#define GPC_CPU_PGC_SW_PDN_REQ		0xfc
#define GPC_PU_PGC_SW_PDN_REQ		0x104
#define GPC_PGC_SW_PDN_PUP_REQ_CORE1_MASK BIT(1)

static vaddr_t gpc_base(void)
{
	return core_mmu_get_va(GPC_BASE, MEM_AREA_IO_SEC, 1);
}

static void imx_gpcv2_set_core_pgc(bool enable, uint32_t offset)
{
	uint32_t val = io_read32(gpc_base() + offset) & (~GPC_PGC_PCG_MASK);

	if (enable)
		val |= GPC_PGC_PCG_MASK;

	io_write32(gpc_base() + offset, val);
}

void imx_gpcv2_set_core1_pdn_by_software(void)
{
	uint32_t val = io_read32(gpc_base() + GPC_CPU_PGC_SW_PDN_REQ);

	imx_gpcv2_set_core_pgc(true, GPC_PGC_C1);

	val |= GPC_PGC_SW_PDN_PUP_REQ_CORE1_MASK;

	io_write32(gpc_base() + GPC_CPU_PGC_SW_PDN_REQ, val);

	while ((io_read32(gpc_base() + GPC_CPU_PGC_SW_PDN_REQ) &
	       GPC_PGC_SW_PDN_PUP_REQ_CORE1_MASK) != 0)
		;

	imx_gpcv2_set_core_pgc(false, GPC_PGC_C1);
}

void imx_gpcv2_set_core1_pup_by_software(void)
{
	uint32_t val = io_read32(gpc_base() + GPC_CPU_PGC_SW_PUP_REQ);

	imx_gpcv2_set_core_pgc(true, GPC_PGC_C1);

	val |= GPC_PGC_SW_PDN_PUP_REQ_CORE1_MASK;

	io_write32(gpc_base() + GPC_CPU_PGC_SW_PUP_REQ, val);

	while ((io_read32(gpc_base() + GPC_CPU_PGC_SW_PUP_REQ) &
	       GPC_PGC_SW_PDN_PUP_REQ_CORE1_MASK) != 0)
		;

	imx_gpcv2_set_core_pgc(false, GPC_PGC_C1);
}
