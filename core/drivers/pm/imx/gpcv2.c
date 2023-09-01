// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2017, 2023 NXP
 *
 * Peng Fan <peng.fan@nxp.com>
 */

#include <io.h>
#include <kernel/delay_arch.h>
#include <mm/core_memprot.h>

#include "local.h"

#define GPC_PGC_C1			0x840
#define GPC_PGC_PCG_MASK		BIT(0)

#define GPC_CPU_PGC_SW_PUP_REQ		0xf0
#define GPC_PU_PGC_SW_PUP_REQ		0xf8
#define GPC_CPU_PGC_SW_PDN_REQ		0xfc
#define GPC_PU_PGC_SW_PDN_REQ		0x104
#define GPC_PGC_SW_PDN_PUP_REQ_CORE1_MASK BIT(1)

static void imx_gpcv2_set_core_pgc(bool enable, uint32_t offset)
{
	vaddr_t va = core_mmu_get_va(GPC_BASE, MEM_AREA_IO_SEC, GPC_SIZE);

	if (enable)
		io_setbits32(va + offset, GPC_PGC_PCG_MASK);
	else
		io_clrbits32(va + offset, GPC_PGC_PCG_MASK);
}

void imx_gpcv2_set_core1_pup_by_software(void)
{
	vaddr_t va = core_mmu_get_va(GPC_BASE, MEM_AREA_IO_SEC, GPC_SIZE);
	uint64_t timeout = timeout_init_us(10 * 1000);

	imx_gpcv2_set_core_pgc(true, GPC_PGC_C1);

	io_setbits32(va + GPC_CPU_PGC_SW_PUP_REQ,
		     GPC_PGC_SW_PDN_PUP_REQ_CORE1_MASK);

	while ((io_read32(va + GPC_CPU_PGC_SW_PUP_REQ) &
		GPC_PGC_SW_PDN_PUP_REQ_CORE1_MASK)) {
		if (timeout_elapsed(timeout))
			return;
	}

	imx_gpcv2_set_core_pgc(false, GPC_PGC_C1);
}
