// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2019 NXP
 */

#include <imx.h>
#include <io.h>
#include <mm/core_mmu.h>
#include <mm/core_memprot.h>

uint32_t imx_get_src_gpr(int cpu)
{
	vaddr_t va = core_mmu_get_va(SRC_BASE, MEM_AREA_IO_SEC, 1);

	if (soc_is_imx7ds())
		return io_read32(va + SRC_GPR1_MX7 + cpu * 8 + 4);
	else
		return io_read32(va + SRC_GPR1 + cpu * 8 + 4);
}

void imx_set_src_gpr(int cpu, uint32_t val)
{
	vaddr_t va = core_mmu_get_va(SRC_BASE, MEM_AREA_IO_SEC, 1);

	if (soc_is_imx7ds())
		io_write32(va + SRC_GPR1_MX7 + cpu * 8 + 4, val);
	else
		io_write32(va + SRC_GPR1 + cpu * 8 + 4, val);
}
