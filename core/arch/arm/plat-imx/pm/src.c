// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2019, 2023 NXP
 */

#include <imx.h>
#include <io.h>
#include <mm/core_mmu.h>
#include <mm/core_memprot.h>

#include "local.h"

#define SRC_SCR		0x000
#define SRC_A7RCR0	0x004
#define SRC_A7RCR1	0x008
#if defined(CFG_MX7)
#define SRC_GPR1	0x074
#else
#define SRC_GPR1	0x020
#endif

#define SRC_SCR_CORE1_RST_BIT(_cpu)		BIT32(14 + (_cpu) - 1)
#define SRC_SCR_CORE1_ENABLE_BIT(_cpu)		BIT32(22 + (_cpu) - 1)
#define SRC_A7RCR0_A7_CORE_RESET0_BIT(_cpu)	BIT32((_cpu) - 1)
#define SRC_A7RCR1_A7_CORE1_ENABLE_BIT(_cpu)	BIT32(1  + (_cpu) - 1)

#define ENTRY_OFFSET(_cpu)	((_cpu) * 8)
#define ARG_OFFSET(_cpu)	(ENTRY_OFFSET(_cpu) + 4)

register_phys_mem(MEM_AREA_IO_SEC, SRC_BASE, SRC_SIZE);

uint32_t imx_get_src_gpr_arg(unsigned int cpu)
{
	vaddr_t va = core_mmu_get_va(SRC_BASE, MEM_AREA_IO_SEC, SRC_SIZE);

	return io_read32(va + SRC_GPR1 + ARG_OFFSET(cpu));
}

void imx_set_src_gpr_arg(unsigned int cpu, uint32_t val)
{
	vaddr_t va = core_mmu_get_va(SRC_BASE, MEM_AREA_IO_SEC, SRC_SIZE);

	io_write32(va + SRC_GPR1 + ARG_OFFSET(cpu), val);
}

uint32_t imx_get_src_gpr_entry(unsigned int cpu)
{
	vaddr_t va = core_mmu_get_va(SRC_BASE, MEM_AREA_IO_SEC, SRC_SIZE);

	return io_read32(va + SRC_GPR1 + ENTRY_OFFSET(cpu));
}

void imx_set_src_gpr_entry(unsigned int cpu, uint32_t val)
{
	vaddr_t va = core_mmu_get_va(SRC_BASE, MEM_AREA_IO_SEC, SRC_SIZE);

	io_write32(va + SRC_GPR1 + ENTRY_OFFSET(cpu), val);
}

void imx_src_release_secondary_core(unsigned int cpu)
{
	vaddr_t va = core_mmu_get_va(SRC_BASE, MEM_AREA_IO_SEC, SRC_SIZE);

	if (soc_is_imx7ds())
		io_setbits32(va + SRC_A7RCR1,
			     SRC_A7RCR1_A7_CORE1_ENABLE_BIT(cpu));
	else
		io_setbits32(va + SRC_SCR, SRC_SCR_CORE1_ENABLE_BIT(cpu) |
					   SRC_SCR_CORE1_RST_BIT(cpu));
}

void imx_src_shutdown_core(unsigned int cpu)
{
	vaddr_t va = core_mmu_get_va(SRC_BASE, MEM_AREA_IO_SEC, SRC_SIZE);

	if (soc_is_imx7ds()) {
		io_clrbits32(va + SRC_A7RCR1,
			     SRC_A7RCR1_A7_CORE1_ENABLE_BIT(cpu));
	} else {
		uint32_t mask = io_read32(va + SRC_SCR);

		mask &= ~SRC_SCR_CORE1_ENABLE_BIT(cpu);
		mask |= SRC_SCR_CORE1_RST_BIT(cpu);
		io_write32(va + SRC_SCR, mask);
	}
}
