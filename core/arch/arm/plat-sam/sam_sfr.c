// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2017 Timesys Corporation.
 * Copyright (C) 2021 Microchip
 * All rights reserved.
 */

#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <sam_sfr.h>
#include <sama5d2.h>
#include <types_ext.h>

register_phys_mem_pgdir(MEM_AREA_IO_SEC, SFR_BASE, CORE_MMU_PGDIR_SIZE);

vaddr_t sam_sfr_base(void)
{
	static void *va;

	if (cpu_mmu_enabled()) {
		if (!va)
			va = phys_to_virt(SFR_BASE, MEM_AREA_IO_SEC, 1);
		return (vaddr_t)va;
	}
	return SFR_BASE;
}
