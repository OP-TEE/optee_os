// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2017 Texas Instruments Incorporated - http://www.ti.com/
 *	Andrew Davis <afd@ti.com>
 */

#include <arm32.h>
#include <io.h>
#include <kernel/boot.h>
#include <kernel/tz_ssvce_def.h>
#include <kernel/tz_ssvce_pl310.h>
#include <mm/core_memprot.h>
#include <platform_config.h>

register_phys_mem_pgdir(MEM_AREA_IO_SEC, PL310_BASE, PL310_SIZE);

vaddr_t pl310_base(void)
{
	static void *va;

	if (cpu_mmu_enabled()) {
		if (!va)
			va = phys_to_virt(PL310_BASE, MEM_AREA_IO_SEC,
					  PL310_SIZE);
		return (vaddr_t)va;
	}

	return PL310_BASE;
}

/* ROM handles initial setup for us */
void arm_cl2_config(vaddr_t pl310_base)
{
	(void)pl310_base;
}

/* We provide platform services that expect the cache to be disabled on boot */
void arm_cl2_enable(vaddr_t pl310_base)
{
	(void)pl310_base;
}
