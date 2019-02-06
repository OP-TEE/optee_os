// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2018-2019, STMicroelectronics
 */

#include <mm/core_memprot.h>
#include <platform_config.h>
#include <drivers/stm32mp1_pwr.h>

uintptr_t stm32_pwr_base(void)
{
	static void *va;

	if (!cpu_mmu_enabled())
		return PWR_BASE;

	if (!va)
		va = phys_to_virt(PWR_BASE, MEM_AREA_IO_SEC);

	return (uintptr_t)va;
}
