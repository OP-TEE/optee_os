// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2018-2019, STMicroelectronics
 */

#include <mm/core_memprot.h>
#include <platform_config.h>
#include <drivers/stm32mp1_pwr.h>

vaddr_t stm32_pwr_base(void)
{
	static struct io_pa_va base = { .pa = PWR_BASE };

	return io_pa_or_va(&base);
}
