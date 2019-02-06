// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2018, STMicroelectronics
 */

#include <drivers/stm32mp1_rcc.h>
#include <mm/core_memprot.h>
#include <platform_config.h>

uintptr_t stm32_rcc_base(void)
{
	static struct io_pa_va base = { .pa = RCC_BASE };

	return io_pa_or_va(&base);
}
