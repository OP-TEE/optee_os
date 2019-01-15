// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2017-2018, STMicroelectronics
 */

#include <drivers/stm32mp1_clk.h>

unsigned long stm32_clock_get_rate(unsigned long id)
{
	return stm32mp1_clk_get_rate(id);
}

bool stm32_clock_is_enabled(unsigned long id)
{
	return stm32mp1_clk_is_enabled(id);
}

void stm32_clock_enable(unsigned long id)
{
	stm32mp1_clk_enable(id);
}

void stm32_clock_disable(unsigned long id)
{
	stm32mp1_clk_disable(id);
}
