/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (C) 2018-2019, STMicroelectronics
 */

#ifndef __STM32MP1_CLK_H
#define __STM32MP1_CLK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum stm32mp_osc_id {
	_HSI = 0,
	_HSE,
	_CSI,
	_LSI,
	_LSE,
	_I2S_CKIN,
	_USB_PHY_48,
	NB_OSC,
	_UNKNOWN_OSC_ID = 0xffU
};

/*
 * Enable target clock with reference counting
 * @id: Target clock (see stm32mp1 clock bindings IDs)
 */
void stm32mp1_clk_enable(unsigned long id);

/*
 * Disable target clock with reference counting
 * @id: Target clock (see stm32mp1 clock bindings IDs)
 */
void stm32mp1_clk_disable(unsigned long id);

/*
 * Return whether target clock is enabled or not
 * @id: Target clock (see stm32mp1 clock bindings IDs)
 */
bool stm32mp1_clk_is_enabled(unsigned long id);

/*
 * Get target clock frequency
 * @id: Target clock (see stm32mp1 clock bindings IDs)
 * Return the frequency in Hertz
 */
unsigned long stm32mp1_clk_get_rate(unsigned long id);

#endif /*__STM32MP1_CLK_H*/
