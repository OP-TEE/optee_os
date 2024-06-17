/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) STMicroelectronics 2024 - All Rights Reserved
 */

#ifndef __DRIVERS_STM32MP2_RCC_UTIL_H__
#define __DRIVERS_STM32MP2_RCC_UTIL_H__

#include <drivers/clk.h>
#include <types_ext.h>

/* Return RCC base address */
vaddr_t stm32_rcc_base(void);

/* Return the clock handle related to a clock DT binding ID */
struct clk *stm32mp_rcc_clock_id_to_clk(unsigned long clock_id);

#endif /*__DRIVERS_STM32MP2_RCC_UTIL_H__*/
