/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) STMicroelectronics 2024 - All Rights Reserved
 */

#ifndef __DRIVERS_STM32MP2_RCC_UTIL_H__
#define __DRIVERS_STM32MP2_RCC_UTIL_H__

#include <drivers/clk.h>
#include <drivers/rstctrl.h>
#include <types_ext.h>

/* Return RCC base address */
vaddr_t stm32_rcc_base(void);

/* Return the clock handle related to a clock DT binding ID */
struct clk *stm32mp_rcc_clock_id_to_clk(unsigned long clock_id);

/* Return rstctrl instance related to RCC reset controller DT binding ID */
struct rstctrl *stm32mp_rcc_reset_id_to_rstctrl(unsigned int binding_id);

#endif /*__DRIVERS_STM32MP2_RCC_UTIL_H__*/
