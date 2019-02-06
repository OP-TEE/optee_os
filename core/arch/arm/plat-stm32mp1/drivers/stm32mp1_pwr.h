/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2018-2019, STMicroelectronics
 */

#ifndef __STM32MP1_PWR_H
#define __STM32MP1_PWR_H

#include <util.h>

#define PWR_CR1_OFF		0x00
#define PWR_CR2_OFF		0x08
#define PWR_CR3_OFF		0x0c
#define PWR_MPUCR_OFF		0x10
#define PWR_WKUPCR_OFF		0x20
#define PWR_MPUWKUPENR_OFF	0x28

#define PWR_OFFSET_MASK		0x3fUL

uintptr_t stm32_pwr_base(void);

#endif /*__STM32MP1_PWR_H*/
