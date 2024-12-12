/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2022-2024, STMicroelectronics
 */

#ifndef __DRIVERS_STM32_STGEN_H
#define __DRIVERS_STM32_STGEN_H

#include <stdint.h>

/* Return the STGEN counter value */
uint64_t stm32_stgen_get_counter_value(void);

#endif /* __DRIVERS_STM32_STGEN_H */
