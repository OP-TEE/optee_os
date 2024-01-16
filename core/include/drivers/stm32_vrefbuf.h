/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2023, STMicroelectronics
 */
#ifndef DRIVERS_STM32_VREFBUF_H
#define DRIVERS_STM32_VREFBUF_H

#include <drivers/regulator.h>

#ifdef CFG_STM32_VREFBUF
/* Return VREFBUF regulator handler if registered */
struct regulator *stm32_vrefbuf_regulator(void);
#else
static inline struct regulator *stm32_vrefbuf_regulator(void)
{
	return NULL;
}
#endif

#endif /*DRIVERS_STM32_VREFBUF_H*/
