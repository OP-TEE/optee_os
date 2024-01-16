/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2021-2023, STMicroelectronics
 */

#ifndef __DRIVERS_STM32MP13_REGULATOR_IOD_H
#define __DRIVERS_STM32MP13_REGULATOR_IOD_H

#include <drivers/regulator.h>

enum iod_regulator_id {
	IOD_SDMMC1,
	IOD_SDMMC2,
	IOD_REGU_COUNT
};

#ifdef CFG_STM32MP13_REGULATOR_IOD
struct regulator *stm32mp1_get_iod_regulator(enum iod_regulator_id index);
#else
static inline struct regulator *
stm32mp1_get_iod_regulator(enum iod_regulator_id id __unused) { return NULL; }
#endif /* CFG_STM32MP13_REGULATOR_IOD */
#endif /* __DRIVERS_STM32MP13_REGULATOR_IOD_H */
