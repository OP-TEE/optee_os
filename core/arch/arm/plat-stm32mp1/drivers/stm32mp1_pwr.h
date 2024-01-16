/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2018-2023, STMicroelectronics
 */

#ifndef __STM32MP1_PWR_H
#define __STM32MP1_PWR_H

#include <drivers/regulator.h>
#include <types_ext.h>
#include <util.h>

#define PWR_CR1_OFF		0x00
#define PWR_CR2_OFF		0x08
#define PWR_CR3_OFF		0x0c
#define PWR_MPUCR_OFF		0x10
#define PWR_WKUPCR_OFF		0x20
#define PWR_MPUWKUPENR_OFF	0x28

/* CR3 register bitfield for STM32MP13 variants */
#define PWR_CR3_VDDSD1EN	BIT(13)
#define PWR_CR3_VDDSD1RDY	BIT(14)
#define PWR_CR3_VDDSD2EN	BIT(15)
#define PWR_CR3_VDDSD2RDY	BIT(16)
#define PWR_CR3_VDDSD1VALID	BIT(22)
#define PWR_CR3_VDDSD2VALID	BIT(23)

#define PWR_OFFSET_MASK		0x3fUL

enum pwr_regulator {
	PWR_REG11 = 0,
	PWR_REG18,
	PWR_USB33,
	PWR_REGU_COUNT
};

vaddr_t stm32_pwr_base(void);

unsigned int stm32mp1_pwr_regulator_mv(enum pwr_regulator id);
void stm32mp1_pwr_regulator_set_state(enum pwr_regulator id, bool enable);
bool stm32mp1_pwr_regulator_is_enabled(enum pwr_regulator id);

/* Returns the registered regulator related to @id or NULL */
struct regulator *stm32mp1_pwr_get_regulator(enum pwr_regulator id);
#endif /*__STM32MP1_PWR_H*/
