/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2022 Foundries.io Ltd
 */

#ifndef __DRIVERS_VERSAL_GPIO_H
#define __DRIVERS_VERSAL_GPIO_H

#include <gpio.h>
#include <stdlib.h>
#include <tee_api_types.h>
#include <util.h>

#define VERSAL_GPIO_MAX_BANK	5

struct versal_gpio_platform_data {
	const char *label;
	uint16_t ngpio;
	uint32_t max_bank;
	uint32_t bank_min[VERSAL_GPIO_MAX_BANK];
	uint32_t bank_max[VERSAL_GPIO_MAX_BANK];
};

struct versal_gpio_platdata {
	paddr_t base;
	const struct versal_gpio_platform_data *p_data;
};

struct versal_gpio_chip {
	struct gpio_chip chip;
	struct versal_gpio_platdata plat;
	vaddr_t base;
};

TEE_Result versal_gpio_pmc_init(struct versal_gpio_chip *chip);
TEE_Result versal_gpio_ps_init(struct versal_gpio_chip *chip);

#endif /* __DRIVERS_VERSAL_GPIO_H */
