/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016, Linaro Limited
 */

#ifndef __PL061_GPIO_H__
#define __PL061_GPIO_H__

#include <gpio.h>
#include <types_ext.h>

#define PL061_REG_SIZE	0x1000

enum pl061_mode_control {
	PL061_MC_SW,
	PL061_MC_HW
};

struct pl061_data {
	struct gpio_chip chip;
};

void pl061_register(vaddr_t base_addr, unsigned int gpio_dev);
void pl061_init(struct pl061_data *pd);
enum pl061_mode_control pl061_get_mode_control(unsigned int gpio_pin);
void pl061_set_mode_control(unsigned int gpio_pin,
	enum pl061_mode_control hw_sw);

#endif	/* __PL061_GPIO_H__ */
