/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2021 NXP
 *
 * Helper Code for GPIO controller driver
 *
 */

#ifndef __DRIVERS_LS_GPIO_H
#define __DRIVERS_LS_GPIO_H

#include <gpio.h>
#include <stdlib.h>
#include <tee_api_types.h>

/* supported ports for GPIO controller */
#define MAX_GPIO_PINS 31

/* map register values to LE by subtracting pin number from MAX GPIO PINS */
#define PIN_SHIFT(x) (1 << (MAX_GPIO_PINS - (x)))

/* gpio register offsets */
#define GPIODIR 0x0  /* direction register */
#define GPIOODR 0x4  /* open drain register */
#define GPIODAT 0x8  /* data register */
#define GPIOIER 0xc  /* interrupt event register */
#define GPIOIMR 0x10 /* interrupt mask register */
#define GPIOICR 0x14 /* interrupt control register */
#define GPIOIBE 0x18 /* input buffer enable register */

/*
 * struct ls_gpio_chip_data describes GPIO controller chip instance
 * The structure contains below members:
 * chip:		generic GPIO chip handle.
 * gpio_base:		starting GPIO module base address managed by this GPIO
 *			controller.
 * gpio_controller:	GPIO controller to be used.
 */
struct ls_gpio_chip_data {
	struct gpio_chip chip;
	vaddr_t gpio_base;
	uint8_t gpio_controller;
};

/*
 * Initialize GPIO Controller
 * gpio_data is a pointer of type 'struct ls_gpio_chip_data'.
 */
TEE_Result ls_gpio_init(struct ls_gpio_chip_data *gpio_data);

#endif /* __DRIVERS_LS_GPIO_H */
