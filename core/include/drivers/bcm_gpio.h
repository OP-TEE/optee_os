/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2019 Broadcom.
 */

#ifndef __DRIVERS_BCM_GPIO_H
#define __DRIVERS_BCM_GPIO_H

#include <drivers/gpio.h>
#include <stdlib.h>
#include <sys/queue.h>

/**
 * struct bcm_gpio_chip describes GPIO controller chip instance
 * @chip:       generic GPIO chip handle.
 * @gpio_base:  starting GPIO number managed by this GPIO controller.
 * @ngpios:     number of GPIOs managed by this GPIO controller.
 * @base:       virtual base address of the GPIO controller registers.
 */
struct bcm_gpio_chip {
	struct gpio_chip chip;
	unsigned int gpio_base;
	unsigned int ngpios;
	vaddr_t base;

	SLIST_ENTRY(bcm_gpio_chip) link;
};

/* Returns bcm_gpio_chip handle for a GPIO pin */
struct bcm_gpio_chip *bcm_gpio_pin_to_chip(unsigned int pin);
/* Set gpiopin as secure */
void iproc_gpio_set_secure(int gpiopin);
#endif	/* __DRIVERS_BCM_GPIO_H */
