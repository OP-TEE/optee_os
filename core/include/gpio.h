/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016, Linaro Limited
 */

#ifndef __GPIO_H__
#define __GPIO_H__

#include <stdlib.h>
#include <sys/queue.h>

enum gpio_dir {
	GPIO_DIR_OUT,
	GPIO_DIR_IN
};

enum gpio_level {
	GPIO_LEVEL_LOW,
	GPIO_LEVEL_HIGH
};

enum gpio_interrupt {
	GPIO_INTERRUPT_DISABLE,
	GPIO_INTERRUPT_ENABLE
};

/**
 * struct gpio_chip describes GPIO controller chip instance
 * @ops:        pointer to supported operations
 * @gpio_base:  starting GPIO number managed by this GPIO controller.
 * @ngpios:     number of GPIOs managed by this GPIO controller.
 * @base:       virtual base address of the GPIO controller registers.
 */
struct gpio_chip {
	const struct gpio_ops *ops;
	unsigned int gpio_base;
	unsigned int ngpios;
	vaddr_t base;

	SLIST_ENTRY(gpio_chip) link;
};

struct gpio_ops {
	enum gpio_dir (*get_direction)(struct gpio_chip *gc, unsigned int pin);
	void (*set_direction)(struct gpio_chip *gc, unsigned int pin,
			      enum gpio_dir direction);
	enum gpio_level (*get_value)(struct gpio_chip *gc, unsigned int pin);
	void (*set_value)(struct gpio_chip *gc, unsigned int pin,
			  enum gpio_level value);
	enum gpio_interrupt (*get_interrupt)(struct gpio_chip *gc,
					     unsigned int pin);
	void (*set_interrupt)(struct gpio_chip *gc, unsigned int pin,
			      enum gpio_interrupt ena_dis);
};

/*
 * struct gpio_desc describes each used pin.
 * pin:   GPIO pin number or unique hardware id
 * gc:    reference to gpio_chip which can manage this pin
 * owner: data related to current owner of the pin.
 */
struct gpio_desc {
	unsigned int pin;
	struct gpio_chip *gc;
	void *owner;

	SLIST_ENTRY(gpio_desc) link;
};

enum gpio_dir gpio_get_direction(struct gpio_desc *gd);
void gpio_set_direction(struct gpio_desc *gd, enum gpio_dir direction);
enum gpio_level gpio_get_value(struct gpio_desc *gd);
void gpio_set_value(struct gpio_desc *gd, enum gpio_level value);
enum gpio_interrupt gpio_get_interrupt(struct gpio_desc *gd);
void gpio_set_interrupt(struct gpio_desc *gd, enum gpio_interrupt ena_dis);
/* creates an instance of GPIO controller */
void gpio_add_chip(struct gpio_chip *gc);
/* returns a descriptor handle if the pin is not in use by other consumer */
struct gpio_desc *request_gpiod(unsigned int pin, void *dev);
/* marks the pin as free */
void release_gpiod(struct gpio_desc *gd);
#endif	/* __GPIO_H__ */
