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

struct gpio_desc {
	unsigned int pin;
	struct gpio_chip *gc;
	void *dev;

	SLIST_ENTRY(gpio_desc) link;
};

enum gpio_dir gpio_get_direction(struct gpio_desc *gd);
void gpio_set_direction(struct gpio_desc *gd, enum gpio_dir direction);
enum gpio_level gpio_get_value(struct gpio_desc *gd);
void gpio_set_value(struct gpio_desc *gd, enum gpio_level value);
enum gpio_interrupt gpio_get_interrupt(struct gpio_desc *gd);
void gpio_set_interrupt(struct gpio_desc *gd, enum gpio_interrupt ena_dis);
void gpio_add_chip(struct gpio_chip *gc);

struct gpio_desc *request_gpiod(unsigned int pin, void *dev);
void release_gpiod(struct gpio_desc *gd);
#endif	/* __GPIO_H__ */
