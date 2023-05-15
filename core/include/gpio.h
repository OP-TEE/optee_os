/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016, Linaro Limited
 */

#ifndef __GPIO_H__
#define __GPIO_H__

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
};

struct gpio_ops {
	enum gpio_dir (*get_direction)(struct gpio_chip *chip,
				       unsigned int gpio_pin);
	void (*set_direction)(struct gpio_chip *chip, unsigned int gpio_pin,
			      enum gpio_dir direction);
	enum gpio_level (*get_value)(struct gpio_chip *chip,
				     unsigned int gpio_pin);
	void (*set_value)(struct gpio_chip *chip, unsigned int gpio_pin,
			  enum gpio_level value);
	enum gpio_interrupt (*get_interrupt)(struct gpio_chip *chip,
					     unsigned int gpio_pin);
	void (*set_interrupt)(struct gpio_chip *chip, unsigned int gpio_pin,
			      enum gpio_interrupt ena_dis);
};

#endif	/* __GPIO_H__ */
