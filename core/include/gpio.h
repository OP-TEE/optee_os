/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
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

struct gpio_ops {
	enum gpio_dir (*get_direction)(int gpio_pin);
	void (*set_direction)(int gpio_pin, enum gpio_dir direction);
	enum gpio_level (*get_value)(int gpio_pin);
	void (*set_value)(int gpio_pin, enum gpio_level value);
};

enum gpio_dir gpio_get_direction(int gpio_pin);
void gpio_set_direction(int gpio_pin, enum gpio_dir direction);
enum gpio_level gpio_get_value(int gpio_pin);
void gpio_set_value(int gpio_pin, enum gpio_level value);
void gpio_init(const struct gpio_ops *ops);

#endif	/* __GPIO_H__ */
