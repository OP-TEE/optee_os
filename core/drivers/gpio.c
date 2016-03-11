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
 *
 * GPIO -- General Purpose Input/Output
 *
 * Defines a simple and generic interface to access GPIO device.
 *
 */

#include <assert.h>
#include <trace.h>
#include <gpio.h>

/*
 * The gpio implementation
 */
static const struct gpio_ops *ops;

enum gpio_dir gpio_get_direction(unsigned int gpio_pin)
{
	assert(ops);
	assert(ops->get_direction != 0);

	return ops->get_direction(gpio_pin);
}

void gpio_set_direction(unsigned int gpio_pin, enum gpio_dir direction)
{
	assert(ops);
	assert(ops->set_direction != 0);
	assert((direction == GPIO_DIR_OUT) || (direction == GPIO_DIR_IN));

	ops->set_direction(gpio_pin, direction);
}

enum gpio_level gpio_get_value(unsigned int gpio_pin)
{
	assert(ops);
	assert(ops->get_value != 0);

	return ops->get_value(gpio_pin);
}

void gpio_set_value(unsigned int gpio_pin, enum gpio_level value)
{
	assert(ops);
	assert(ops->set_value != 0);
	assert((value == GPIO_LEVEL_LOW) || (value == GPIO_LEVEL_HIGH));

	ops->set_value(gpio_pin, value);
}

/*
 * Initialize the gpio. The fields in the provided gpio
 * ops pointer must be valid.
 */
void gpio_init(const struct gpio_ops *ops_ptr)
{
	assert(ops_ptr != 0  &&
		(ops_ptr->get_direction != 0) &&
		(ops_ptr->set_direction != 0) &&
		(ops_ptr->get_value != 0) &&
		(ops_ptr->set_value != 0));

	ops = ops_ptr;
}
