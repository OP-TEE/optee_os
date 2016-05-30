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

#include <assert.h>
#include <trace.h>
#include <gpio.h>
#include <io.h>
#include <util.h>
#include <drivers/pl061_gpio.h>

#ifndef PLAT_PL061_MAX_GPIOS
# define PLAT_PL061_MAX_GPIOS	32
#endif	/* PLAT_PL061_MAX_GPIOS */

#define MAX_GPIO_DEVICES	((PLAT_PL061_MAX_GPIOS + \
	(GPIOS_PER_PL061 - 1)) / GPIOS_PER_PL061)

#define PL061_GPIO_DIR		0x400

#define GPIOS_PER_PL061		8

static enum gpio_dir pl061_get_direction(unsigned int gpio_pin);
static void pl061_set_direction(unsigned int gpio_pin, enum gpio_dir direction);
static enum gpio_level pl061_get_value(unsigned int gpio_pin);
static void pl061_set_value(unsigned int gpio_pin, enum gpio_level value);

static vaddr_t pl061_reg_base[MAX_GPIO_DEVICES];

static const struct gpio_ops pl061_gpio_ops = {
	.get_direction	= pl061_get_direction,
	.set_direction	= pl061_set_direction,
	.get_value	= pl061_get_value,
	.set_value	= pl061_set_value,
};

static enum gpio_dir pl061_get_direction(unsigned int gpio_pin)
{
	vaddr_t base_addr;
	uint8_t data;
	unsigned int offset;

	assert(gpio_pin < PLAT_PL061_MAX_GPIOS);

	base_addr = pl061_reg_base[gpio_pin / GPIOS_PER_PL061];
	offset = gpio_pin % GPIOS_PER_PL061;
	data = read8(base_addr + PL061_GPIO_DIR);
	if (data & BIT(offset))
		return GPIO_DIR_OUT;
	return GPIO_DIR_IN;
}

static void pl061_set_direction(unsigned int gpio_pin, enum gpio_dir direction)
{
	vaddr_t base_addr;
	uint8_t data;
	unsigned int offset;

	assert(gpio_pin < PLAT_PL061_MAX_GPIOS);

	base_addr = pl061_reg_base[gpio_pin / GPIOS_PER_PL061];
	offset = gpio_pin % GPIOS_PER_PL061;
	if (direction == GPIO_DIR_OUT) {
		data = read8(base_addr + PL061_GPIO_DIR) | BIT(offset);
		write8(data, base_addr + PL061_GPIO_DIR);
	} else {
		data = read8(base_addr + PL061_GPIO_DIR) & ~BIT(offset);
		write8(data, base_addr + PL061_GPIO_DIR);
	}
}

/*
 * The offset of GPIODATA register is 0.
 * The values read from GPIODATA are determined for each bit, by the mask bit
 * derived from the address used to access the data register, PADDR[9:2].
 * Bits that are 1 in the address mask cause the corresponding bits in GPIODATA
 * to be read, and bits that are 0 in the address mask cause the corresponding
 * bits in GPIODATA to be read as 0, regardless of their value.
 */
static enum gpio_level pl061_get_value(unsigned int gpio_pin)
{
	vaddr_t base_addr;
	unsigned int offset;

	assert(gpio_pin < PLAT_PL061_MAX_GPIOS);

	base_addr = pl061_reg_base[gpio_pin / GPIOS_PER_PL061];
	offset = gpio_pin % GPIOS_PER_PL061;
	if (read8(base_addr + BIT(offset + 2)))
		return GPIO_LEVEL_HIGH;
	return GPIO_LEVEL_LOW;
}

/*
 * In order to write GPIODATA, the corresponding bits in the mask, resulting
 * from the address bus, PADDR[9:2], must be HIGH. Otherwise the bit values
 * remain unchanged by the write.
 */
static void pl061_set_value(unsigned int gpio_pin, enum gpio_level value)
{
	vaddr_t base_addr;
	unsigned int offset;

	assert(gpio_pin < PLAT_PL061_MAX_GPIOS);

	base_addr = pl061_reg_base[gpio_pin / GPIOS_PER_PL061];
	offset = gpio_pin % GPIOS_PER_PL061;
	if (value == GPIO_LEVEL_HIGH)
		write8(BIT(offset), base_addr + BIT(offset + 2));
	else
		write8(0, base_addr + BIT(offset + 2));
}


/*
 * Register the PL061 GPIO controller with a base address and the offset
 * of start pin in this GPIO controller.
 * This function is called after pl061_gpio_ops_init().
 */
void pl061_gpio_register(vaddr_t base_addr, unsigned int gpio_dev)
{
	assert(gpio_dev < MAX_GPIO_DEVICES);

	pl061_reg_base[gpio_dev] = base_addr;
}

/*
 * Initialize PL061 GPIO controller with the total GPIO numbers in SoC.
 */
void pl061_gpio_init(void)
{
	COMPILE_TIME_ASSERT(PLAT_PL061_MAX_GPIOS > 0);
	gpio_init(&pl061_gpio_ops);
}
