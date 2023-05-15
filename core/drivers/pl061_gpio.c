// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016, Linaro Limited
 */

#include <assert.h>
#include <drivers/pl061_gpio.h>
#include <io.h>
#include <keep.h>
#include <trace.h>
#include <util.h>

#ifndef PLAT_PL061_MAX_GPIOS
# define PLAT_PL061_MAX_GPIOS	32
#endif	/* PLAT_PL061_MAX_GPIOS */

#define MAX_GPIO_DEVICES	((PLAT_PL061_MAX_GPIOS + \
	(GPIOS_PER_PL061 - 1)) / GPIOS_PER_PL061)

#define GPIOS_PER_PL061		8

/* gpio register offsets */
#define GPIODIR		0x400
#define GPIOIS		0x404
#define GPIOIBE		0x408
#define GPIOIEV		0x40C
#define GPIOIE		0x410
#define GPIORIS		0x414
#define GPIOMIS		0x418
#define GPIOIC		0x41C
#define GPIOAFSEL	0x420

/* gpio register masks */
#define GPIOIE_ENABLED		SHIFT_U32(1, 0)
#define GPIOIE_MASKED		SHIFT_U32(0, 0)
#define GPIOAFSEL_HW		SHIFT_U32(1, 0)
#define GPIOAFSEL_SW		SHIFT_U32(0, 0)
#define GPIODIR_OUT			SHIFT_U32(1, 0)
#define GPIODIR_IN			SHIFT_U32(0, 0)

static vaddr_t pl061_reg_base[MAX_GPIO_DEVICES];

static enum gpio_dir pl061_get_direction(struct gpio_chip *chip __unused,
					 unsigned int gpio_pin)
{
	vaddr_t base_addr;
	uint8_t data;
	unsigned int offset;

	assert(gpio_pin < PLAT_PL061_MAX_GPIOS);

	base_addr = pl061_reg_base[gpio_pin / GPIOS_PER_PL061];
	offset = gpio_pin % GPIOS_PER_PL061;
	data = io_read8(base_addr + GPIODIR);
	if (data & BIT(offset))
		return GPIO_DIR_OUT;
	return GPIO_DIR_IN;
}

static void pl061_set_direction(struct gpio_chip *chip __unused,
				unsigned int gpio_pin, enum gpio_dir direction)
{
	vaddr_t base_addr;
	unsigned int offset;

	assert(gpio_pin < PLAT_PL061_MAX_GPIOS);

	base_addr = pl061_reg_base[gpio_pin / GPIOS_PER_PL061];
	offset = gpio_pin % GPIOS_PER_PL061;
	if (direction == GPIO_DIR_OUT)
		io_setbits8(base_addr + GPIODIR, BIT(offset));
	else
		io_clrbits8(base_addr + GPIODIR, BIT(offset));
}

/*
 * The offset of GPIODATA register is 0.
 * The values read from GPIODATA are determined for each bit, by the mask bit
 * derived from the address used to access the data register, PADDR[9:2].
 * Bits that are 1 in the address mask cause the corresponding bits in GPIODATA
 * to be read, and bits that are 0 in the address mask cause the corresponding
 * bits in GPIODATA to be read as 0, regardless of their value.
 */
static enum gpio_level pl061_get_value(struct gpio_chip *chip __unused,
				       unsigned int gpio_pin)
{
	vaddr_t base_addr;
	unsigned int offset;

	assert(gpio_pin < PLAT_PL061_MAX_GPIOS);

	base_addr = pl061_reg_base[gpio_pin / GPIOS_PER_PL061];
	offset = gpio_pin % GPIOS_PER_PL061;
	if (io_read8(base_addr + BIT(offset + 2)))
		return GPIO_LEVEL_HIGH;
	return GPIO_LEVEL_LOW;
}

/*
 * In order to write GPIODATA, the corresponding bits in the mask, resulting
 * from the address bus, PADDR[9:2], must be HIGH. Otherwise the bit values
 * remain unchanged by the write.
 */
static void pl061_set_value(struct gpio_chip *chip __unused,
			    unsigned int gpio_pin, enum gpio_level value)
{
	vaddr_t base_addr;
	unsigned int offset;

	assert(gpio_pin < PLAT_PL061_MAX_GPIOS);

	base_addr = pl061_reg_base[gpio_pin / GPIOS_PER_PL061];
	offset = gpio_pin % GPIOS_PER_PL061;
	if (value == GPIO_LEVEL_HIGH)
		io_write8(base_addr + BIT(offset + 2), BIT(offset));
	else
		io_write8(base_addr + BIT(offset + 2), 0);
}

static enum gpio_interrupt pl061_get_interrupt(struct gpio_chip *chip __unused,
					       unsigned int gpio_pin)
{
	vaddr_t base_addr;
	uint8_t data;
	unsigned int offset;

	assert(gpio_pin < PLAT_PL061_MAX_GPIOS);

	base_addr = pl061_reg_base[gpio_pin / GPIOS_PER_PL061];
	offset = gpio_pin % GPIOS_PER_PL061;
	data = io_read8(base_addr + GPIOIE);
	if (data & BIT(offset))
		return GPIO_INTERRUPT_ENABLE;
	return GPIO_INTERRUPT_DISABLE;
}

static void pl061_set_interrupt(struct gpio_chip *chip __unused,
				unsigned int gpio_pin,
				enum gpio_interrupt ena_dis)
{
	vaddr_t base_addr;
	unsigned int offset;

	assert(gpio_pin < PLAT_PL061_MAX_GPIOS);

	base_addr = pl061_reg_base[gpio_pin / GPIOS_PER_PL061];
	offset = gpio_pin % GPIOS_PER_PL061;
	if (ena_dis == GPIO_INTERRUPT_ENABLE)
		io_setbits8(base_addr + GPIOIE, BIT(offset));
	else
		io_clrbits8(base_addr + GPIOIE, BIT(offset));
}

/*
 * Register the PL061 GPIO controller with a base address and the offset
 * of start pin in this GPIO controller.
 * This function is called after pl061_init().
 */
void pl061_register(vaddr_t base_addr, unsigned int gpio_dev)
{
	assert(gpio_dev < MAX_GPIO_DEVICES);

	pl061_reg_base[gpio_dev] = base_addr;
}

static const struct gpio_ops pl061_ops = {
	.get_direction = pl061_get_direction,
	.set_direction = pl061_set_direction,
	.get_value = pl061_get_value,
	.set_value = pl061_set_value,
	.get_interrupt = pl061_get_interrupt,
	.set_interrupt = pl061_set_interrupt,
};
DECLARE_KEEP_PAGER(pl061_ops);

/*
 * Initialize PL061 GPIO controller
 */
void pl061_init(struct pl061_data *pd)
{
	COMPILE_TIME_ASSERT(PLAT_PL061_MAX_GPIOS > 0);

	assert(pd);
	pd->chip.ops = &pl061_ops;
}

enum pl061_mode_control pl061_get_mode_control(unsigned int gpio_pin)
{
	vaddr_t base_addr;
	uint8_t data;
	unsigned int offset;

	assert(gpio_pin < PLAT_PL061_MAX_GPIOS);

	base_addr = pl061_reg_base[gpio_pin / GPIOS_PER_PL061];
	offset = gpio_pin % GPIOS_PER_PL061;
	data = io_read8(base_addr + GPIOAFSEL);
	if (data & BIT(offset))
		return PL061_MC_HW;
	return PL061_MC_SW;
}

void pl061_set_mode_control(unsigned int gpio_pin,
	enum pl061_mode_control hw_sw)
{
	vaddr_t base_addr;
	unsigned int offset;

	assert(gpio_pin < PLAT_PL061_MAX_GPIOS);

	base_addr = pl061_reg_base[gpio_pin / GPIOS_PER_PL061];
	offset = gpio_pin % GPIOS_PER_PL061;
	if (hw_sw == PL061_MC_HW)
		io_setbits8(base_addr + GPIOAFSEL, BIT(offset));
	else
		io_clrbits8(base_addr + GPIOAFSEL, BIT(offset));
}
