// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2019 Broadcom.
 */
#include <assert.h>
#include <gpio.h>
#include <initcall.h>
#include <io.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <trace.h>

#define IPROC_GPIO_DATA_IN_OFFSET   0x00
#define IPROC_GPIO_DATA_OUT_OFFSET  0x04
#define IPROC_GPIO_OUT_EN_OFFSET    0x08
#define IPROC_GPIO_INT_MSK_OFFSET   0x18

#define GPIO_BANK_SIZE  0x200
#define NGPIOS_PER_BANK 32
#define GPIO_BANK(pin)  ((pin) / NGPIOS_PER_BANK)

#define IPROC_GPIO_REG(pin, reg) (GPIO_BANK(pin) * GPIO_BANK_SIZE + (reg))
#define IPROC_GPIO_SHIFT(pin)    ((pin) % NGPIOS_PER_BANK)

static void iproc_set_bit(struct gpio_chip *gc, unsigned int reg,
			  unsigned int gpio)
{
	unsigned int offset = IPROC_GPIO_REG(gpio, reg);
	unsigned int shift = IPROC_GPIO_SHIFT(gpio);

	io_setbits32((vaddr_t)gc->pd + offset, BIT(shift));
}

static void iproc_clr_bit(struct gpio_chip *gc, unsigned int reg,
			  unsigned int gpio)
{
	unsigned int offset = IPROC_GPIO_REG(gpio, reg);
	unsigned int shift = IPROC_GPIO_SHIFT(gpio);

	io_clrbits32((vaddr_t)gc->pd + offset, BIT(shift));
}

static void iproc_gpio_set(struct gpio_chip *gc, unsigned int gpio,
			   enum gpio_level val)
{
	if (val == GPIO_LEVEL_HIGH)
		iproc_set_bit(gc, IPROC_GPIO_DATA_OUT_OFFSET, gpio);
	else
		iproc_clr_bit(gc, IPROC_GPIO_DATA_OUT_OFFSET, gpio);
}

static enum gpio_level iproc_gpio_get(struct gpio_chip *gc, unsigned int gpio)
{
	unsigned int offset = IPROC_GPIO_REG(gpio, IPROC_GPIO_DATA_IN_OFFSET);
	unsigned int shift = IPROC_GPIO_SHIFT(gpio);

	if (io_read32((vaddr_t)gc->pd + offset) & BIT(shift))
		return GPIO_LEVEL_HIGH;
	else
		return GPIO_LEVEL_LOW;
}

static void iproc_gpio_set_dir(struct gpio_chip *gc, unsigned int gpio,
			       enum gpio_dir dir)
{
	if (dir == GPIO_DIR_OUT)
		iproc_set_bit(gc, IPROC_GPIO_OUT_EN_OFFSET, gpio);
	else
		iproc_clr_bit(gc, IPROC_GPIO_OUT_EN_OFFSET, gpio);

}

static enum gpio_dir iproc_gpio_get_dir(struct gpio_chip *gc,
					unsigned int gpio)
{
	unsigned int offset = IPROC_GPIO_REG(gpio, IPROC_GPIO_OUT_EN_OFFSET);
	unsigned int shift = IPROC_GPIO_SHIFT(gpio);

	if (io_read32((vaddr_t)gc->pd + offset) & BIT(shift))
		return GPIO_DIR_OUT;
	else
		return GPIO_DIR_IN;
}

static enum gpio_interrupt iproc_gpio_get_itr(struct gpio_chip *gc,
					      unsigned int gpio)
{
	unsigned int offset = IPROC_GPIO_REG(gpio, IPROC_GPIO_INT_MSK_OFFSET);
	unsigned int shift = IPROC_GPIO_SHIFT(gpio);

	if (io_read32((vaddr_t)gc->pd + offset) & BIT(shift))
		return GPIO_INTERRUPT_ENABLE;
	else
		return GPIO_INTERRUPT_DISABLE;
}

static void iproc_gpio_set_itr(struct gpio_chip *gc, unsigned int gpio,
			       enum gpio_interrupt ena_dis)
{
	if (ena_dis == GPIO_INTERRUPT_ENABLE)
		iproc_set_bit(gc, IPROC_GPIO_OUT_EN_OFFSET, gpio);
	else
		iproc_clr_bit(gc, IPROC_GPIO_OUT_EN_OFFSET, gpio);

}

static const struct gpio_ops bcm_gpio_ops = {
	.get_direction = iproc_gpio_get_dir,
	.set_direction = iproc_gpio_set_dir,
	.get_value = iproc_gpio_get,
	.set_value = iproc_gpio_set,
	.get_interrupt = iproc_gpio_get_itr,
	.set_interrupt = iproc_gpio_set_itr,
};
KEEP_PAGER(bcm_gpio_ops);

static void iproc_gpio_init(struct gpio_chip *gc, unsigned int paddr,
			    unsigned int gpio_base, unsigned int ngpios)
{
	gc->pd = (void *)core_mmu_get_va(paddr, MEM_AREA_IO_SEC);
	gc->ops = &bcm_gpio_ops;
	gc->gpio_base = gpio_base;
	gc->ngpios = ngpios;

	gpio_add_chip(gc);
	DMSG("gpio chip added for <%d - %d>", gpio_base, gpio_base + ngpios);
}

static TEE_Result bcm_gpio_init(void)
{
	struct gpio_chip *gc = malloc(sizeof(*gc));

	if (gc == NULL)
		return TEE_ERROR_OUT_OF_MEMORY;

	iproc_gpio_init(gc, SECURE_GPIO_BASE0, GPIO_NUM_START0, NUM_GPIOS0);

	return TEE_SUCCESS;
}
driver_init(bcm_gpio_init);
