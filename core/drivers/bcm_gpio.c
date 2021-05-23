// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2019 Broadcom.
 */
#include <assert.h>
#include <drivers/bcm_gpio.h>
#include <initcall.h>
#include <io.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <trace.h>

#define IPROC_GPIO_DATA_IN_OFFSET	0x00
#define IPROC_GPIO_DATA_OUT_OFFSET	0x04
#define IPROC_GPIO_OUT_EN_OFFSET	0x08
#define IPROC_GPIO_INT_MSK_OFFSET	0x18

#define GPIO_BANK_SIZE			0x200
#define NGPIOS_PER_BANK			32
#define GPIO_BANK(pin)			((pin) / NGPIOS_PER_BANK)

#define IPROC_GPIO_REG(pin, reg)	((reg) + \
	GPIO_BANK(pin) * GPIO_BANK_SIZE)

#define IPROC_GPIO_SHIFT(pin)		((pin) % NGPIOS_PER_BANK)

#define GPIO_BANK_CNT			5
#define SEC_GPIO_SIZE			0x4
#define IPROC_GPIO_SEC_CFG_REG(pin) \
	(((GPIO_BANK_CNT - 1) - GPIO_BANK(pin)) * SEC_GPIO_SIZE)

static SLIST_HEAD(, bcm_gpio_chip) gclist = SLIST_HEAD_INITIALIZER(gclist);

struct bcm_gpio_chip *bcm_gpio_pin_to_chip(unsigned int pin)
{
	struct bcm_gpio_chip *gc = NULL;

	SLIST_FOREACH(gc, &gclist, link)
		if ((pin >= gc->gpio_base) &&
		    (pin < (gc->gpio_base + gc->ngpios)))
			return gc;
	return NULL;
}

static bool __maybe_unused gpio_is_range_overlap(unsigned int start,
						 unsigned int end)
{
	struct bcm_gpio_chip *gc = NULL;

	SLIST_FOREACH(gc, &gclist, link)
		if ((start < (gc->gpio_base + gc->ngpios)) &&
		    (end > gc->gpio_base))
			return true;
	return false;
}

static void iproc_set_bit(unsigned int reg, unsigned int gpio)
{
	unsigned int offset = IPROC_GPIO_REG(gpio, reg);
	unsigned int shift = IPROC_GPIO_SHIFT(gpio);
	struct bcm_gpio_chip *gc = bcm_gpio_pin_to_chip(gpio);

	assert(gc);
	io_setbits32(gc->base + offset, BIT(shift));
}

static void iproc_clr_bit(unsigned int reg, unsigned int gpio)
{
	unsigned int offset = IPROC_GPIO_REG(gpio, reg);
	unsigned int shift = IPROC_GPIO_SHIFT(gpio);
	struct bcm_gpio_chip *gc = bcm_gpio_pin_to_chip(gpio);

	assert(gc);
	io_clrbits32(gc->base + offset, BIT(shift));
}

static void iproc_gpio_set(struct gpio_chip *chip __unused, unsigned int gpio,
			   enum gpio_level val)
{
	if (val == GPIO_LEVEL_HIGH)
		iproc_set_bit(IPROC_GPIO_DATA_OUT_OFFSET, gpio);
	else
		iproc_clr_bit(IPROC_GPIO_DATA_OUT_OFFSET, gpio);
}

static enum gpio_level iproc_gpio_get(struct gpio_chip *chip __unused,
				      unsigned int gpio)
{
	unsigned int offset = IPROC_GPIO_REG(gpio, IPROC_GPIO_DATA_IN_OFFSET);
	unsigned int shift = IPROC_GPIO_SHIFT(gpio);
	struct bcm_gpio_chip *gc = bcm_gpio_pin_to_chip(gpio);

	assert(gc);

	if (io_read32(gc->base + offset) & BIT(shift))
		return GPIO_LEVEL_HIGH;
	else
		return GPIO_LEVEL_LOW;
}

static void iproc_gpio_set_dir(struct gpio_chip *chip __unused,
			       unsigned int gpio, enum gpio_dir dir)
{
	if (dir == GPIO_DIR_OUT)
		iproc_set_bit(IPROC_GPIO_OUT_EN_OFFSET, gpio);
	else
		iproc_clr_bit(IPROC_GPIO_OUT_EN_OFFSET, gpio);
}

static enum gpio_dir iproc_gpio_get_dir(struct gpio_chip *chip __unused,
					unsigned int gpio)
{
	unsigned int offset = IPROC_GPIO_REG(gpio, IPROC_GPIO_OUT_EN_OFFSET);
	unsigned int shift = IPROC_GPIO_SHIFT(gpio);
	struct bcm_gpio_chip *gc = bcm_gpio_pin_to_chip(gpio);

	assert(gc);

	if (io_read32(gc->base + offset) & BIT(shift))
		return GPIO_DIR_OUT;
	else
		return GPIO_DIR_IN;
}

static enum gpio_interrupt iproc_gpio_get_itr(struct gpio_chip *chip __unused,
					      unsigned int gpio)
{
	unsigned int offset = IPROC_GPIO_REG(gpio, IPROC_GPIO_INT_MSK_OFFSET);
	unsigned int shift = IPROC_GPIO_SHIFT(gpio);
	struct bcm_gpio_chip *gc = bcm_gpio_pin_to_chip(gpio);

	assert(gc);

	if (io_read32(gc->base + offset) & BIT(shift))
		return GPIO_INTERRUPT_ENABLE;
	else
		return GPIO_INTERRUPT_DISABLE;
}

static void iproc_gpio_set_itr(struct gpio_chip *chip __unused,
			       unsigned int gpio, enum gpio_interrupt ena_dis)
{
	if (ena_dis == GPIO_INTERRUPT_ENABLE)
		iproc_set_bit(IPROC_GPIO_OUT_EN_OFFSET, gpio);
	else
		iproc_clr_bit(IPROC_GPIO_OUT_EN_OFFSET, gpio);
}

static const struct gpio_ops bcm_gpio_ops = {
	.get_direction = iproc_gpio_get_dir,
	.set_direction = iproc_gpio_set_dir,
	.get_value = iproc_gpio_get,
	.set_value = iproc_gpio_set,
	.get_interrupt = iproc_gpio_get_itr,
	.set_interrupt = iproc_gpio_set_itr,
};
DECLARE_KEEP_PAGER(bcm_gpio_ops);

void iproc_gpio_set_secure(int gpiopin)
{
	vaddr_t regaddr = 0;
	unsigned int shift = IPROC_GPIO_SHIFT(gpiopin);
	vaddr_t baseaddr =
		(vaddr_t)phys_to_virt(CHIP_SECURE_GPIO_CONTROL0_BASE,
				      MEM_AREA_IO_SEC,
				      IPROC_GPIO_SEC_CFG_REG(gpiopin) +
				      sizeof(uint32_t));

	regaddr = baseaddr + IPROC_GPIO_SEC_CFG_REG(gpiopin);

	io_clrbits32(regaddr, BIT(shift));
}

static void iproc_gpio_init(struct bcm_gpio_chip *gc, unsigned int paddr,
			    unsigned int gpio_base, unsigned int ngpios)
{
	assert(!gpio_is_range_overlap(gpio_base, gpio_base + gc->ngpios));

	gc->base = core_mmu_get_va(paddr, MEM_AREA_IO_SEC, 1);
	gc->chip.ops = &bcm_gpio_ops;
	gc->gpio_base = gpio_base;
	gc->ngpios = ngpios;

	SLIST_INSERT_HEAD(&gclist, gc, link);

	DMSG("gpio chip for <%u - %u>", gpio_base, gpio_base + ngpios);
}

static TEE_Result bcm_gpio_init(void)
{
	struct bcm_gpio_chip *gc = NULL;

#ifdef SECURE_GPIO_BASE0
	gc = malloc(sizeof(*gc));
	if (gc == NULL)
		return TEE_ERROR_OUT_OF_MEMORY;

	iproc_gpio_init(gc, SECURE_GPIO_BASE0, GPIO_NUM_START0, NUM_GPIOS0);
#endif
#ifdef SECURE_GPIO_BASE1
	gc = malloc(sizeof(*gc));
	if (gc == NULL)
		return TEE_ERROR_OUT_OF_MEMORY;

	iproc_gpio_init(gc, SECURE_GPIO_BASE1, GPIO_NUM_START1, NUM_GPIOS1);
#endif
	return TEE_SUCCESS;
}
driver_init(bcm_gpio_init);
