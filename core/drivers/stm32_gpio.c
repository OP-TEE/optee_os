// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2017-2019, STMicroelectronics
 *
 * STM32 GPIO driver is used as pin controller for stm32mp SoCs.
 * The driver API is defined in header file stm32_gpio.h.
 */

#include <assert.h>
#include <drivers/stm32_gpio.h>
#include <io.h>
#include <kernel/dt.h>
#include <kernel/boot.h>
#include <kernel/panic.h>
#include <kernel/spinlock.h>
#include <libfdt.h>
#include <mm/core_memprot.h>
#include <stdbool.h>
#include <stm32_util.h>
#include <trace.h>
#include <util.h>

#define GPIO_PIN_MAX		15

#define GPIO_MODER_OFFSET	0x00
#define GPIO_OTYPER_OFFSET	0x04
#define GPIO_OSPEEDR_OFFSET	0x08
#define GPIO_PUPDR_OFFSET	0x0c
#define GPIO_IDR_OFFSET		0x10
#define GPIO_ODR_OFFSET		0x14
#define GPIO_BSRR_OFFSET	0x18
#define GPIO_AFRL_OFFSET	0x20
#define GPIO_AFRH_OFFSET	0x24
#define GPIO_SECR_OFFSET	0x30

#define GPIO_ALT_LOWER_LIMIT	0x8

#define GPIO_MODE_MASK		GENMASK_32(1, 0)
#define GPIO_OSPEED_MASK	GENMASK_32(1, 0)
#define GPIO_PUPD_PULL_MASK	GENMASK_32(1, 0)
#define GPIO_ALTERNATE_MASK	GENMASK_32(3, 0)

#define DT_GPIO_BANK_SHIFT	12
#define DT_GPIO_BANK_MASK	GENMASK_32(16, 12)
#define DT_GPIO_PIN_SHIFT	8
#define DT_GPIO_PIN_MASK	GENMASK_32(11, 8)
#define DT_GPIO_MODE_MASK	GENMASK_32(7, 0)

static unsigned int gpio_lock;

/* Save to output @cfg the current GPIO (@bank/@pin) configuration */
static void get_gpio_cfg(uint32_t bank, uint32_t pin, struct gpio_cfg *cfg)
{
	vaddr_t base = stm32_get_gpio_bank_base(bank);
	unsigned int clock = stm32_get_gpio_bank_clock(bank);

	stm32_clock_enable(clock);

	/*
	 * Save GPIO configuration bits spread over the few bank registers.
	 * 1bit fields are accessed at bit position being the pin index.
	 * 2bit fields are accessed at bit position being twice the pin index.
	 * 4bit fields are accessed at bit position being fourth the pin index
	 * but accessed from 2 32bit registers at incremental addresses.
	 */
	cfg->mode = (io_read32(base + GPIO_MODER_OFFSET) >> (pin << 1)) &
		     GPIO_MODE_MASK;

	cfg->otype = (io_read32(base + GPIO_OTYPER_OFFSET) >> pin) & 1;

	cfg->ospeed = (io_read32(base +  GPIO_OSPEEDR_OFFSET) >> (pin << 1)) &
		       GPIO_OSPEED_MASK;

	cfg->pupd = (io_read32(base +  GPIO_PUPDR_OFFSET) >> (pin << 1)) &
		     GPIO_PUPD_PULL_MASK;

	cfg->od = (io_read32(base + GPIO_ODR_OFFSET) >> (pin << 1)) & 1;

	if (pin < GPIO_ALT_LOWER_LIMIT)
		cfg->af = (io_read32(base + GPIO_AFRL_OFFSET) >> (pin << 2)) &
			   GPIO_ALTERNATE_MASK;
	else
		cfg->af = (io_read32(base + GPIO_AFRH_OFFSET) >>
			    ((pin - GPIO_ALT_LOWER_LIMIT) << 2)) &
			   GPIO_ALTERNATE_MASK;

	stm32_clock_disable(clock);
}

/* Apply GPIO (@bank/@pin) configuration described by @cfg */
static void set_gpio_cfg(uint32_t bank, uint32_t pin, struct gpio_cfg *cfg)
{
	vaddr_t base = stm32_get_gpio_bank_base(bank);
	unsigned int clock = stm32_get_gpio_bank_clock(bank);
	uint32_t exceptions = cpu_spin_lock_xsave(&gpio_lock);

	stm32_clock_enable(clock);

	/* Load GPIO MODE value, 2bit value shifted by twice the pin number */
	io_clrsetbits32(base + GPIO_MODER_OFFSET,
			GPIO_MODE_MASK << (pin << 1),
			cfg->mode << (pin << 1));

	/* Load GPIO Output TYPE value, 1bit shifted by pin number value */
	io_clrsetbits32(base + GPIO_OTYPER_OFFSET, BIT(pin), cfg->otype << pin);

	/* Load GPIO Output Speed confguration, 2bit value */
	io_clrsetbits32(base + GPIO_OSPEEDR_OFFSET,
			GPIO_OSPEED_MASK << (pin << 1),
			cfg->ospeed << (pin << 1));

	/* Load GPIO pull configuration, 2bit value */
	io_clrsetbits32(base + GPIO_PUPDR_OFFSET, BIT(pin),
			cfg->pupd << (pin << 1));

	/* Load pin mux Alternate Function configuration, 4bit value */
	if (pin < GPIO_ALT_LOWER_LIMIT) {
		io_clrsetbits32(base + GPIO_AFRL_OFFSET,
				GPIO_ALTERNATE_MASK << (pin << 2),
				cfg->af << (pin << 2));
	} else {
		size_t shift = (pin - GPIO_ALT_LOWER_LIMIT) << 2;

		io_clrsetbits32(base + GPIO_AFRH_OFFSET,
				GPIO_ALTERNATE_MASK << shift,
				cfg->af << shift);
	}

	/* Load GPIO Output direction confuguration, 1bit */
	io_clrsetbits32(base + GPIO_ODR_OFFSET, BIT(pin), cfg->od << pin);

	stm32_clock_disable(clock);
	cpu_spin_unlock_xrestore(&gpio_lock, exceptions);
}

void stm32_pinctrl_load_active_cfg(struct stm32_pinctrl *pinctrl, size_t cnt)
{
	size_t n = 0;

	for (n = 0; n < cnt; n++)
		set_gpio_cfg(pinctrl[n].bank, pinctrl[n].pin,
			     &pinctrl[n].active_cfg);
}

void stm32_pinctrl_load_standby_cfg(struct stm32_pinctrl *pinctrl, size_t cnt)
{
	size_t n = 0;

	for (n = 0; n < cnt; n++)
		set_gpio_cfg(pinctrl[n].bank, pinctrl[n].pin,
			     &pinctrl[n].standby_cfg);
}

void stm32_pinctrl_store_standby_cfg(struct stm32_pinctrl *pinctrl, size_t cnt)
{
	size_t n = 0;

	for (n = 0; n < cnt; n++)
		get_gpio_cfg(pinctrl[n].bank, pinctrl[n].pin,
			     &pinctrl[n].standby_cfg);
}

#ifdef CFG_DT
/* Panic if GPIO bank information from platform do not match DTB description */
static void ckeck_gpio_bank(void *fdt, uint32_t bank, int pinctrl_node)
{
	int pinctrl_subnode = 0;

	fdt_for_each_subnode(pinctrl_subnode, fdt, pinctrl_node) {
		const fdt32_t *cuint = NULL;

		if (fdt_getprop(fdt, pinctrl_subnode,
				"gpio-controller", NULL) == NULL)
			continue;

		/* Check bank register offset matches platform assumptions */
		cuint = fdt_getprop(fdt, pinctrl_subnode, "reg", NULL);
		if (fdt32_to_cpu(*cuint) != stm32_get_gpio_bank_offset(bank))
			continue;

		/* Check bank clock matches platform assumptions */
		cuint = fdt_getprop(fdt, pinctrl_subnode, "clocks", NULL);
		if (!cuint)
			panic();
		cuint++;
		if (fdt32_to_cpu(*cuint) != stm32_get_gpio_bank_clock(bank))
			panic();

		/* Check controller is enabled */
		if (_fdt_get_status(fdt, pinctrl_subnode) == DT_STATUS_DISABLED)
			panic();

		return;
	}

	panic();
}

/* Count pins described in the DT node and get related data if possible */
static int get_pinctrl_from_fdt(void *fdt, int node,
				struct stm32_pinctrl *pinctrl, size_t count)
{
	const fdt32_t *cuint, *slewrate;
	int len = 0;
	int pinctrl_node = 0;
	uint32_t i = 0;
	uint32_t speed = GPIO_OSPEED_LOW;
	uint32_t pull = GPIO_PUPD_NO_PULL;
	size_t found = 0;

	cuint = fdt_getprop(fdt, node, "pinmux", &len);
	if (!cuint)
		return -FDT_ERR_NOTFOUND;

	pinctrl_node = fdt_parent_offset(fdt, fdt_parent_offset(fdt, node));
	if (pinctrl_node < 0)
		return -FDT_ERR_NOTFOUND;

	slewrate = fdt_getprop(fdt, node, "slew-rate", NULL);
	if (slewrate)
		speed = fdt32_to_cpu(*slewrate);

	if (fdt_getprop(fdt, node, "bias-pull-up", NULL))
		pull = GPIO_PUPD_PULL_UP;
	if (fdt_getprop(fdt, node, "bias-pull-down", NULL))
		pull = GPIO_PUPD_PULL_DOWN;

	for (i = 0; i < ((uint32_t)len / sizeof(uint32_t)); i++) {
		uint32_t pincfg = 0;
		uint32_t bank = 0;
		uint32_t pin = 0;
		uint32_t mode = 0;
		uint32_t alternate = 0;
		bool opendrain = false;

		pincfg = fdt32_to_cpu(*cuint);
		cuint++;

		bank = (pincfg & DT_GPIO_BANK_MASK) >> DT_GPIO_BANK_SHIFT;

		pin = (pincfg & DT_GPIO_PIN_MASK) >> DT_GPIO_PIN_SHIFT;

		mode = pincfg & DT_GPIO_MODE_MASK;

		switch (mode) {
		case 0:
			mode = GPIO_MODE_INPUT;
			break;
		case 1:
		case 2:
		case 3:
		case 4:
		case 5:
		case 6:
		case 7:
		case 8:
		case 9:
		case 10:
		case 11:
		case 12:
		case 13:
		case 14:
		case 15:
		case 16:
			alternate = mode - 1U;
			mode = GPIO_MODE_ALTERNATE;
			break;
		case 17:
			mode = GPIO_MODE_ANALOG;
			break;
		default:
			mode = GPIO_MODE_OUTPUT;
			break;
		}

		if (fdt_getprop(fdt, node, "drive-open-drain", NULL))
			opendrain = true;

		/* Check GPIO bank clock/base address against platform */
		ckeck_gpio_bank(fdt, bank, pinctrl_node);

		if (found < count) {
			struct stm32_pinctrl *ref = &pinctrl[found];

			ref->bank = (uint8_t)bank;
			ref->pin = (uint8_t)pin;
			ref->active_cfg.mode = mode;
			ref->active_cfg.otype = opendrain ? 1 : 0;
			ref->active_cfg.ospeed = speed;
			ref->active_cfg.pupd = pull;
			ref->active_cfg.od = 0;
			ref->active_cfg.af = alternate;
			/* Default to analog mode for standby state */
			ref->standby_cfg.mode = GPIO_MODE_ANALOG;
			ref->standby_cfg.pupd = GPIO_PUPD_NO_PULL;
		}

		found++;
	}

	return (int)found;
}

int stm32_pinctrl_fdt_get_pinctrl(void *fdt, int device_node,
				  struct stm32_pinctrl *pinctrl, size_t count)
{
	const fdt32_t *cuint = NULL;
	int lenp = 0;
	int i = 0;
	size_t found = 0;

	cuint = fdt_getprop(fdt, device_node, "pinctrl-0", &lenp);
	if (!cuint)
		return -FDT_ERR_NOTFOUND;

	for (i = 0; i < (lenp / 4); i++) {
		int node = 0;
		int subnode = 0;

		node = fdt_node_offset_by_phandle(fdt, fdt32_to_cpu(*cuint));
		if (node < 0)
			return -FDT_ERR_NOTFOUND;

		fdt_for_each_subnode(subnode, fdt, node) {
			size_t n = 0;
			int rc = 0;

			if (count > found)
				n = count - found;
			else
				n = 0;

			rc = get_pinctrl_from_fdt(fdt, subnode,
						  &pinctrl[found], n);
			if (rc < 0)
				return rc;

			found += (size_t)rc;
		}

		cuint++;
	}

	return (int)found;
}

int stm32_get_gpio_count(void *fdt, int pinctrl_node, unsigned int bank)
{
	int node = 0;
	const fdt32_t *cuint = NULL;

	fdt_for_each_subnode(node, fdt, pinctrl_node) {
		if (!fdt_getprop(fdt, node, "gpio-controller", NULL))
			continue;

		cuint = fdt_getprop(fdt, node, "reg", NULL);
		if (!cuint)
			continue;

		if (fdt32_to_cpu(*cuint) != stm32_get_gpio_bank_offset(bank))
			continue;

		cuint = fdt_getprop(fdt, node, "ngpios", NULL);
		if (!cuint)
			panic();

		return (int)fdt32_to_cpu(*cuint);
	}

	return -1;
}
#endif /*CFG_DT*/

static __maybe_unused bool valid_gpio_config(unsigned int bank,
					     unsigned int pin, bool input)
{
	vaddr_t base = stm32_get_gpio_bank_base(bank);
	uint32_t mode = (io_read32(base + GPIO_MODER_OFFSET) >> (pin << 1)) &
			GPIO_MODE_MASK;

	if (pin > GPIO_PIN_MAX)
		return false;

	if (input)
		return mode == GPIO_MODE_INPUT;
	else
		return mode == GPIO_MODE_OUTPUT;
}

int stm32_gpio_get_input_level(unsigned int bank, unsigned int pin)
{
	vaddr_t base = stm32_get_gpio_bank_base(bank);
	unsigned int clock = stm32_get_gpio_bank_clock(bank);
	int rc = 0;

	assert(valid_gpio_config(bank, pin, true));

	stm32_clock_enable(clock);

	if (io_read32(base + GPIO_IDR_OFFSET) == BIT(pin))
		rc = 1;

	stm32_clock_disable(clock);

	return rc;
}

void stm32_gpio_set_output_level(unsigned int bank, unsigned int pin, int level)
{
	vaddr_t base = stm32_get_gpio_bank_base(bank);
	unsigned int clock = stm32_get_gpio_bank_clock(bank);

	assert(valid_gpio_config(bank, pin, false));

	stm32_clock_enable(clock);

	if (level)
		io_write32(base + GPIO_BSRR_OFFSET, BIT(pin));
	else
		io_write32(base + GPIO_BSRR_OFFSET, BIT(pin + 16));

	stm32_clock_disable(clock);
}

void stm32_gpio_set_secure_cfg(unsigned int bank, unsigned int pin, bool secure)
{
	vaddr_t base = stm32_get_gpio_bank_base(bank);
	unsigned int clock = stm32_get_gpio_bank_clock(bank);
	uint32_t exceptions = cpu_spin_lock_xsave(&gpio_lock);

	stm32_clock_enable(clock);

	if (secure)
		io_setbits32(base + GPIO_SECR_OFFSET, BIT(pin));
	else
		io_clrbits32(base + GPIO_SECR_OFFSET, BIT(pin));

	stm32_clock_disable(clock);
	cpu_spin_unlock_xrestore(&gpio_lock, exceptions);
}
