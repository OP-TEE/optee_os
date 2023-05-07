// SPDX-License-Identifier: MIT
/*
 * Copyright (C) 2002 - 2021 Xilinx, Inc.  All rights reserved.
 * Copyright (c) 2022 Foundries.io Ltd. (jorge@foundries.io)
 */
#include <arm.h>
#include <assert.h>
#include <crypto/crypto.h>
#include <initcall.h>
#include <io.h>
#include <kernel/panic.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <stdlib.h>
#include <string.h>
#include <tee/tee_cryp_utl.h>

#include "drivers/versal_gpio.h"

#define VERSAL_GPIO_LEN  0x10000

#define DATA_LSW_OFFSET(__bank)	(0x000 + 0x08 * (__bank))
#define DATA_MSW_OFFSET(__bank)	(0x004 + 0x08 * (__bank))
#define DATA_RO_OFFSET(__bank)	(0x060 + 0x04 * (__bank))
#define DIRM_OFFSET(__bank)	(0x204 + 0x40 * (__bank))
#define OUTEN_OFFSET(__bank)	(0x208 + 0x40 * (__bank))

#define VERSAL_GPIO_MID_PIN		16
#define VERSAL_GPIO_UPPER_MASK		0xFFFF0000

/* Max pins in the PMC_GPIO devices
 * 00  - 025,  Bank 0
 * 26 -  051,  Bank 1
 * 52 -  083,  Bank 3
 * 84 -  115,  Bank 4
 */
#define VERSAL_GPIO_PMC_BASE		0xf1020000
#define VERSAL_GPIO_PMC_NR_GPIOS	116
#define VERSAL_GPIO_PMC_MAX_BANK	5

static const struct versal_gpio_platform_data versal_gpio_pmc_def = {
	.max_bank = VERSAL_GPIO_PMC_MAX_BANK,
	.ngpio = VERSAL_GPIO_PMC_NR_GPIOS,
	.label = "versal_pmc_gpio",
	.bank_min[0] = 0,
	.bank_max[0] = 25,
	.bank_min[1] = 26,
	.bank_max[1] = 51,
	.bank_min[3] = 52,
	.bank_max[3] = 83,
	.bank_min[4] = 84,
	.bank_max[4] = 115,
};

/* Max pins in the PS_GPIO devices
 *  00 - 25, Bank 0
 *  26 - 57, Bank 3
 */
#define VERSAL_GPIO_PS_BASE		0xff0b0000
#define VERSAL_GPIO_PS_NR_GPIOS		58
#define VERSAL_GPIO_PS_MAX_BANK		4

static const struct versal_gpio_platform_data versal_gpio_ps_def = {
	.max_bank = VERSAL_GPIO_PS_MAX_BANK,
	.ngpio = VERSAL_GPIO_PS_NR_GPIOS,
	.label = "versal_ps_gpio",
	.bank_min[0] = 0,
	.bank_max[0] = 25,
	.bank_min[3] = 26,
	.bank_max[3] = 57,
};

static void versal_gpio_get_pin(struct versal_gpio_chip *chip, uint32_t gpio,
				uint32_t *bank, uint32_t *pin)
{
	struct versal_gpio_platdata *platdata = &chip->plat;
	uint32_t bnk = 0;

	assert(gpio < platdata->p_data->ngpio);

	for (bnk = 0; bnk < platdata->p_data->max_bank; bnk++) {
		if (gpio < platdata->p_data->bank_min[bnk])
			continue;

		if (gpio > platdata->p_data->bank_max[bnk])
			continue;

		*bank = bnk;
		*pin = gpio - platdata->p_data->bank_min[bnk];

		return;
	}

	EMSG("GPIO_%d not found", gpio);
	panic();
}

static enum gpio_level gpio_get_value(struct versal_gpio_chip *chip,
				      uint32_t gpio)
{
	uint32_t bank = 0;
	uint32_t pin = 0;

	versal_gpio_get_pin(chip, gpio, &bank, &pin);

	return (io_read32(chip->base + DATA_RO_OFFSET(bank)) >> pin) & 1;
}

static void gpio_set_value(struct versal_gpio_chip *chip, uint32_t gpio,
			   enum gpio_level val)
{
	uint32_t bank = 0;
	uint32_t off = 0;
	uint32_t pin = 0;

	versal_gpio_get_pin(chip, gpio, &bank, &pin);

	if (bank >= VERSAL_GPIO_MID_PIN) {
		bank -= VERSAL_GPIO_MID_PIN;
		off = DATA_MSW_OFFSET(bank);
	} else {
		off = DATA_LSW_OFFSET(bank);
	}

	/*
	 * get the 32 bit value to be written to the mask/data register where
	 * the upper 16 bits is the mask and lower 16 bits is the data
	 */
	val = !!val;
	val = ~BIT32(pin + VERSAL_GPIO_MID_PIN) &
	      (SHIFT_U32(val, pin) | VERSAL_GPIO_UPPER_MASK);

	io_write32(chip->base + off, val);
}

static void gpio_set_direction(struct versal_gpio_chip *chip, uint32_t gpio,
			       enum gpio_dir direction)
{
	uint32_t bank = 0;
	uint32_t reg = 0;
	uint32_t pin = 0;

	versal_gpio_get_pin(chip, gpio, &bank, &pin);

	if (direction == GPIO_DIR_OUT) {
		/* set the GPIO pin as output */
		reg = io_read32(chip->base + DIRM_OFFSET(bank));
		reg |= BIT(pin);
		io_write32(chip->base + DIRM_OFFSET(bank), reg);

		/* configure the output enable reg for the pin */
		reg = io_read32(chip->base + OUTEN_OFFSET(bank));

		reg |= BIT(pin);
		io_write32(chip->base + OUTEN_OFFSET(bank), reg);

		/* set the state of the pin */
		gpio_set_value(chip, gpio, GPIO_LEVEL_LOW);
	} else {
		/* bnk 0 pins 7 and 8 cannot be used as inputs */
		assert(!(bank == 0 && (pin == 7 || pin == 8)));

		reg = io_read32(chip->base + DIRM_OFFSET(bank));
		reg &= ~BIT(pin);
		io_write32(chip->base + DIRM_OFFSET(bank), reg);
	}
}

static enum gpio_dir gpio_get_direction(struct versal_gpio_chip *chip,
					uint32_t gpio)
{
	uint32_t pin = 0;
	uint32_t bank = 0;

	versal_gpio_get_pin(chip, gpio, &bank, &pin);

	if (io_read32(chip->base + DIRM_OFFSET(bank)) & BIT(pin))
		return GPIO_DIR_OUT;

	return GPIO_DIR_IN;
}

static enum gpio_level do_get_value(struct gpio_chip *chip, uint32_t gpio)
{
	struct versal_gpio_chip *p = container_of(chip,
						struct versal_gpio_chip, chip);
	return gpio_get_value(p, gpio);
}

static void do_set_value(struct gpio_chip *chip, uint32_t gpio,
			 enum gpio_level val)
{
	struct versal_gpio_chip *p = container_of(chip,
						struct versal_gpio_chip, chip);
	return gpio_set_value(p, gpio, val);
}

static void do_set_dir(struct gpio_chip *chip, uint32_t gpio,
		       enum gpio_dir direction)
{
	struct versal_gpio_chip *p = container_of(chip,
						struct versal_gpio_chip, chip);
	return gpio_set_direction(p, gpio, direction);
}

static enum gpio_dir do_get_dir(struct gpio_chip *chip, uint32_t gpio)
{
	struct versal_gpio_chip *p = container_of(chip,
						struct versal_gpio_chip, chip);
	return gpio_get_direction(p, gpio);
}

static const struct gpio_ops versal_gpio_ops = {
	.get_direction = do_get_dir,
	.set_direction = do_set_dir,
	.get_value = do_get_value,
	.set_value = do_set_value,
	.get_interrupt = NULL,
	.set_interrupt = NULL,
};

TEE_Result versal_gpio_pmc_init(struct versal_gpio_chip *chip)
{
	if (chip->base)
		return TEE_SUCCESS;

	chip->plat.p_data = &versal_gpio_pmc_def;
	chip->plat.base = VERSAL_GPIO_PMC_BASE;
	chip->chip.ops = &versal_gpio_ops;

	chip->base = (vaddr_t)core_mmu_add_mapping(MEM_AREA_IO_SEC,
						   VERSAL_GPIO_PMC_BASE,
						   VERSAL_GPIO_LEN);
	if (!chip->base) {
		EMSG("Failed to map gpio");
		chip->chip.ops = NULL;
		return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}

TEE_Result versal_gpio_ps_init(struct versal_gpio_chip *chip)
{
	if (chip->base)
		return TEE_SUCCESS;

	chip->plat.p_data = &versal_gpio_ps_def;
	chip->plat.base = VERSAL_GPIO_PS_BASE;
	chip->chip.ops = &versal_gpio_ops;

	chip->base = (vaddr_t)core_mmu_add_mapping(MEM_AREA_IO_SEC,
						   VERSAL_GPIO_PS_BASE,
						   VERSAL_GPIO_LEN);
	if (!chip->base) {
		EMSG("Failed to map gpio");
		chip->chip.ops = NULL;
		return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}
