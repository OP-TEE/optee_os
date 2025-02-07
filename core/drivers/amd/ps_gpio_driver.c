// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2002-2021 Xilinx, Inc.  All rights reserved.
 * Copyright (c) 2022 Foundries.io Ltd. (jorge@foundries.io)
 * Copyright (c) 2024-2025, Advanced Micro Devices, Inc. All rights reserved.
 *
 */

#include <assert.h>
#include <drivers/gpio.h>
#include <io.h>
#include <kernel/dt.h>
#include <kernel/panic.h>
#include <libfdt.h>
#include <malloc.h>
#include <mm/core_mmu.h>
#include <stdbool.h>
#include <stdint.h>
#include <trace.h>
#include <util.h>

#include "gpio_private.h"

static struct amd_gbank_data ps_bank = {
	.label = "ps_gpio",
	.ngpio = 58,
	.max_bank = PS_BANK_MAX,
	.bank_min[0] = 0,
	.bank_max[0] = 25,
	.bank_min[3] = 26,
	.bank_max[3] = 57,
};

/* Standard GPIO Operations */
static enum gpio_level ps_gpio_get_value(struct gpio_chip *chip,
					 unsigned int gpio_pin)
{
	uint32_t bank = 0;
	uint32_t pin = 0;
	struct amd_gpio_info *ps = container_of(chip, struct amd_gpio_info,
						chip);

	amd_gpio_get_bank_and_pin(ps->bdata, gpio_pin, &bank, &pin);

	if (io_read32(ps->vbase + DATA_RO_OFFSET(bank)) & BIT(pin))
		return GPIO_LEVEL_HIGH;

	return GPIO_LEVEL_LOW;
}

static void ps_gpio_set_value(struct gpio_chip *chip,
			      unsigned int gpio_pin,
			      enum gpio_level level)
{
	uint32_t bank = 0;
	uint32_t pin = 0;
	uint32_t offset = 0;
	uint32_t lvl = 0;
	struct amd_gpio_info *ps = container_of(chip, struct amd_gpio_info,
						chip);

	amd_gpio_get_bank_and_pin(ps->bdata, gpio_pin, &bank, &pin);

	if (pin < GPIO_NUM_MAX) {
		offset = DATA_LSW_OFFSET(bank);
	} else {
		pin -= GPIO_NUM_MAX;
		offset = DATA_MSW_OFFSET(bank);
	}

	/* Explicitly compare the enum value */
	if (level == GPIO_LEVEL_HIGH)
		lvl = 1;
	else
		lvl = 0;

	lvl = ~BIT32(pin + GPIO_NUM_MAX) &
		(SHIFT_U32(lvl, pin) | GPIO_UPPER_MASK);

	io_write32(ps->vbase + offset, lvl);
}

static enum gpio_dir ps_gpio_get_dir(struct gpio_chip *chip,
				     unsigned int gpio_pin)
{
	uint32_t bank = 0;
	uint32_t pin = 0;
	struct amd_gpio_info *ps = container_of(chip, struct amd_gpio_info,
						chip);

	amd_gpio_get_bank_and_pin(ps->bdata, gpio_pin, &bank, &pin);

	if (io_read32(ps->vbase + DIRM_OFFSET(bank)) & BIT(pin))
		return GPIO_DIR_OUT;

	return GPIO_DIR_IN;
}

static void ps_gpio_set_dir(struct gpio_chip *chip,
			    unsigned int gpio_pin,
			    enum gpio_dir direction)
{
	uint32_t bank = 0;
	uint32_t pin = 0;
	struct amd_gpio_info *ps = container_of(chip, struct amd_gpio_info,
						chip);

	amd_gpio_get_bank_and_pin(ps->bdata, gpio_pin, &bank, &pin);

	if (direction == GPIO_DIR_OUT) {
		/* set the GPIO pin as output */
		io_setbits32(ps->vbase + DIRM_OFFSET(bank), BIT(pin));

		/* configure the output enable reg for the pin */
		io_setbits32(ps->vbase + OUTEN_OFFSET(bank), BIT(pin));

		/* set the state of the pin */
		ps_gpio_set_value(chip, gpio_pin, GPIO_LEVEL_LOW);
	} else {
		/* Set the GPIO pin as input */
		io_clrbits32(ps->vbase + DIRM_OFFSET(bank), BIT(pin));
	}
}

static enum gpio_interrupt ps_gpio_get_intr(struct gpio_chip *chip,
					    unsigned int gpio_pin)
{
	uint32_t bank = 0;
	uint32_t pin = 0;
	struct amd_gpio_info *ps = container_of(chip, struct amd_gpio_info,
						chip);

	amd_gpio_get_bank_and_pin(ps->bdata, gpio_pin, &bank, &pin);

	if ((io_read32(ps->vbase + INTMASK_OFFSET(bank)) & BIT(pin)))
		return GPIO_INTERRUPT_DISABLE;

	return GPIO_INTERRUPT_ENABLE;
}

static void ps_gpio_set_intr(struct gpio_chip *chip,
			     unsigned int gpio_pin,
			     enum gpio_interrupt interrupt)
{
	uint32_t bank = 0;
	uint32_t pin = 0;
	uint32_t offset = 0;
	uint32_t mask = 0;
	struct amd_gpio_info *ps = container_of(chip, struct amd_gpio_info,
						chip);

	amd_gpio_get_bank_and_pin(ps->bdata, gpio_pin, &bank, &pin);

	mask = io_read32(ps->vbase + INTMASK_OFFSET(bank)) & BIT(pin);

	/*
	 * mask = 1 --> Interrupt is masked/disabled.
	 * mask = 0 --> Interrupt is un-masked/enabled.
	 */
	if (mask && interrupt == GPIO_INTERRUPT_ENABLE) {
		offset = INTEN_OFFSET(bank);
	} else if (!mask && interrupt == GPIO_INTERRUPT_DISABLE) {
		offset = INTDIS_OFFSET(bank);
	} else {
		DMSG("No change, interrupt already %s",
		     interrupt ? "Enabled" : "Disabled");
		return;
	}

	io_setbits32(ps->vbase + offset, BIT(pin));
}

static const struct gpio_ops ps_gpio_ops = {
	.get_direction = ps_gpio_get_dir,
	.set_direction = ps_gpio_set_dir,
	.get_value = ps_gpio_get_value,
	.set_value = ps_gpio_set_value,
	.get_interrupt = ps_gpio_get_intr,
	.set_interrupt = ps_gpio_set_intr,
};

static TEE_Result amd_ps_gpio_probe(const void *fdt, int node,
				    const void *compat_data __unused)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	int status = DT_STATUS_DISABLED;
	struct amd_gpio_info *ps_gpio = NULL;
	paddr_t base = 0;
	size_t len = 0;

	/* Status Check */
	status = fdt_get_status(fdt, node);

	/* PS GPIO Controller to be in Non Secure World */
	if (status & DT_STATUS_OK_NSEC) {
		DMSG("PS GPIO controller configured for NS world");
		return TEE_SUCCESS;
	}

	/* PS GPIO Controller is disabled for Secure World as well */
	if (!(status & DT_STATUS_OK_SEC)) {
		DMSG("PS GPIO Controller is disabled");
		return TEE_SUCCESS;
	}

	ps_gpio = calloc(1, sizeof(*ps_gpio));
	if (!ps_gpio) {
		EMSG("Failed to allocate memory for ps_gpio");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	if (fdt_reg_info(fdt, node, &base, &len) != 0) {
		EMSG("Failed to get Register Base and Size");
		free(ps_gpio);
		return TEE_ERROR_GENERIC;
	}

	/* Populate GPIO ops */
	ps_gpio->chip.ops = &ps_gpio_ops;
	/* Populate Bank information */
	ps_gpio->bdata = &ps_bank;

	/* Validate node entries */
	assert(base);
	assert(len);

	ps_gpio->vbase = (vaddr_t)core_mmu_add_mapping(MEM_AREA_IO_SEC, base,
						       len);
	if (!ps_gpio->vbase) {
		EMSG("AMD PS GPIO initialization Failed");
		free(ps_gpio);
		return TEE_ERROR_GENERIC;
	}

	res = gpio_register_provider(fdt, node, amd_gpio_get_dt, ps_gpio);
	if (res) {
		EMSG("Failed to register PS GPIO Provider");
		/* Ignoring return value */
		core_mmu_remove_mapping(MEM_AREA_IO_SEC,
					(void *)ps_gpio->vbase, len);
		free(ps_gpio);
		return res;
	}

	DMSG("AMD PS GPIO initialized");

	return TEE_SUCCESS;
}

GPIO_DT_DECLARE(amd_ps_gpio, "xlnx,versal-gpio-1.0", amd_ps_gpio_probe);
