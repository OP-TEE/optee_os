// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <assert.h>
#include <drivers/gpio.h>
#include <drivers/qcom/tlmm/tlmm.h>
#include <initcall.h>
#include <io.h>
#include <kernel/mutex.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <trace.h>
#include <util.h>

#include "tlmm_priv.h"

register_phys_mem_pgdir(MEM_AREA_IO_SEC, TLMM_BASE, TLMM_BASE_SIZE);

struct tlmm_chip tlmm = {
	.lock = MUTEX_INITIALIZER,
};

static const struct gpio_ops tlmm_gpio_ops;

uint32_t tlmm_tile_offset(const struct tlmm_chip *chip, unsigned int pin)
{
	const struct tlmm_desc *d = chip->desc;
	unsigned int t = 0;
	vaddr_t id_reg = 0;

	if (d->num_tiles <= 1)
		return d->tile_offsets[0];

	for (t = 0; t < d->num_tiles; t++) {
		id_reg = chip->base +
			 d->tile_offsets[t] +
			 (vaddr_t)d->pin_reg_width * pin +
			 TLMM_REG_ID_STATUS;
		if (io_read32(id_reg) & TLMM_ID_STATUS_PRESENT)
			return d->tile_offsets[t];
	}

	EMSG("TLMM: pin %u not found in any tile, defaulting to tile 0", pin);
	return d->tile_offsets[0];
}

vaddr_t tlmm_pin_reg(const struct tlmm_chip *chip, unsigned int pin,
		     uint32_t reg_off)
{
	return chip->base +
	       tlmm_tile_offset(chip, pin) +
	       (vaddr_t)chip->desc->pin_reg_width * pin +
	       reg_off;
}

void tlmm_claim_egpio_unlocked(struct tlmm_chip *chip, unsigned int pin)
{
	vaddr_t reg = TLMM_GPIO_CFG(chip, pin);
	uint32_t val = io_read32(reg);

	if (!chip->desc->has_egpio || !(val & TLMM_CFG_EGPIO_PRESENT))
		return;

	if (val & TLMM_CFG_EGPIO_ENABLE)
		return;

	io_write32(reg, val | TLMM_CFG_EGPIO_ENABLE);
}

void tlmm_write_cfg_unlocked(struct tlmm_chip *chip, unsigned int pin,
			     uint32_t clear_mask, uint32_t set_mask)
{
	vaddr_t reg = TLMM_GPIO_CFG(chip, pin);

	tlmm_claim_egpio_unlocked(chip, pin);

	clear_mask &= ~TLMM_CFG_PRESERVE_MASK;
	io_clrsetbits32(reg, clear_mask, set_mask);
}

void tlmm_write_cfg(struct tlmm_chip *chip, unsigned int pin,
		    uint32_t clear_mask, uint32_t set_mask)
{
	mutex_lock(&chip->lock);
	tlmm_write_cfg_unlocked(chip, pin, clear_mask, set_mask);
	mutex_unlock(&chip->lock);
}

static bool __maybe_unused is_tlmm_chip(struct gpio_chip *chip)
{
	return chip && chip->ops == &tlmm_gpio_ops;
}

static struct tlmm_chip *chip_to_tlmm(struct gpio_chip *chip)
{
	assert(is_tlmm_chip(chip));
	return container_of(chip, struct tlmm_chip, gpio_chip);
}

bool tlmm_pin_is_owned_unlocked(unsigned int pin)
{
	if (!tlmm.desc)
		return false;

	if (pin >= TLMM_MAX_GPIOS || pin >= tlmm.desc->num_gpios)
		return false;

	return tlmm.pin_owners[pin / 32] & BIT(pin % 32);
}

void tlmm_restore_lp(struct tlmm_chip *chip, unsigned int pin)
{
	uint32_t lp_val = io_read32(TLMM_GPIO_LP_CFG(chip, pin));

	if (!(lp_val & TLMM_LP_CFG_APPLIED))
		return;

	io_write32(TLMM_GPIO_IN_OUT(chip, pin),
		   (lp_val & TLMM_LP_CFG_OUT_VAL) ? TLMM_IN_OUT_OUT_BIT : U(0));

	io_write32(TLMM_GPIO_CFG(chip, pin), lp_val & TLMM_LP_CFG_CONFIG_MASK);
}

TEE_Result tlmm_request_pin(unsigned int pin)
{
	if (!tlmm.desc)
		return TEE_ERROR_BAD_STATE;

	if (pin >= TLMM_MAX_GPIOS || pin >= tlmm.desc->num_gpios)
		return TEE_ERROR_BAD_PARAMETERS;

	mutex_lock(&tlmm.lock);
	if (tlmm_pin_is_owned_unlocked(pin)) {
		mutex_unlock(&tlmm.lock);
		EMSG("TLMM: pin %u already owned", pin);
		return TEE_ERROR_BUSY;
	}
	tlmm.pin_owners[pin / 32] |= BIT(pin % 32);
	mutex_unlock(&tlmm.lock);

	return TEE_SUCCESS;
}

void tlmm_release_pin(unsigned int pin)
{
	if (!tlmm.desc)
		return;

	if (pin >= TLMM_MAX_GPIOS || pin >= tlmm.desc->num_gpios)
		return;

	mutex_lock(&tlmm.lock);
	if (!tlmm_pin_is_owned_unlocked(pin)) {
		mutex_unlock(&tlmm.lock);
		EMSG("TLMM: pin %u not owned, release rejected", pin);
		return;
	}
	tlmm_restore_lp(&tlmm, pin);
	tlmm.pin_owners[pin / 32] &= ~BIT(pin % 32);
	mutex_unlock(&tlmm.lock);
}

static enum gpio_dir tlmm_get_direction(struct gpio_chip *chip,
					unsigned int pin)
{
	struct tlmm_chip *tc = chip_to_tlmm(chip);

	if (pin >= tc->desc->num_gpios) {
		EMSG("TLMM: pin %u out of range", pin);
		return GPIO_DIR_IN;
	}

	return (io_read32(TLMM_GPIO_CFG(tc, pin)) & TLMM_CFG_OE) ?
		GPIO_DIR_OUT : GPIO_DIR_IN;
}

static void tlmm_set_direction(struct gpio_chip *chip, unsigned int pin,
			       enum gpio_dir dir)
{
	struct tlmm_chip *tc = chip_to_tlmm(chip);

	assert(pin < tc->desc->num_gpios);

	mutex_lock(&tc->lock);
	if (!tlmm_pin_is_owned_unlocked(pin)) {
		mutex_unlock(&tc->lock);
		EMSG("TLMM: pin %u not owned, set_direction rejected", pin);
		return;
	}
	if (dir == GPIO_DIR_OUT)
		tlmm_write_cfg_unlocked(tc, pin, 0, TLMM_CFG_OE);
	else
		tlmm_write_cfg_unlocked(tc, pin, TLMM_CFG_OE, 0);
	mutex_unlock(&tc->lock);
}

static enum gpio_level tlmm_get_value(struct gpio_chip *chip, unsigned int pin)
{
	struct tlmm_chip *tc = chip_to_tlmm(chip);

	if (pin >= tc->desc->num_gpios) {
		EMSG("TLMM: pin %u out of range", pin);
		return GPIO_LEVEL_LOW;
	}

	return (io_read32(TLMM_GPIO_IN_OUT(tc, pin)) & TLMM_IN_OUT_IN_BIT) ?
		GPIO_LEVEL_HIGH : GPIO_LEVEL_LOW;
}

static void tlmm_set_value(struct gpio_chip *chip, unsigned int pin,
			   enum gpio_level level)
{
	struct tlmm_chip *tc = chip_to_tlmm(chip);

	assert(pin < tc->desc->num_gpios);

	mutex_lock(&tc->lock);
	if (!tlmm_pin_is_owned_unlocked(pin)) {
		mutex_unlock(&tc->lock);
		EMSG("TLMM: pin %u not owned, set_value rejected", pin);
		return;
	}
	tlmm_claim_egpio_unlocked(tc, pin);
	io_write32(TLMM_GPIO_IN_OUT(tc, pin),
		   (level == GPIO_LEVEL_HIGH) ? TLMM_IN_OUT_OUT_BIT : U(0));
	mutex_unlock(&tc->lock);
}

static const struct gpio_ops tlmm_gpio_ops = {
	.get_direction = tlmm_get_direction,
	.set_direction = tlmm_set_direction,
	.get_value = tlmm_get_value,
	.set_value = tlmm_set_value,
};

struct gpio_chip *tlmm_get_chip(void)
{
	if (!tlmm.desc)
		return NULL;

	return &tlmm.gpio_chip;
}

static TEE_Result tlmm_init(void)
{
	const struct tlmm_desc *desc = &tlmm_soc_desc;

	tlmm.base = (vaddr_t)phys_to_virt(desc->base, MEM_AREA_IO_SEC,
					  desc->size);
	if (!tlmm.base) {
		EMSG("TLMM: failed to map base 0x%"PRIxPA, desc->base);
		return TEE_ERROR_GENERIC;
	}

	tlmm.desc = desc;
	tlmm.gpio_chip.ops = &tlmm_gpio_ops;

	IMSG("TLMM: base=0x%"PRIxPA", %u GPIOs", desc->base, desc->num_gpios);

	return TEE_SUCCESS;
}

driver_init(tlmm_init);
