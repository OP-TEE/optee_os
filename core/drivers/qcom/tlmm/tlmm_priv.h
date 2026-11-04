/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __QCOM_TLMM_PRIV_H__
#define __QCOM_TLMM_PRIV_H__

#include <drivers/qcom/tlmm/tlmm.h>
#include <io.h>
#include <kernel/mutex.h>
#include <stdint.h>
#include <tee_api_types.h>
#include <trace.h>

#define TLMM_CFG_PULL_MASK		GENMASK_32(1, 0)
#define TLMM_CFG_FUNC_SHIFT		U(2)
#define TLMM_CFG_FUNC_MASK		GENMASK_32(5, 2)
#define TLMM_CFG_DRIVE_SHIFT		U(6)
#define TLMM_CFG_DRIVE_MASK		GENMASK_32(8, 6)
#define TLMM_CFG_OE			BIT(9)
#define TLMM_CFG_HIHYS			BIT(10)
#define TLMM_CFG_EGPIO_PRESENT		BIT(11)
#define TLMM_CFG_EGPIO_ENABLE		BIT(12)
#define TLMM_CFG_STRONG_PULL		BIT(13)
#define TLMM_CFG_PRESERVE_MASK		TLMM_CFG_HIHYS

#define TLMM_IN_OUT_IN_BIT		BIT(0)
#define TLMM_IN_OUT_OUT_BIT		BIT(1)

#define TLMM_ID_STATUS_PRESENT		BIT(0)

/*
 * GPIO_LP_CFG bits [9:0] match GPIO_CFG, but bit 10 is the stored output
 * level and bit 11 flags a valid low-power config, so restore-on-release is
 * not a plain masked copy into GPIO_CFG.
 */
#define TLMM_LP_CFG_OUT_VAL		BIT(10)
#define TLMM_LP_CFG_APPLIED		BIT(11)
#define TLMM_LP_CFG_CONFIG_MASK		GENMASK_32(9, 0)

#define TLMM_MAX_GPIOS			U(256)

#define TLMM_REG_CFG			U(0x00)
#define TLMM_REG_IN_OUT			U(0x04)
#define TLMM_REG_ID_STATUS		U(0x10)
#define TLMM_REG_LP_CFG			U(0x14)

struct tlmm_chip {
	struct gpio_chip gpio_chip;
	vaddr_t base;
	const struct tlmm_desc *desc;
	/* Serialises @pin_owners and the GPIO_CFG read-modify-writes */
	struct mutex lock;
	uint32_t pin_owners[TLMM_MAX_GPIOS / 32];
};

uint32_t tlmm_tile_offset(const struct tlmm_chip *chip, unsigned int pin);
vaddr_t tlmm_pin_reg(const struct tlmm_chip *chip, unsigned int pin,
		     uint32_t reg_off);

/*
 * A GPIO_CFG update is a read-modify-write, and the pin ownership bitmap must
 * not change between the ownership check and the register write, so both are
 * serialised by @chip->lock. Callers already holding the lock use the
 * _unlocked() variant; the locking wrapper is for callers that do not.
 *
 * @chip->lock is a mutex, so every caller must be in thread context.
 */
void tlmm_write_cfg_unlocked(struct tlmm_chip *chip, unsigned int pin,
			     uint32_t clear_mask, uint32_t set_mask);
void tlmm_write_cfg(struct tlmm_chip *chip, unsigned int pin,
		    uint32_t clear_mask, uint32_t set_mask);

/* Both require @chip->lock to be held by the caller */
bool tlmm_pin_is_owned_unlocked(unsigned int pin);
void tlmm_restore_lp(struct tlmm_chip *chip, unsigned int pin);

/*
 * EGPIO_PRESENT is read-only and set by hardware only on pads shared with an
 * Island TLMM, where EGPIO_ENABLE picks the owner: 1 gives the pad to the chip
 * TLMM, 0 leaves it with the Island domain. It reads 0 out of reset, so a
 * shared pad comes up Island-owned and the registers this driver programs do
 * not reach it until the pad is claimed.
 */
void tlmm_claim_egpio_unlocked(struct tlmm_chip *chip, unsigned int pin);

#define TLMM_GPIO_CFG(c, p)		tlmm_pin_reg((c), (p), TLMM_REG_CFG)
#define TLMM_GPIO_IN_OUT(c, p)		tlmm_pin_reg((c), (p), TLMM_REG_IN_OUT)
#define TLMM_GPIO_ID_STATUS(c, p)	\
	tlmm_pin_reg((c), (p), TLMM_REG_ID_STATUS)
#define TLMM_GPIO_LP_CFG(c, p)		tlmm_pin_reg((c), (p), TLMM_REG_LP_CFG)

extern struct tlmm_chip tlmm;

#endif /* __QCOM_TLMM_PRIV_H__ */
