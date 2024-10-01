/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2024, STMicroelectronics
 */

#ifndef __STM32_SYSCONF_H__
#define __STM32_SYSCONF_H__

#include <stdbool.h>
#include <stdint.h>
#include <util.h>

/* syscon banks */
enum syscon_banks {
	SYSCON_SYSCFG,
	SYSCON_A35SSC,
	SYSCON_NB_BANKS
};

#define SYSCON_ID(bank, offset) (((bank) << 16) | \
				((offset) & GENMASK_32(15, 0)))

/*
 * SYSCFG register offsets (base relative)
 */
#define SYSCFG_VDERAMCR		SYSCON_ID(SYSCON_SYSCFG, 0x1800)

/*
 * SYSCFG_VDERAMCR register offsets
 */
#define VDERAMCR_VDERAM_EN		BIT(0)
#define VDERAMCR_MASK			BIT(0)

/*
 * A35SSC register offsets (base relative)
 */
#define A35SS_SSC_CHGCLKREQ	SYSCON_ID(SYSCON_A35SSC, 0x0)
#define A35SS_SSC_PLL_FREQ1	SYSCON_ID(SYSCON_A35SSC, 0x80)
#define A35SS_SSC_PLL_FREQ2	SYSCON_ID(SYSCON_A35SSC, 0x90)
#define A35SS_SSC_PLL_EN	SYSCON_ID(SYSCON_A35SSC, 0xA0)

#define A35SSC_M33CFG_ACCESS_CR  SYSCON_ID(SYSCON_A35SSC, 0x2088)
#define A35SSC_M33_TZEN_CR       SYSCON_ID(SYSCON_A35SSC, 0x20A0)
#define A35SSC_M33_INITSVTOR_CR  SYSCON_ID(SYSCON_A35SSC, 0x20A4)
#define A35SSC_M33_INITNSVTOR_CR SYSCON_ID(SYSCON_A35SSC, 0x20A8)

/*
 * A35SSC M33CFG_ACCESS_CR register
 */
#define A35SSC_M33_TZEN_CR_M33CFG_SEC		BIT(0)
#define A35SSC_M33_TZEN_CR_M33CFG_PRIV		BIT(1)

/*
 * A35SSC M33_TZEN_CR register
 */
#define A35SSC_M33_TZEN_CR_CFG_SECEXT		BIT(0)

/*
 * A35SSC A35SS_SSC_CHGCLKREQ register
 */
#define A35SS_SSC_CHGCLKREQ_ARM_CHGCLKREQ_EN	BIT(0)
#define A35SS_SSC_CHGCLKREQ_ARM_CHGCLKREQ_MASK	BIT(0)

#define A35SS_SSC_CHGCLKREQ_ARM_CHGCLKACK_MASK	BIT(1)
#define A35SS_SSC_CHGCLKREQ_ARM_CHGCLKACK_SHIFT	U(1)

/*
 * A35SSC A35SS_SSC_PLL_FREQ1 register
 */
#define A35SS_SSC_PLL_FREQ1_FBDIV_MASK		GENMASK_32(11, 0)
#define A35SS_SSC_PLL_FREQ1_FBDIV_SHIFT		U(0)

#define A35SS_SSC_PLL_FREQ1_REFDIV_MASK		GENMASK_32(21, 16)
#define A35SS_SSC_PLL_FREQ1_REFDIV_SHIFT	U(16)

#define A35SS_SSC_PLL_FREQ1_MASK	(A35SS_SSC_PLL_FREQ1_REFDIV_MASK | \
					 A35SS_SSC_PLL_FREQ1_FBDIV_MASK)

/*
 * A35SSC A35SS_SSC_PLL_FREQ2 register
 */
#define A35SS_SSC_PLL_FREQ2_POSTDIV1_MASK	GENMASK_32(2, 0)
#define A35SS_SSC_PLL_FREQ2_POSTDIV1_SHIFT	U(0)

#define A35SS_SSC_PLL_FREQ2_POSTDIV2_MASK	GENMASK_32(5, 3)
#define A35SS_SSC_PLL_FREQ2_POSTDIV2_SHIFT	U(3)

#define A35SS_SSC_PLL_FREQ2_MASK		GENMASK_32(5, 0)

/*
 * A35SSC A35SS_SSC_PLL_EN register
 */
#define A35SS_SSC_PLL_ENABLE_PD_EN			BIT(0)
#define A35SS_SSC_PLL_ENABLE_PD_MASK			BIT(0)

#define A35SS_SSC_PLL_ENABLE_LOCKP_MASK			BIT(1)

#define A35SS_SSC_PLL_ENABLE_NRESET_SWPLL_FF_EN		BIT(2)
#define A35SS_SSC_PLL_ENABLE_NRESET_SWPLL_FF_MASK	BIT(2)

/*
 * Write masked value is SYSCONF register
 * @id: SYSCONF register ID, processed with SYSCON_ID() macro
 * @value: Value to be written
 * @bitmsk: Bit mask applied to @value
 */
void stm32mp_syscfg_write(uint32_t id, uint32_t value, uint32_t bitmsk);

/*
 * Read SYSCONF reagister
 * @id: SYSCONF register ID, processed with SYSCON_ID() macro
 */
uint32_t stm32mp_syscfg_read(uint32_t id);

/*
 * Set safe reset state
 * @status: True to enable safe reset, false to disable safe reset
 */
void stm32mp25_syscfg_set_safe_reset(bool status);

#endif /*__STM32_SYSCONF_H__*/
