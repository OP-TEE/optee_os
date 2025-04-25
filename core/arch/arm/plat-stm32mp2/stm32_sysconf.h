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
	SYSCON_CA35SS,
	SYSCON_NB_BANKS
};

#define SYSCON_ID(bank, offset) (((bank) << 16) | \
				((offset) & GENMASK_32(15, 0)))

/*
 * SYSCFG register offsets (base relative)
 */
#define SYSCFG_VDERAMCR		SYSCON_ID(SYSCON_SYSCFG, 0x1800)

/*
 * SYSCFG_VDERAMCR register fields
 */
#define VDERAMCR_VDERAM_EN		BIT(0)
#define VDERAMCR_MASK			BIT(0)

/*
 * CA35SS register offsets (base relative)
 * Standardized Status and Control registers (SSC) access modes.
 */
#define CA35SS_SSC_CHGCLKREQ		SYSCON_ID(SYSCON_CA35SS, 0x0U)
#define CA35SS_SSC_PLL_FREQ1		SYSCON_ID(SYSCON_CA35SS, 0x80U)
#define CA35SS_SSC_PLL_FREQ2		SYSCON_ID(SYSCON_CA35SS, 0x90U)
#define CA35SS_SSC_PLL_EN		SYSCON_ID(SYSCON_CA35SS, 0xA0U)

/*
 * CA35SS_SSC_CHGCLKREQ register fields
 */
#define CA35SS_SSC_CHGCLKREQ_ARM_CHGCLKREQ		BIT(0)
#define CA35SS_SSC_CHGCLKREQ_ARM_CHGCLKREQ_MASK		BIT(0)

#define CA35SS_SSC_CHGCLKREQ_ARM_CHGCLKACK_MASK		BIT(1)
#define CA35SS_SSC_CHGCLKREQ_ARM_CHGCLKACK_SHIFT	U(1)

#define CA35SS_SSC_CHGCLKREQ_ARM_DIVSEL		BIT(16)
#define CA35SS_SSC_CHGCLKREQ_ARM_DIVSELACK	BIT(17)

/*
 * CA35SS_SSC_PLL_FREQ1 register fields
 */
#define CA35SS_SSC_PLL_FREQ1_FBDIV_MASK		GENMASK_32(11, 0)
#define CA35SS_SSC_PLL_FREQ1_FBDIV_SHIFT	U(0)

#define CA35SS_SSC_PLL_FREQ1_REFDIV_MASK	GENMASK_32(21, 16)
#define CA35SS_SSC_PLL_FREQ1_REFDIV_SHIFT	U(16)

#define CA35SS_SSC_PLL_FREQ1_MASK	(CA35SS_SSC_PLL_FREQ1_REFDIV_MASK | \
					 CA35SS_SSC_PLL_FREQ1_FBDIV_MASK)

/*
 * CA35SS_SSC_PLL_FREQ2 register fields
 */
#define CA35SS_SSC_PLL_FREQ2_POSTDIV1_MASK	GENMASK_32(2, 0)
#define CA35SS_SSC_PLL_FREQ2_POSTDIV1_SHIFT	U(0)

#define CA35SS_SSC_PLL_FREQ2_POSTDIV2_MASK	GENMASK_32(5, 3)
#define CA35SS_SSC_PLL_FREQ2_POSTDIV2_SHIFT	U(3)

#define CA35SS_SSC_PLL_FREQ2_MASK		GENMASK_32(5, 0)

/*
 * CA35SS_SSC_PLL_EN register fields
 */
#define CA35SS_SSC_PLL_EN_PLL_EN		BIT(0)

#define CA35SS_SSC_PLL_EN_LOCKP_MASK		BIT(1)

#define CA35SS_SSC_PLL_EN_NRESET_SWPLL		BIT(2)
#define CA35SS_SSC_PLL_EN_NRESET_SWPLL_MASK	BIT(2)

/*
 * CA35SS_SYSCFG registers
 */
#define CA35SS_SYSCFG_M33_ACCESS_CR	SYSCON_ID(SYSCON_CA35SS, 0x2088U)
#define CA35SS_SYSCFG_M33_TZEN_CR	SYSCON_ID(SYSCON_CA35SS, 0x20A0U)
#define CA35SS_SYSCFG_M33_INITSVTOR_CR	SYSCON_ID(SYSCON_CA35SS, 0x20A4U)
#define CA35SS_SYSCFG_M33_INITNSVTOR_CR	SYSCON_ID(SYSCON_CA35SS, 0x20A8U)

/*
 * CA35SS_SYSCFG_M33_ACCESS_CR register offsets
 */
#define CA35SS_SYSCFG_M33_ACCESS_CR_SEC			BIT(0)
#define CA35SS_SYSCFG_M33_ACCESS_CR_PRIV		BIT(1)

/*
 * CA35SS_SYSCFG_M33_TZEN_CR register offsets
 */
#define CA35SS_SYSCFG_M33_TZEN_CR_CFG_SECEXT		BIT(0)

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

/*
 * Manage OSPI address mapping
 * @mm1_size: Size of memory addressed by the OSPI1 peripheral
 * @mm2_size: Size of memory addressed by the OSPI2 peripheral
 */
void stm32mp25_syscfg_set_amcr(size_t mm1_size, size_t mm2_size);

#endif /*__STM32_SYSCONF_H__*/
