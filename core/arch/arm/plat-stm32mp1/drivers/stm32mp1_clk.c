// SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0+)
/*
 * Copyright (C) 2018-2019, STMicroelectronics
 */

#include <assert.h>
#include <drivers/stm32mp1_rcc.h>
#include <dt-bindings/clock/stm32mp1-clks.h>
#include <initcall.h>
#include <io.h>
#include <keep.h>
#include <kernel/dt.h>
#include <kernel/boot.h>
#include <kernel/panic.h>
#include <kernel/spinlock.h>
#include <libfdt.h>
#include <platform_config.h>
#include <stdio.h>
#include <stm32_util.h>
#include <trace.h>
#include <util.h>

/* Identifiers for root oscillators */
enum stm32mp_osc_id {
	_HSI = 0,
	_HSE,
	_CSI,
	_LSI,
	_LSE,
	_I2S_CKIN,
	_USB_PHY_48,
	NB_OSC,
	_UNKNOWN_OSC_ID = 0xffU
};

/* Identifiers for parent clocks */
enum stm32mp1_parent_id {
/*
 * Oscillators are valid IDs for parent clock and are already
 * defined in enum stm32mp_osc_id, ending at NB_OSC - 1.
 * This enum defines IDs are the other possible clock parents.
 */
	_HSI_KER = NB_OSC,
	_HSE_KER,
	_HSE_KER_DIV2,
	_CSI_KER,
	_PLL1_P,
	_PLL1_Q,
	_PLL1_R,
	_PLL2_P,
	_PLL2_Q,
	_PLL2_R,
	_PLL3_P,
	_PLL3_Q,
	_PLL3_R,
	_PLL4_P,
	_PLL4_Q,
	_PLL4_R,
	_ACLK,
	_PCLK1,
	_PCLK2,
	_PCLK3,
	_PCLK4,
	_PCLK5,
	_HCLK5,
	_HCLK6,
	_HCLK2,
	_CK_PER,
	_CK_MPU,
	_CK_MCU,
	_PARENT_NB,
	_UNKNOWN_ID = 0xff,
};

/*
 * Identifiers for parent clock selectors.
 * This enum lists only the parent clocks we are interested in.
 */
enum stm32mp1_parent_sel {
	_STGEN_SEL,
	_I2C46_SEL,
	_SPI6_SEL,
	_USART1_SEL,
	_RNG1_SEL,
	_UART6_SEL,
	_UART24_SEL,
	_UART35_SEL,
	_UART78_SEL,
	_AXISS_SEL,
	_MCUSS_SEL,
	_USBPHY_SEL,
	_USBO_SEL,
	_RTC_SEL,
	_PARENT_SEL_NB,
	_UNKNOWN_SEL = 0xff,
};

static const uint8_t parent_id_clock_id[_PARENT_NB] = {
	[_HSE] = CK_HSE,
	[_HSI] = CK_HSI,
	[_CSI] = CK_CSI,
	[_LSE] = CK_LSE,
	[_LSI] = CK_LSI,
	[_I2S_CKIN] = _UNKNOWN_ID,
	[_USB_PHY_48] = _UNKNOWN_ID,
	[_HSI_KER] = CK_HSI,
	[_HSE_KER] = CK_HSE,
	[_HSE_KER_DIV2] = CK_HSE_DIV2,
	[_CSI_KER] = CK_CSI,
	[_PLL1_P] = PLL1_P,
	[_PLL1_Q] = PLL1_Q,
	[_PLL1_R] = PLL1_R,
	[_PLL2_P] = PLL2_P,
	[_PLL2_Q] = PLL2_Q,
	[_PLL2_R] = PLL2_R,
	[_PLL3_P] = PLL3_P,
	[_PLL3_Q] = PLL3_Q,
	[_PLL3_R] = PLL3_R,
	[_PLL4_P] = PLL4_P,
	[_PLL4_Q] = PLL4_Q,
	[_PLL4_R] = PLL4_R,
	[_ACLK] = CK_AXI,
	[_PCLK1] = CK_AXI,
	[_PCLK2] = CK_AXI,
	[_PCLK3] = CK_AXI,
	[_PCLK4] = CK_AXI,
	[_PCLK5] = CK_AXI,
	[_HCLK5] = CK_AXI,
	[_HCLK6] = CK_AXI,
	[_HCLK2] = CK_AXI,
	[_CK_PER] = CK_PER,
	[_CK_MPU] = CK_MPU,
	[_CK_MCU] = CK_MCU,
};

static enum stm32mp1_parent_id clock_id2parent_id(unsigned long id)
{
	size_t n = 0;

	COMPILE_TIME_ASSERT(STM32MP1_LAST_CLK < _UNKNOWN_ID);

	for (n = 0; n < ARRAY_SIZE(parent_id_clock_id); n++)
		if (parent_id_clock_id[n] == id)
			return (enum stm32mp1_parent_id)n;

	return _UNKNOWN_ID;
}

/* Identifiers for PLLs and their configuration resources */
enum stm32mp1_pll_id {
	_PLL1,
	_PLL2,
	_PLL3,
	_PLL4,
	_PLL_NB
};

enum stm32mp1_div_id {
	_DIV_P,
	_DIV_Q,
	_DIV_R,
	_DIV_NB,
};

enum stm32mp1_plltype {
	PLL_800,
	PLL_1600,
	PLL_TYPE_NB
};

/*
 * Clock generic gates clocks which state is controlled by a single RCC bit
 *
 * @offset: RCC register byte offset from RCC base where clock is controlled
 * @bit: Bit position in the RCC 32bit register
 * @clock_id: Identifier used for the clock in the clock driver API
 * @set_clr: Non-null if and only-if RCC register is a CLEAR/SET register
 *	(CLEAR register is at offset RCC_MP_ENCLRR_OFFSET from SET register)
 * @secure: One of N_S or SEC, defined below
 * @sel: _UNKNOWN_ID (fixed parent) or reference to parent clock selector
 *	(8bit storage of ID from enum stm32mp1_parent_sel)
 * @fixed: _UNKNOWN_ID (selectable paranet) or reference to parent clock
 *	(8bit storage of ID from enum stm32mp1_parent_id)
 */
struct stm32mp1_clk_gate {
	uint16_t offset;
	uint8_t bit;
	uint8_t clock_id;
	uint8_t set_clr;
	uint8_t secure;
	uint8_t sel; /* Relates to enum stm32mp1_parent_sel */
	uint8_t fixed; /* Relates to enum stm32mp1_parent_id */
};

/* Parent clock selection: select register info, parent clocks references */
struct stm32mp1_clk_sel {
	uint16_t offset;
	uint8_t src;
	uint8_t msk;
	uint8_t nb_parent;
	const uint8_t *parent;
};

#define REFCLK_SIZE 4
/* PLL control: type, control register offsets, up-to-4 selectable parent */
struct stm32mp1_clk_pll {
	enum stm32mp1_plltype plltype;
	uint16_t rckxselr;
	uint16_t pllxcfgr1;
	uint16_t pllxcfgr2;
	uint16_t pllxfracr;
	uint16_t pllxcr;
	uint16_t pllxcsgr;
	enum stm32mp_osc_id refclk[REFCLK_SIZE];
};

#define N_S	0	/* Non-secure can access RCC interface */
#define SEC	1	/* RCC[TZEN] protects RCC interface */

/* Clocks with selectable source and not set/clr register access */
#define _CLK_SELEC(_sec, _offset, _bit, _clock_id, _parent_sel)	\
	{							\
		.offset = (_offset),				\
		.bit = (_bit),					\
		.clock_id = (_clock_id),			\
		.set_clr = 0,					\
		.secure = (_sec),				\
		.sel = (_parent_sel),				\
		.fixed = _UNKNOWN_ID,				\
	}

/* Clocks with fixed source and not set/clr register access */
#define _CLK_FIXED(_sec, _offset, _bit, _clock_id, _parent)		\
	{							\
		.offset = (_offset),				\
		.bit = (_bit),					\
		.clock_id = (_clock_id),			\
		.set_clr = 0,					\
		.secure = (_sec),				\
		.sel = _UNKNOWN_SEL,				\
		.fixed = (_parent),				\
	}

/* Clocks with selectable source and set/clr register access */
#define _CLK_SC_SELEC(_sec, _offset, _bit, _clock_id, _parent_sel)	\
	{							\
		.offset = (_offset),				\
		.bit = (_bit),					\
		.clock_id = (_clock_id),			\
		.set_clr = 1,					\
		.secure = (_sec),				\
		.sel = (_parent_sel),				\
		.fixed = _UNKNOWN_ID,				\
	}

/* Clocks with fixed source and set/clr register access */
#define _CLK_SC_FIXED(_sec, _offset, _bit, _clock_id, _parent)	\
	{							\
		.offset = (_offset),				\
		.bit = (_bit),					\
		.clock_id = (_clock_id),			\
		.set_clr = 1,					\
		.secure = (_sec),				\
		.sel = _UNKNOWN_SEL,				\
		.fixed = (_parent),				\
	}

/*
 * Clocks with selectable source and set/clr register access
 * and enable bit position defined by a label (argument _bit)
 */
#define _CLK_SC2_SELEC(_sec, _offset, _bit, _clock_id, _parent_sel)	\
	{							\
		.offset = (_offset),				\
		.clock_id = (_clock_id),			\
		.bit = _offset ## _ ## _bit ## _POS,		\
		.set_clr = 1,					\
		.secure = (_sec),				\
		.sel = (_parent_sel),				\
		.fixed = _UNKNOWN_ID,				\
	}
#define _CLK_SC2_FIXED(_sec, _offset, _bit, _clock_id, _parent)	\
	{							\
		.offset = (_offset),				\
		.clock_id = (_clock_id),			\
		.bit = _offset ## _ ## _bit ## _POS,		\
		.set_clr = 1,					\
		.secure = (_sec),				\
		.sel = _UNKNOWN_SEL,				\
		.fixed = (_parent),				\
	}

#define _CLK_PARENT(idx, _offset, _src, _mask, _parent)		\
	[(idx)] = {						\
		.offset = (_offset),				\
		.src = (_src),					\
		.msk = (_mask),					\
		.parent = (_parent),				\
		.nb_parent = ARRAY_SIZE(_parent)		\
	}

#define _CLK_PLL(_idx, _type, _off1, _off2, _off3, _off4,	\
		 _off5, _off6, _p1, _p2, _p3, _p4)		\
	[(_idx)] = {						\
		.plltype = (_type),				\
		.rckxselr = (_off1),				\
		.pllxcfgr1 = (_off2),				\
		.pllxcfgr2 = (_off3),				\
		.pllxfracr = (_off4),				\
		.pllxcr = (_off5),				\
		.pllxcsgr = (_off6),				\
		.refclk[0] = (_p1),				\
		.refclk[1] = (_p2),				\
		.refclk[2] = (_p3),				\
		.refclk[3] = (_p4),				\
	}

#define NB_GATES	ARRAY_SIZE(stm32mp1_clk_gate)

static const struct stm32mp1_clk_gate stm32mp1_clk_gate[] = {
	_CLK_FIXED(SEC, RCC_DDRITFCR, 0, DDRC1, _ACLK),
	_CLK_FIXED(SEC, RCC_DDRITFCR, 1, DDRC1LP, _ACLK),
	_CLK_FIXED(SEC, RCC_DDRITFCR, 2, DDRC2, _ACLK),
	_CLK_FIXED(SEC, RCC_DDRITFCR, 3, DDRC2LP, _ACLK),
	_CLK_FIXED(SEC, RCC_DDRITFCR, 4, DDRPHYC, _PLL2_R),
	_CLK_FIXED(SEC, RCC_DDRITFCR, 5, DDRPHYCLP, _PLL2_R),
	_CLK_FIXED(SEC, RCC_DDRITFCR, 6, DDRCAPB, _PCLK4),
	_CLK_FIXED(SEC, RCC_DDRITFCR, 7, DDRCAPBLP, _PCLK4),
	_CLK_FIXED(SEC, RCC_DDRITFCR, 8, AXIDCG, _ACLK),
	_CLK_FIXED(SEC, RCC_DDRITFCR, 9, DDRPHYCAPB, _PCLK4),
	_CLK_FIXED(SEC, RCC_DDRITFCR, 10, DDRPHYCAPBLP, _PCLK4),

	_CLK_SC2_SELEC(SEC, RCC_MP_APB5ENSETR, SPI6EN, SPI6_K, _SPI6_SEL),
	_CLK_SC2_SELEC(SEC, RCC_MP_APB5ENSETR, I2C4EN, I2C4_K, _I2C46_SEL),
	_CLK_SC2_SELEC(SEC, RCC_MP_APB5ENSETR, I2C6EN, I2C6_K, _I2C46_SEL),
	_CLK_SC2_SELEC(SEC, RCC_MP_APB5ENSETR, USART1EN, USART1_K, _USART1_SEL),
	_CLK_SC2_FIXED(SEC, RCC_MP_APB5ENSETR, RTCAPBEN, RTCAPB, _PCLK5),
	_CLK_SC2_FIXED(SEC, RCC_MP_APB5ENSETR, TZC1EN, TZC1, _PCLK5),
	_CLK_SC2_FIXED(SEC, RCC_MP_APB5ENSETR, TZC2EN, TZC2, _PCLK5),
	_CLK_SC2_FIXED(SEC, RCC_MP_APB5ENSETR, TZPCEN, TZPC, _PCLK5),
	_CLK_SC2_FIXED(SEC, RCC_MP_APB5ENSETR, IWDG1APBEN, IWDG1, _PCLK5),
	_CLK_SC2_FIXED(SEC, RCC_MP_APB5ENSETR, BSECEN, BSEC, _PCLK5),
	_CLK_SC2_SELEC(SEC, RCC_MP_APB5ENSETR, STGENEN, STGEN_K, _STGEN_SEL),

	_CLK_SC2_FIXED(SEC, RCC_MP_AHB5ENSETR, GPIOZEN, GPIOZ, _HCLK5),
	_CLK_SC2_FIXED(SEC, RCC_MP_AHB5ENSETR, CRYP1EN, CRYP1, _HCLK5),
	_CLK_SC2_FIXED(SEC, RCC_MP_AHB5ENSETR, HASH1EN, HASH1, _HCLK5),
	_CLK_SC2_SELEC(SEC, RCC_MP_AHB5ENSETR, RNG1EN, RNG1_K, _RNG1_SEL),
	_CLK_SC2_FIXED(SEC, RCC_MP_AHB5ENSETR, BKPSRAMEN, BKPSRAM, _PCLK5),

	_CLK_SC2_FIXED(SEC, RCC_MP_TZAHB6ENSETR, MDMA, MDMA, _HCLK6),

	_CLK_SELEC(SEC, RCC_BDCR, RCC_BDCR_RTCCKEN_POS, RTC, _RTC_SEL),

	/* Non-secure clocks */
#ifdef CFG_WITH_NSEC_GPIOS
	_CLK_SC_FIXED(N_S, RCC_MP_AHB4ENSETR, 0, GPIOA, _UNKNOWN_ID),
	_CLK_SC_FIXED(N_S, RCC_MP_AHB4ENSETR, 1, GPIOB, _UNKNOWN_ID),
	_CLK_SC_FIXED(N_S, RCC_MP_AHB4ENSETR, 2, GPIOC, _UNKNOWN_ID),
	_CLK_SC_FIXED(N_S, RCC_MP_AHB4ENSETR, 3, GPIOD, _UNKNOWN_ID),
	_CLK_SC_FIXED(N_S, RCC_MP_AHB4ENSETR, 4, GPIOE, _UNKNOWN_ID),
	_CLK_SC_FIXED(N_S, RCC_MP_AHB4ENSETR, 5, GPIOF, _UNKNOWN_ID),
	_CLK_SC_FIXED(N_S, RCC_MP_AHB4ENSETR, 6, GPIOG, _UNKNOWN_ID),
	_CLK_SC_FIXED(N_S, RCC_MP_AHB4ENSETR, 7, GPIOH, _UNKNOWN_ID),
	_CLK_SC_FIXED(N_S, RCC_MP_AHB4ENSETR, 8, GPIOI, _UNKNOWN_ID),
	_CLK_SC_FIXED(N_S, RCC_MP_AHB4ENSETR, 9, GPIOJ, _UNKNOWN_ID),
	_CLK_SC_FIXED(N_S, RCC_MP_AHB4ENSETR, 10, GPIOK, _UNKNOWN_ID),
#endif
	_CLK_SC_FIXED(N_S, RCC_MP_APB1ENSETR, 6, TIM12_K, _PCLK1),
#ifdef CFG_WITH_NSEC_UARTS
	_CLK_SC_SELEC(N_S, RCC_MP_APB1ENSETR, 14, USART2_K, _UART24_SEL),
	_CLK_SC_SELEC(N_S, RCC_MP_APB1ENSETR, 15, USART3_K, _UART35_SEL),
	_CLK_SC_SELEC(N_S, RCC_MP_APB1ENSETR, 16, UART4_K, _UART24_SEL),
	_CLK_SC_SELEC(N_S, RCC_MP_APB1ENSETR, 17, UART5_K, _UART35_SEL),
	_CLK_SC_SELEC(N_S, RCC_MP_APB1ENSETR, 18, UART7_K, _UART78_SEL),
	_CLK_SC_SELEC(N_S, RCC_MP_APB1ENSETR, 19, UART8_K, _UART78_SEL),
#endif
	_CLK_SC_FIXED(N_S, RCC_MP_APB2ENSETR, 2, TIM15_K, _PCLK2),
#ifdef CFG_WITH_NSEC_UARTS
	_CLK_SC_SELEC(N_S, RCC_MP_APB2ENSETR, 13, USART6_K, _UART6_SEL),
#endif
	_CLK_SC_FIXED(N_S, RCC_MP_APB3ENSETR, 11, SYSCFG, _UNKNOWN_ID),
	_CLK_SC_SELEC(N_S, RCC_MP_APB4ENSETR, 8, DDRPERFM, _UNKNOWN_SEL),
	_CLK_SC_SELEC(N_S, RCC_MP_APB4ENSETR, 15, IWDG2, _UNKNOWN_SEL),

	_CLK_SELEC(N_S, RCC_DBGCFGR, 8, CK_DBG, _UNKNOWN_SEL),
};
DECLARE_KEEP_PAGER(stm32mp1_clk_gate);

/* Parents for secure aware clocks in the xxxSELR value ordering */
static const uint8_t stgen_parents[] = {
	_HSI_KER, _HSE_KER
};

static const uint8_t i2c46_parents[] = {
	_PCLK5, _PLL3_Q, _HSI_KER, _CSI_KER
};

static const uint8_t spi6_parents[] = {
	_PCLK5, _PLL4_Q, _HSI_KER, _CSI_KER, _HSE_KER, _PLL3_Q
};

static const uint8_t usart1_parents[] = {
	_PCLK5, _PLL3_Q, _HSI_KER, _CSI_KER, _PLL4_Q, _HSE_KER
};

static const uint8_t rng1_parents[] = {
	_CSI, _PLL4_R, _LSE, _LSI
};

/* Parents for (some) non-secure clocks */
#ifdef CFG_WITH_NSEC_UARTS
static const uint8_t uart6_parents[] = {
	_PCLK2, _PLL4_Q, _HSI_KER, _CSI_KER, _HSE_KER
};

static const uint8_t uart234578_parents[] = {
	_PCLK1, _PLL4_Q, _HSI_KER, _CSI_KER, _HSE_KER
};
#endif

static const uint8_t axiss_parents[] = {
	_HSI, _HSE, _PLL2_P
};

static const uint8_t mcuss_parents[] = {
	_HSI, _HSE, _CSI, _PLL3_P
};

static const uint8_t rtc_parents[] = {
	_UNKNOWN_ID, _LSE, _LSI, _HSE
};

static const struct stm32mp1_clk_sel stm32mp1_clk_sel[_PARENT_SEL_NB] = {
	/* Secure aware clocks */
	_CLK_PARENT(_STGEN_SEL, RCC_STGENCKSELR, 0, 0x3, stgen_parents),
	_CLK_PARENT(_I2C46_SEL, RCC_I2C46CKSELR, 0, 0x7, i2c46_parents),
	_CLK_PARENT(_SPI6_SEL, RCC_SPI6CKSELR, 0, 0x7, spi6_parents),
	_CLK_PARENT(_USART1_SEL, RCC_UART1CKSELR, 0, 0x7, usart1_parents),
	_CLK_PARENT(_RNG1_SEL, RCC_RNG1CKSELR, 0, 0x3, rng1_parents),
	_CLK_PARENT(_RTC_SEL, RCC_BDCR, 0, 0x3, rtc_parents),
	/* Always non-secure clocks (maybe used in some way in secure world) */
#ifdef CFG_WITH_NSEC_UARTS
	_CLK_PARENT(_UART6_SEL, RCC_UART6CKSELR, 0, 0x7, uart6_parents),
	_CLK_PARENT(_UART24_SEL, RCC_UART24CKSELR, 0, 0x7, uart234578_parents),
	_CLK_PARENT(_UART35_SEL, RCC_UART35CKSELR, 0, 0x7, uart234578_parents),
	_CLK_PARENT(_UART78_SEL, RCC_UART78CKSELR, 0, 0x7, uart234578_parents),
#endif
	_CLK_PARENT(_AXISS_SEL, RCC_ASSCKSELR, 0, 0x3, axiss_parents),
	_CLK_PARENT(_MCUSS_SEL, RCC_MSSCKSELR, 0, 0x3, mcuss_parents),
};

/* PLLNCFGR2 register divider by output */
static const uint8_t pllncfgr2[_DIV_NB] = {
	[_DIV_P] = RCC_PLLNCFGR2_DIVP_SHIFT,
	[_DIV_Q] = RCC_PLLNCFGR2_DIVQ_SHIFT,
	[_DIV_R] = RCC_PLLNCFGR2_DIVR_SHIFT,
};

static const struct stm32mp1_clk_pll stm32mp1_clk_pll[_PLL_NB] = {
	_CLK_PLL(_PLL1, PLL_1600,
		 RCC_RCK12SELR, RCC_PLL1CFGR1, RCC_PLL1CFGR2,
		 RCC_PLL1FRACR, RCC_PLL1CR, RCC_PLL1CSGR,
		 _HSI, _HSE, _UNKNOWN_OSC_ID, _UNKNOWN_OSC_ID),
	_CLK_PLL(_PLL2, PLL_1600,
		 RCC_RCK12SELR, RCC_PLL2CFGR1, RCC_PLL2CFGR2,
		 RCC_PLL2FRACR, RCC_PLL2CR, RCC_PLL2CSGR,
		 _HSI, _HSE, _UNKNOWN_OSC_ID, _UNKNOWN_OSC_ID),
	_CLK_PLL(_PLL3, PLL_800,
		 RCC_RCK3SELR, RCC_PLL3CFGR1, RCC_PLL3CFGR2,
		 RCC_PLL3FRACR, RCC_PLL3CR, RCC_PLL3CSGR,
		 _HSI, _HSE, _CSI, _UNKNOWN_OSC_ID),
	_CLK_PLL(_PLL4, PLL_800,
		 RCC_RCK4SELR, RCC_PLL4CFGR1, RCC_PLL4CFGR2,
		 RCC_PLL4FRACR, RCC_PLL4CR, RCC_PLL4CSGR,
		 _HSI, _HSE, _CSI, _I2S_CKIN),
};

/* Prescaler table lookups for clock computation */
/* div = /1 /2 /4 /8 / 16 /64 /128 /512 */
static const uint8_t stm32mp1_mcu_div[16] = {
	0, 1, 2, 3, 4, 6, 7, 8, 9, 9, 9, 9, 9, 9, 9, 9
};

/* div = /1 /2 /4 /8 /16 : same divider for PMU and APBX */
#define stm32mp1_mpu_div	stm32mp1_mpu_apbx_div
#define stm32mp1_apbx_div	stm32mp1_mpu_apbx_div
static const uint8_t stm32mp1_mpu_apbx_div[8] = {
	0, 1, 2, 3, 4, 4, 4, 4
};

/* div = /1 /2 /3 /4 */
static const uint8_t stm32mp1_axi_div[8] = {
	1, 2, 3, 4, 4, 4, 4, 4
};

static const char __maybe_unused *const stm32mp1_clk_parent_name[_PARENT_NB] = {
	[_HSI] = "HSI",
	[_HSE] = "HSE",
	[_CSI] = "CSI",
	[_LSI] = "LSI",
	[_LSE] = "LSE",
	[_I2S_CKIN] = "I2S_CKIN",
	[_HSI_KER] = "HSI_KER",
	[_HSE_KER] = "HSE_KER",
	[_HSE_KER_DIV2] = "HSE_KER_DIV2",
	[_CSI_KER] = "CSI_KER",
	[_PLL1_P] = "PLL1_P",
	[_PLL1_Q] = "PLL1_Q",
	[_PLL1_R] = "PLL1_R",
	[_PLL2_P] = "PLL2_P",
	[_PLL2_Q] = "PLL2_Q",
	[_PLL2_R] = "PLL2_R",
	[_PLL3_P] = "PLL3_P",
	[_PLL3_Q] = "PLL3_Q",
	[_PLL3_R] = "PLL3_R",
	[_PLL4_P] = "PLL4_P",
	[_PLL4_Q] = "PLL4_Q",
	[_PLL4_R] = "PLL4_R",
	[_ACLK] = "ACLK",
	[_PCLK1] = "PCLK1",
	[_PCLK2] = "PCLK2",
	[_PCLK3] = "PCLK3",
	[_PCLK4] = "PCLK4",
	[_PCLK5] = "PCLK5",
	[_HCLK5] = "HCLK5",
	[_HCLK6] = "HCLK6",
	[_HCLK2] = "HCLK2",
	[_CK_PER] = "CK_PER",
	[_CK_MPU] = "CK_MPU",
	[_CK_MCU] = "CK_MCU",
	[_USB_PHY_48] = "USB_PHY_48",
};

/*
 * Oscillator frequency in Hz. This array shall be initialized
 * according to platform.
 */
static unsigned long stm32mp1_osc[NB_OSC];

static unsigned long osc_frequency(enum stm32mp_osc_id idx)
{
	if (idx >= ARRAY_SIZE(stm32mp1_osc)) {
		DMSG("clk id %d not found", idx);
		return 0;
	}

	return stm32mp1_osc[idx];
}

/* Reference counting for clock gating */
static unsigned int gate_refcounts[NB_GATES];
static unsigned int refcount_lock;

static const struct stm32mp1_clk_gate *gate_ref(unsigned int idx)
{
	return &stm32mp1_clk_gate[idx];
}

static bool gate_is_non_secure(const struct stm32mp1_clk_gate *gate)
{
	return gate->secure == N_S || !stm32_rcc_is_secure();
}

static const struct stm32mp1_clk_sel *clk_sel_ref(unsigned int idx)
{
	return &stm32mp1_clk_sel[idx];
}

static const struct stm32mp1_clk_pll *pll_ref(unsigned int idx)
{
	return &stm32mp1_clk_pll[idx];
}

static int stm32mp1_clk_get_gated_id(unsigned long id)
{
	unsigned int i = 0;

	for (i = 0; i < NB_GATES; i++)
		if (gate_ref(i)->clock_id == id)
			return i;

	DMSG("clk id %lu not found", id);
	return -1;
}

static enum stm32mp1_parent_sel stm32mp1_clk_get_sel(int i)
{
	return (enum stm32mp1_parent_sel)gate_ref(i)->sel;
}

static enum stm32mp1_parent_id stm32mp1_clk_get_fixed_parent(int i)
{
	return (enum stm32mp1_parent_id)gate_ref(i)->fixed;
}

static int stm32mp1_clk_get_parent(unsigned long id)
{
	const struct stm32mp1_clk_sel *sel = NULL;
	enum stm32mp1_parent_id parent_id = 0;
	uint32_t p_sel = 0;
	int i = 0;
	enum stm32mp1_parent_id p = _UNKNOWN_ID;
	enum stm32mp1_parent_sel s = _UNKNOWN_SEL;
	vaddr_t rcc_base = stm32_rcc_base();

	parent_id = clock_id2parent_id(id);
	if (parent_id != _UNKNOWN_ID)
		return (int)parent_id;

	i = stm32mp1_clk_get_gated_id(id);
	if (i < 0)
		panic();

	p = stm32mp1_clk_get_fixed_parent(i);
	if (p < _PARENT_NB)
		return (int)p;

	s = stm32mp1_clk_get_sel(i);
	if (s == _UNKNOWN_SEL)
		return -1;
	if (s >= _PARENT_SEL_NB)
		panic();

	sel = clk_sel_ref(s);
	p_sel = (io_read32(rcc_base + sel->offset) >> sel->src) & sel->msk;
	if (p_sel < sel->nb_parent)
		return (int)sel->parent[p_sel];

	DMSG("No parent selected for clk %lu", id);
	return -1;
}

static unsigned long stm32mp1_pll_get_fref(const struct stm32mp1_clk_pll *pll)
{
	uint32_t selr = io_read32(stm32_rcc_base() + pll->rckxselr);
	uint32_t src = selr & RCC_SELR_REFCLK_SRC_MASK;

	return osc_frequency(pll->refclk[src]);
}

/*
 * pll_get_fvco() : return the VCO or (VCO / 2) frequency for the requested PLL
 * - PLL1 & PLL2 => return VCO / 2 with Fpll_y_ck = FVCO / 2 * (DIVy + 1)
 * - PLL3 & PLL4 => return VCO     with Fpll_y_ck = FVCO / (DIVy + 1)
 * => in all cases Fpll_y_ck = pll_get_fvco() / (DIVy + 1)
 */
static unsigned long stm32mp1_pll_get_fvco(const struct stm32mp1_clk_pll *pll)
{
	unsigned long refclk = 0;
	unsigned long fvco = 0;
	uint32_t cfgr1 = 0;
	uint32_t fracr = 0;
	uint32_t divm = 0;
	uint32_t divn = 0;

	cfgr1 = io_read32(stm32_rcc_base() + pll->pllxcfgr1);
	fracr = io_read32(stm32_rcc_base() + pll->pllxfracr);

	divm = (cfgr1 & RCC_PLLNCFGR1_DIVM_MASK) >> RCC_PLLNCFGR1_DIVM_SHIFT;
	divn = cfgr1 & RCC_PLLNCFGR1_DIVN_MASK;

	refclk = stm32mp1_pll_get_fref(pll);

	/*
	 * With FRACV :
	 *   Fvco = Fck_ref * ((DIVN + 1) + FRACV / 2^13) / (DIVM + 1)
	 * Without FRACV
	 *   Fvco = Fck_ref * ((DIVN + 1) / (DIVM + 1)
	 */
	if (fracr & RCC_PLLNFRACR_FRACLE) {
		unsigned long long numerator = 0;
		unsigned long long denominator = 0;
		uint32_t fracv = (fracr & RCC_PLLNFRACR_FRACV_MASK) >>
				 RCC_PLLNFRACR_FRACV_SHIFT;

		numerator = (((unsigned long long)divn + 1U) << 13) + fracv;
		numerator = refclk * numerator;
		denominator = ((unsigned long long)divm + 1U) << 13;
		fvco = (unsigned long)(numerator / denominator);
	} else {
		fvco = (unsigned long)(refclk * (divn + 1U) / (divm + 1U));
	}

	return fvco;
}

static unsigned long stm32mp1_read_pll_freq(enum stm32mp1_pll_id pll_id,
					    enum stm32mp1_div_id div_id)
{
	const struct stm32mp1_clk_pll *pll = pll_ref(pll_id);
	unsigned long dfout = 0;
	uint32_t cfgr2 = 0;
	uint32_t divy = 0;

	if (div_id >= _DIV_NB)
		return 0;

	cfgr2 = io_read32(stm32_rcc_base() + pll->pllxcfgr2);
	divy = (cfgr2 >> pllncfgr2[div_id]) & RCC_PLLNCFGR2_DIVX_MASK;

	dfout = stm32mp1_pll_get_fvco(pll) / (divy + 1U);

	return dfout;
}

static unsigned long get_clock_rate(int p)
{
	uint32_t reg = 0;
	unsigned long clock = 0;
	vaddr_t rcc_base = stm32_rcc_base();

	switch (p) {
	case _CK_MPU:
	/* MPU sub system */
		reg = io_read32(rcc_base + RCC_MPCKSELR);
		switch (reg & RCC_SELR_SRC_MASK) {
		case RCC_MPCKSELR_HSI:
			clock = osc_frequency(_HSI);
			break;
		case RCC_MPCKSELR_HSE:
			clock = osc_frequency(_HSE);
			break;
		case RCC_MPCKSELR_PLL:
			clock = stm32mp1_read_pll_freq(_PLL1, _DIV_P);
			break;
		case RCC_MPCKSELR_PLL_MPUDIV:
			reg = io_read32(rcc_base + RCC_MPCKDIVR);
			if (reg & RCC_MPUDIV_MASK)
				clock = stm32mp1_read_pll_freq(_PLL1, _DIV_P) >>
					stm32mp1_mpu_div[reg & RCC_MPUDIV_MASK];
			else
				clock = 0;
			break;
		default:
			break;
		}
		break;
	/* AXI sub system */
	case _ACLK:
	case _HCLK2:
	case _HCLK5:
	case _HCLK6:
	case _PCLK4:
	case _PCLK5:
		reg = io_read32(rcc_base + RCC_ASSCKSELR);
		switch (reg & RCC_SELR_SRC_MASK) {
		case RCC_ASSCKSELR_HSI:
			clock = osc_frequency(_HSI);
			break;
		case RCC_ASSCKSELR_HSE:
			clock = osc_frequency(_HSE);
			break;
		case RCC_ASSCKSELR_PLL:
			clock = stm32mp1_read_pll_freq(_PLL2, _DIV_P);
			break;
		default:
			break;
		}

		/* System clock divider */
		reg = io_read32(rcc_base + RCC_AXIDIVR);
		clock /= stm32mp1_axi_div[reg & RCC_AXIDIV_MASK];

		switch (p) {
		case _PCLK4:
			reg = io_read32(rcc_base + RCC_APB4DIVR);
			clock >>= stm32mp1_apbx_div[reg & RCC_APBXDIV_MASK];
			break;
		case _PCLK5:
			reg = io_read32(rcc_base + RCC_APB5DIVR);
			clock >>= stm32mp1_apbx_div[reg & RCC_APBXDIV_MASK];
			break;
		default:
			break;
		}
		break;
	/* MCU sub system */
	case _CK_MCU:
	case _PCLK1:
	case _PCLK2:
	case _PCLK3:
		reg = io_read32(rcc_base + RCC_MSSCKSELR);
		switch (reg & RCC_SELR_SRC_MASK) {
		case RCC_MSSCKSELR_HSI:
			clock = osc_frequency(_HSI);
			break;
		case RCC_MSSCKSELR_HSE:
			clock = osc_frequency(_HSE);
			break;
		case RCC_MSSCKSELR_CSI:
			clock = osc_frequency(_CSI);
			break;
		case RCC_MSSCKSELR_PLL:
			clock = stm32mp1_read_pll_freq(_PLL3, _DIV_P);
			break;
		default:
			break;
		}

		/* MCU clock divider */
		reg = io_read32(rcc_base + RCC_MCUDIVR);
		clock >>= stm32mp1_mcu_div[reg & RCC_MCUDIV_MASK];

		switch (p) {
		case _PCLK1:
			reg = io_read32(rcc_base + RCC_APB1DIVR);
			clock >>= stm32mp1_apbx_div[reg & RCC_APBXDIV_MASK];
			break;
		case _PCLK2:
			reg = io_read32(rcc_base + RCC_APB2DIVR);
			clock >>= stm32mp1_apbx_div[reg & RCC_APBXDIV_MASK];
			break;
		case _PCLK3:
			reg = io_read32(rcc_base + RCC_APB3DIVR);
			clock >>= stm32mp1_apbx_div[reg & RCC_APBXDIV_MASK];
			break;
		case _CK_MCU:
		default:
			break;
		}
		break;
	case _CK_PER:
		reg = io_read32(rcc_base + RCC_CPERCKSELR);
		switch (reg & RCC_SELR_SRC_MASK) {
		case RCC_CPERCKSELR_HSI:
			clock = osc_frequency(_HSI);
			break;
		case RCC_CPERCKSELR_HSE:
			clock = osc_frequency(_HSE);
			break;
		case RCC_CPERCKSELR_CSI:
			clock = osc_frequency(_CSI);
			break;
		default:
			break;
		}
		break;
	case _HSI:
	case _HSI_KER:
		clock = osc_frequency(_HSI);
		break;
	case _CSI:
	case _CSI_KER:
		clock = osc_frequency(_CSI);
		break;
	case _HSE:
	case _HSE_KER:
		clock = osc_frequency(_HSE);
		break;
	case _HSE_KER_DIV2:
		clock = osc_frequency(_HSE) >> 1;
		break;
	case _LSI:
		clock = osc_frequency(_LSI);
		break;
	case _LSE:
		clock = osc_frequency(_LSE);
		break;
	/* PLL */
	case _PLL1_P:
		clock = stm32mp1_read_pll_freq(_PLL1, _DIV_P);
		break;
	case _PLL1_Q:
		clock = stm32mp1_read_pll_freq(_PLL1, _DIV_Q);
		break;
	case _PLL1_R:
		clock = stm32mp1_read_pll_freq(_PLL1, _DIV_R);
		break;
	case _PLL2_P:
		clock = stm32mp1_read_pll_freq(_PLL2, _DIV_P);
		break;
	case _PLL2_Q:
		clock = stm32mp1_read_pll_freq(_PLL2, _DIV_Q);
		break;
	case _PLL2_R:
		clock = stm32mp1_read_pll_freq(_PLL2, _DIV_R);
		break;
	case _PLL3_P:
		clock = stm32mp1_read_pll_freq(_PLL3, _DIV_P);
		break;
	case _PLL3_Q:
		clock = stm32mp1_read_pll_freq(_PLL3, _DIV_Q);
		break;
	case _PLL3_R:
		clock = stm32mp1_read_pll_freq(_PLL3, _DIV_R);
		break;
	case _PLL4_P:
		clock = stm32mp1_read_pll_freq(_PLL4, _DIV_P);
		break;
	case _PLL4_Q:
		clock = stm32mp1_read_pll_freq(_PLL4, _DIV_Q);
		break;
	case _PLL4_R:
		clock = stm32mp1_read_pll_freq(_PLL4, _DIV_R);
		break;
	/* Other */
	case _USB_PHY_48:
		clock = osc_frequency(_USB_PHY_48);
		break;
	default:
		break;
	}

	return clock;
}

static void __clk_enable(struct stm32mp1_clk_gate const *gate)
{
	vaddr_t base = stm32_rcc_base();
	uint32_t bit = BIT(gate->bit);

	if (gate->set_clr)
		io_write32(base + gate->offset, bit);
	else
		io_setbits32_stm32shregs(base + gate->offset, bit);

	FMSG("Clock %u has been enabled", gate->clock_id);
}

static void __clk_disable(struct stm32mp1_clk_gate const *gate)
{
	vaddr_t base = stm32_rcc_base();
	uint32_t bit = BIT(gate->bit);

	if (gate->set_clr)
		io_write32(base + gate->offset + RCC_MP_ENCLRR_OFFSET, bit);
	else
		io_clrbits32_stm32shregs(base + gate->offset, bit);

	FMSG("Clock %u has been disabled", gate->clock_id);
}

static bool __clk_is_enabled(struct stm32mp1_clk_gate const *gate)
{
	vaddr_t base = stm32_rcc_base();

	return io_read32(base + gate->offset) & BIT(gate->bit);
}

static bool clock_is_always_on(unsigned long id)
{
	COMPILE_TIME_ASSERT(CK_HSE == 0 &&
			    (CK_HSE + 1) == CK_CSI &&
			    (CK_HSE + 2) == CK_LSI &&
			    (CK_HSE + 3) == CK_LSE &&
			    (CK_HSE + 4) == CK_HSI &&
			    (CK_HSE + 5) == CK_HSE_DIV2 &&
			    (PLL1_P + 1) == PLL1_Q &&
			    (PLL1_P + 2) == PLL1_R &&
			    (PLL1_P + 3) == PLL2_P &&
			    (PLL1_P + 4) == PLL2_Q &&
			    (PLL1_P + 5) == PLL2_R &&
			    (PLL1_P + 6) == PLL3_P &&
			    (PLL1_P + 7) == PLL3_Q &&
			    (PLL1_P + 8) == PLL3_R);

	if (id <= CK_HSE_DIV2 || (id >= PLL1_P && id <= PLL3_R))
		return true;

	switch (id) {
	case CK_AXI:
	case CK_MPU:
	case CK_MCU:
		return true;
	default:
		return false;
	}
}

bool stm32_clock_is_enabled(unsigned long id)
{
	int i = 0;

	if (clock_is_always_on(id))
		return true;

	i = stm32mp1_clk_get_gated_id(id);
	if (i < 0)
		return false;

	return __clk_is_enabled(gate_ref(i));
}

void stm32_clock_enable(unsigned long id)
{
	int i = 0;
	uint32_t exceptions = 0;

	if (clock_is_always_on(id))
		return;

	i = stm32mp1_clk_get_gated_id(id);
	if (i < 0) {
		DMSG("Invalid clock %lu: %d", id, i);
		panic();
	}

	if (gate_is_non_secure(gate_ref(i))) {
		/* Enable non-secure clock w/o any refcounting */
		__clk_enable(gate_ref(i));
		return;
	}

	exceptions = may_spin_lock(&refcount_lock);

	if (!gate_refcounts[i])
		__clk_enable(gate_ref(i));

	gate_refcounts[i]++;

	may_spin_unlock(&refcount_lock, exceptions);
}

void stm32_clock_disable(unsigned long id)
{
	int i = 0;
	uint32_t exceptions = 0;

	if (clock_is_always_on(id))
		return;

	i = stm32mp1_clk_get_gated_id(id);
	if (i < 0) {
		DMSG("Invalid clock %lu: %d", id, i);
		panic();
	}

	if (gate_is_non_secure(gate_ref(i))) {
		/* Don't disable non-secure clocks */
		return;
	}

	exceptions = may_spin_lock(&refcount_lock);

	assert(gate_refcounts[i]);
	gate_refcounts[i]--;
	if (!gate_refcounts[i])
		__clk_disable(gate_ref(i));

	may_spin_unlock(&refcount_lock, exceptions);
}

static long get_timer_rate(long parent_rate, unsigned int apb_bus)
{
	uint32_t timgxpre = 0;
	uint32_t apbxdiv = 0;
	vaddr_t rcc_base = stm32_rcc_base();

	switch (apb_bus) {
	case 1:
		apbxdiv = io_read32(rcc_base + RCC_APB1DIVR) &
			  RCC_APBXDIV_MASK;
		timgxpre = io_read32(rcc_base + RCC_TIMG1PRER) &
			   RCC_TIMGXPRER_TIMGXPRE;
		break;
	case 2:
		apbxdiv = io_read32(rcc_base + RCC_APB2DIVR) &
			  RCC_APBXDIV_MASK;
		timgxpre = io_read32(rcc_base + RCC_TIMG2PRER) &
			   RCC_TIMGXPRER_TIMGXPRE;
		break;
	default:
		panic();
		break;
	}

	if (apbxdiv == 0)
		return parent_rate;

	return parent_rate * (timgxpre + 1) * 2;
}

unsigned long stm32_clock_get_rate(unsigned long id)
{
	int p = 0;
	unsigned long rate = 0;

	p = stm32mp1_clk_get_parent(id);
	if (p < 0)
		return 0;

	rate = get_clock_rate(p);

	if ((id >= TIM2_K) && (id <= TIM14_K))
		rate = get_timer_rate(rate, 1);

	if ((id >= TIM1_K) && (id <= TIM17_K))
		rate = get_timer_rate(rate, 2);

	return rate;
}

/*
 * Get the parent ID of the target parent clock, or -1 if no parent found.
 */
static int get_parent_id_parent(unsigned int parent_id)
{
	enum stm32mp1_parent_sel s = _UNKNOWN_SEL;
	enum stm32mp1_pll_id pll_id = _PLL_NB;
	uint32_t p_sel = 0;

	switch (parent_id) {
	case _ACLK:
	case _PCLK4:
	case _PCLK5:
		s = _AXISS_SEL;
		break;
	case _PLL1_P:
	case _PLL1_Q:
	case _PLL1_R:
		pll_id = _PLL1;
		break;
	case _PLL2_P:
	case _PLL2_Q:
	case _PLL2_R:
		pll_id = _PLL2;
		break;
	case _PLL3_P:
	case _PLL3_Q:
	case _PLL3_R:
		pll_id = _PLL3;
		break;
	case _PLL4_P:
	case _PLL4_Q:
	case _PLL4_R:
		pll_id = _PLL4;
		break;
	case _PCLK1:
	case _PCLK2:
	case _HCLK2:
	case _HCLK6:
	case _CK_PER:
	case _CK_MPU:
	case _CK_MCU:
	case _USB_PHY_48:
		/* We do not expected to access these */
		panic();
		break;
	default:
		/* Other parents have no parent */
		return -1;
	}

	if (s != _UNKNOWN_SEL) {
		const struct stm32mp1_clk_sel *sel = clk_sel_ref(s);
		vaddr_t rcc_base = stm32_rcc_base();

		p_sel = (io_read32(rcc_base + sel->offset) >> sel->src) &
			sel->msk;

		if (p_sel < sel->nb_parent)
			return sel->parent[p_sel];
	} else {
		const struct stm32mp1_clk_pll *pll = pll_ref(pll_id);

		p_sel = io_read32(stm32_rcc_base() + pll->rckxselr) &
			RCC_SELR_REFCLK_SRC_MASK;

		if (pll->refclk[p_sel] != _UNKNOWN_OSC_ID)
			return pll->refclk[p_sel];
	}

	FMSG("No parent found for %s", stm32mp1_clk_parent_name[parent_id]);
	return -1;
}

/* We are only interested in knowing if PLL3 shall be secure or not */
static void secure_parent_clocks(unsigned long parent_id)
{
	int grandparent_id = 0;

	switch (parent_id) {
	case _ACLK:
	case _HCLK2:
	case _HCLK5:
	case _HCLK6:
	case _PCLK4:
	case _PCLK5:
		/* Intermediate clock mux or clock, go deeper in clock tree */
		break;
	case _HSI:
	case _HSI_KER:
	case _LSI:
	case _CSI:
	case _CSI_KER:
	case _HSE:
	case _HSE_KER:
	case _HSE_KER_DIV2:
	case _LSE:
	case _PLL1_P:
	case _PLL1_Q:
	case _PLL1_R:
	case _PLL2_P:
	case _PLL2_Q:
	case _PLL2_R:
		/* Always secure clocks, no need to go further */
		return;
	case _PLL3_P:
	case _PLL3_Q:
	case _PLL3_R:
		/* PLL3 is a shared resource, registered and don't go further */
		stm32mp_register_secure_periph(STM32MP1_SHRES_PLL3);
		return;
	default:
		DMSG("Cannot lookup parent clock %s",
		     stm32mp1_clk_parent_name[parent_id]);
		panic();
	}

	grandparent_id = get_parent_id_parent(parent_id);
	if (grandparent_id >= 0)
		secure_parent_clocks(grandparent_id);
}

void stm32mp_register_clock_parents_secure(unsigned long clock_id)
{
	int parent_id = stm32mp1_clk_get_parent(clock_id);

	if (parent_id < 0) {
		DMSG("No parent for clock %lu", clock_id);
		return;
	}

	secure_parent_clocks(parent_id);
}

#ifdef CFG_EMBED_DTB
static const char *stm32mp_osc_node_label[NB_OSC] = {
	[_LSI] = "clk-lsi",
	[_LSE] = "clk-lse",
	[_HSI] = "clk-hsi",
	[_HSE] = "clk-hse",
	[_CSI] = "clk-csi",
	[_I2S_CKIN] = "i2s_ckin",
	[_USB_PHY_48] = "ck_usbo_48m"
};

static unsigned int clk_freq_prop(const void *fdt, int node)
{
	const fdt32_t *cuint = NULL;
	int ret = 0;

	/* Disabled clocks report null rate */
	if (_fdt_get_status(fdt, node) == DT_STATUS_DISABLED)
		return 0;

	cuint = fdt_getprop(fdt, node, "clock-frequency", &ret);
	if (!cuint)
		panic();

	return fdt32_to_cpu(*cuint);
}

static void get_osc_freq_from_dt(const void *fdt)
{
	enum stm32mp_osc_id idx = _UNKNOWN_OSC_ID;
	int clk_node = fdt_path_offset(fdt, "/clocks");

	if (clk_node < 0)
		panic();

	COMPILE_TIME_ASSERT((int)_HSI == 0);
	for (idx = _HSI; idx < NB_OSC; idx++) {
		const char *name = stm32mp_osc_node_label[idx];
		int subnode = 0;

		fdt_for_each_subnode(subnode, fdt, clk_node) {
			const char *cchar = NULL;
			int ret = 0;

			cchar = fdt_get_name(fdt, subnode, &ret);
			if (!cchar)
				panic();

			if (strncmp(cchar, name, (size_t)ret) == 0) {
				stm32mp1_osc[idx] = clk_freq_prop(fdt, subnode);

				DMSG("Osc %s: %lu Hz", name, stm32mp1_osc[idx]);
				break;
			}
		}

		if (!stm32mp1_osc[idx])
			DMSG("Osc %s: no frequency info", name);
	}
}

static void enable_static_secure_clocks(void)
{
	unsigned int idx = 0;
	static const unsigned long secure_enable[] = {
		DDRC1, DDRC1LP, DDRC2, DDRC2LP, DDRPHYC, DDRPHYCLP, DDRCAPB,
		AXIDCG, DDRPHYCAPB, DDRPHYCAPBLP, TZPC, TZC1, TZC2, STGEN_K,
		BSEC,
	};

	for (idx = 0; idx < ARRAY_SIZE(secure_enable); idx++) {
		stm32_clock_enable(secure_enable[idx]);
		stm32mp_register_clock_parents_secure(secure_enable[idx]);
	}

	if (CFG_TEE_CORE_NB_CORE > 1)
		stm32_clock_enable(RTCAPB);
}

static void enable_rcc_tzen(void)
{
	io_setbits32(stm32_rcc_base() + RCC_TZCR, RCC_TZCR_TZEN);
}

static void disable_rcc_tzen(void)
{
	IMSG("RCC is non-secure");
	io_clrbits32(stm32_rcc_base() + RCC_TZCR, RCC_TZCR_TZEN);
}

static TEE_Result stm32mp1_clk_init(const void *fdt, int node)
{
	unsigned int i = 0;
	int len = 0;
	int ignored = 0;

	get_osc_freq_from_dt(fdt);

	/*
	 * OP-TEE core is not in charge of configuring clock parenthood.
	 * This is expected from an earlier boot stage. Modifying the clock
	 * tree parenthood here may jeopardize already configured clocks.
	 * The sequence below ignores such DT directives with a friendly
	 * debug trace.
	 */
	if (fdt_getprop(fdt, node, "st,clksrc", &len)) {
		DMSG("Ignore source clocks configuration from DT");
		ignored++;
	}
	if (fdt_getprop(fdt, node, "st,clkdiv", &len)) {
		DMSG("Ignore clock divisors configuration from DT");
		ignored++;
	}
	if (fdt_getprop(fdt, node, "st,pkcs", &len)) {
		DMSG("Ignore peripheral clocks tree configuration from DT");
		ignored++;
	}
	for (i = (enum stm32mp1_pll_id)0; i < _PLL_NB; i++) {
		char name[] = "st,pll@X";

		snprintf(name, sizeof(name), "st,pll@%d", i);
		node = fdt_subnode_offset(fdt, node, name);
		if (node < 0)
			continue;

		if (fdt_getprop(fdt, node, "cfg", &len) ||
		    fdt_getprop(fdt, node, "frac", &len)) {
			DMSG("Ignore PLL%u configurations from DT", i);
			ignored++;
		}
	}

	if (ignored != 0)
		IMSG("DT clock tree configurations were ignored");

	return TEE_SUCCESS;
}

static TEE_Result stm32mp1_clk_early_init(void)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	const void *fdt = get_embedded_dt();
	bool rcc_secure = true;
	int node = 0;

	node = fdt_node_offset_by_compatible(fdt, -1, DT_RCC_SECURE_CLK_COMPAT);
	if (node < 0) {
		node = fdt_node_offset_by_compatible(fdt, -1,
						     DT_RCC_CLK_COMPAT);
		if (node < 0)
			panic();

		rcc_secure = false;
	}

	assert(_fdt_reg_base_address(fdt, node) == RCC_BASE);
	assert(_fdt_get_status(fdt, node) != DT_STATUS_DISABLED);

	if (!rcc_secure) {
		if (io_read32(stm32_rcc_base() + RCC_TZCR) & RCC_TZCR_TZEN)
			panic("Refuse to release RCC[TZEN]");

		disable_rcc_tzen();
	} else {
		enable_rcc_tzen();
	}

	res = stm32mp1_clk_init(fdt, node);
	if (res)
		return res;

	enable_static_secure_clocks();

	return TEE_SUCCESS;
}

service_init(stm32mp1_clk_early_init);
#endif /*CFG_EMBED_DTB*/
