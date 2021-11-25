// SPDX-License-Identifier: (GPL-2.0+ OR BSD-3-Clause)
/*
 * Copyright (C) STMicroelectronics 2022 - All Rights Reserved
 */

#include <assert.h>
#include <drivers/clk.h>
#include <drivers/clk_dt.h>
#include <drivers/stm32mp_dt_bindings.h>
#include <drivers/stm32mp13_rcc.h>
#include <io.h>
#include <kernel/boot.h>
#include <libfdt.h>
#include <stdio.h>

#include "clk-stm32-core.h"

#define MAX_HSI_HZ		64000000
#define USB_PHY_48_MHZ		48000000

#define TIMEOUT_US_200MS	U(200000)
#define HSIDIV_TIMEOUT		TIMEOUT_US_200MS

#define MAX_OPP		CFG_STM32MP_OPP_COUNT

#define RCC_PLL_NAME_SIZE 12

struct stm32_osci_dt_cfg {
	unsigned long freq;
	bool bypass;
	bool digbyp;
	bool css;
	uint32_t drive;
};

enum pll_mn {
	PLL_CFG_M,
	PLL_CFG_N,
	PLL_DIV_MN_NB
};

enum pll_pqr {
	PLL_CFG_P,
	PLL_CFG_Q,
	PLL_CFG_R,
	PLL_DIV_PQR_NB
};

enum pll_csg {
	PLL_CSG_MOD_PER,
	PLL_CSG_INC_STEP,
	PLL_CSG_SSCG_MODE,
	PLL_CSG_NB
};

struct stm32_pll_vco {
	uint32_t status;
	uint32_t src;
	uint32_t div_mn[PLL_DIV_MN_NB];
	uint32_t frac;
	bool csg_enabled;
	uint32_t csg[PLL_CSG_NB];
};

struct stm32_pll_output {
	uint32_t output[PLL_DIV_PQR_NB];
};

struct stm32_pll_dt_cfg {
	struct stm32_pll_vco vco;
	struct stm32_pll_output output;
};

struct stm32_clk_opp_cfg {
	uint32_t frq;
	uint32_t src;
	uint32_t div;
	struct stm32_pll_dt_cfg pll_cfg;
};

struct stm32_clk_opp_dt_cfg {
	struct stm32_clk_opp_cfg mpu_opp[MAX_OPP];
	struct stm32_clk_opp_cfg axi_opp[MAX_OPP];
	struct stm32_clk_opp_cfg mlahbs_opp[MAX_OPP];
};

struct stm32_clk_platdata {
	uintptr_t rcc_base;
	uint32_t nosci;
	struct stm32_osci_dt_cfg *osci;
	uint32_t npll;
	struct stm32_pll_dt_cfg *pll;
	struct stm32_clk_opp_dt_cfg *opp;
	uint32_t nclksrc;
	uint32_t *clksrc;
	uint32_t nclkdiv;
	uint32_t *clkdiv;
};

/*
 * GATE CONFIG
 */

/* Warning GATE_XXX_RDY must follow GATE_XXX */
enum enum_gate_cfg {
	GATE_LSE,
	GATE_LSE_RDY,
	GATE_LSI,
	GATE_LSI_RDY,
	GATE_HSI,
	GATE_HSI_RDY,
	GATE_CSI,
	GATE_CSI_RDY,
	GATE_HSE,
	GATE_HSE_RDY,
	GATE_PLL1,
	GATE_PLL1_RDY,
	GATE_PLL2,
	GATE_PLL2_RDY,
	GATE_PLL3,
	GATE_PLL3_RDY,
	GATE_PLL4,
	GATE_PLL4_RDY,
	GATE_HSIDIVRDY,
	GATE_MPUSRCRDY,
	GATE_AXISSRCRDY,
	GATE_MCUSSRCRDY,
	GATE_PLL12SRCRDY,
	GATE_PLL3SRCRDY,
	GATE_PLL4SRCRDY,
	GATE_MPUDIVRDY,
	GATE_AXIDIVRDY,
	GATE_MLAHBDIVRDY,
	GATE_APB1DIVRDY,
	GATE_APB2DIVRDY,
	GATE_APB3DIVRDY,
	GATE_APB4DIVRDY,
	GATE_APB5DIVRDY,
	GATE_APB6DIVRDY,
	GATE_RTCCK,
	GATE_MCO1,
	GATE_MCO2,
	GATE_DBGCK,
	GATE_TRACECK,
	GATE_PLL1_DIVP,
	GATE_PLL1_DIVQ,
	GATE_PLL1_DIVR,
	GATE_PLL2_DIVP,
	GATE_PLL2_DIVQ,
	GATE_PLL2_DIVR,
	GATE_PLL3_DIVP,
	GATE_PLL3_DIVQ,
	GATE_PLL3_DIVR,
	GATE_PLL4_DIVP,
	GATE_PLL4_DIVQ,
	GATE_PLL4_DIVR,
	GATE_DDRC1,
	GATE_DDRC1LP,
	GATE_DDRPHYC,
	GATE_DDRPHYCLP,
	GATE_DDRCAPB,
	GATE_DDRCAPBLP,
	GATE_AXIDCG,
	GATE_DDRPHYCAPB,
	GATE_DDRPHYCAPBLP,
	GATE_TIM2,
	GATE_TIM3,
	GATE_TIM4,
	GATE_TIM5,
	GATE_TIM6,
	GATE_TIM7,
	GATE_LPTIM1,
	GATE_SPI2,
	GATE_SPI3,
	GATE_USART3,
	GATE_UART4,
	GATE_UART5,
	GATE_UART7,
	GATE_UART8,
	GATE_I2C1,
	GATE_I2C2,
	GATE_SPDIF,
	GATE_TIM1,
	GATE_TIM8,
	GATE_SPI1,
	GATE_USART6,
	GATE_SAI1,
	GATE_SAI2,
	GATE_DFSDM,
	GATE_ADFSDM,
	GATE_FDCAN,
	GATE_LPTIM2,
	GATE_LPTIM3,
	GATE_LPTIM4,
	GATE_LPTIM5,
	GATE_VREF,
	GATE_DTS,
	GATE_PMBCTRL,
	GATE_HDP,
	GATE_SYSCFG,
	GATE_DCMIPP,
	GATE_DDRPERFM,
	GATE_IWDG2APB,
	GATE_USBPHY,
	GATE_STGENRO,
	GATE_LTDC,
	GATE_RTCAPB,
	GATE_TZC,
	GATE_ETZPC,
	GATE_IWDG1APB,
	GATE_BSEC,
	GATE_STGENC,
	GATE_USART1,
	GATE_USART2,
	GATE_SPI4,
	GATE_SPI5,
	GATE_I2C3,
	GATE_I2C4,
	GATE_I2C5,
	GATE_TIM12,
	GATE_TIM13,
	GATE_TIM14,
	GATE_TIM15,
	GATE_TIM16,
	GATE_TIM17,
	GATE_DMA1,
	GATE_DMA2,
	GATE_DMAMUX1,
	GATE_DMA3,
	GATE_DMAMUX2,
	GATE_ADC1,
	GATE_ADC2,
	GATE_USBO,
	GATE_TSC,
	GATE_GPIOA,
	GATE_GPIOB,
	GATE_GPIOC,
	GATE_GPIOD,
	GATE_GPIOE,
	GATE_GPIOF,
	GATE_GPIOG,
	GATE_GPIOH,
	GATE_GPIOI,
	GATE_PKA,
	GATE_SAES,
	GATE_CRYP1,
	GATE_HASH1,
	GATE_RNG1,
	GATE_BKPSRAM,
	GATE_AXIMC,
	GATE_MCE,
	GATE_ETH1CK,
	GATE_ETH1TX,
	GATE_ETH1RX,
	GATE_ETH1MAC,
	GATE_FMC,
	GATE_QSPI,
	GATE_SDMMC1,
	GATE_SDMMC2,
	GATE_CRC1,
	GATE_USBH,
	GATE_ETH2CK,
	GATE_ETH2TX,
	GATE_ETH2RX,
	GATE_ETH2MAC,
	GATE_MDMA,
	GATE_NB
};

#define GATE_CFG(_id, _offset, _bit_idx, _offset_clr)\
	[(_id)] = {\
		.offset		= (_offset),\
		.bit_idx	= (_bit_idx),\
		.set_clr	= (_offset_clr),\
	}

static const struct gate_cfg gates_mp13[GATE_NB] = {
	GATE_CFG(GATE_LSE,		RCC_BDCR,		0,	0),
	GATE_CFG(GATE_LSE_RDY,		RCC_BDCR,		2,	0),
	GATE_CFG(GATE_RTCCK,		RCC_BDCR,		20,	0),
	GATE_CFG(GATE_LSI,		RCC_RDLSICR,		0,	0),
	GATE_CFG(GATE_LSI_RDY,		RCC_RDLSICR,		1,	0),
	GATE_CFG(GATE_HSI,		RCC_OCENSETR,		0,	1),
	GATE_CFG(GATE_HSI_RDY,		RCC_OCRDYR,		0,	0),
	GATE_CFG(GATE_CSI,		RCC_OCENSETR,		4,	1),
	GATE_CFG(GATE_CSI_RDY,		RCC_OCRDYR,		4,	0),
	GATE_CFG(GATE_HSE,		RCC_OCENSETR,		8,	1),
	GATE_CFG(GATE_HSE_RDY,		RCC_OCRDYR,		8,	0),
	GATE_CFG(GATE_HSIDIVRDY,	RCC_OCRDYR,		2,	0),
	GATE_CFG(GATE_MPUSRCRDY,	RCC_MPCKSELR,		31,	0),
	GATE_CFG(GATE_AXISSRCRDY,	RCC_ASSCKSELR,		31,	0),
	GATE_CFG(GATE_MCUSSRCRDY,	RCC_MSSCKSELR,		31,	0),
	GATE_CFG(GATE_PLL12SRCRDY,	RCC_RCK12SELR,		31,	0),
	GATE_CFG(GATE_PLL3SRCRDY,	RCC_RCK3SELR,		31,	0),
	GATE_CFG(GATE_PLL4SRCRDY,	RCC_RCK4SELR,		31,	0),
	GATE_CFG(GATE_MPUDIVRDY,	RCC_MPCKDIVR,		31,	0),
	GATE_CFG(GATE_AXIDIVRDY,	RCC_AXIDIVR,		31,	0),
	GATE_CFG(GATE_MLAHBDIVRDY,	RCC_MLAHBDIVR,		31,	0),
	GATE_CFG(GATE_APB1DIVRDY,	RCC_APB1DIVR,		31,	0),
	GATE_CFG(GATE_APB2DIVRDY,	RCC_APB2DIVR,		31,	0),
	GATE_CFG(GATE_APB3DIVRDY,	RCC_APB3DIVR,		31,	0),
	GATE_CFG(GATE_APB4DIVRDY,	RCC_APB4DIVR,		31,	0),
	GATE_CFG(GATE_APB5DIVRDY,	RCC_APB5DIVR,		31,	0),
	GATE_CFG(GATE_APB6DIVRDY,	RCC_APB6DIVR,		31,	0),
	GATE_CFG(GATE_MCO1,		RCC_MCO1CFGR,		12,	0),
	GATE_CFG(GATE_MCO2,		RCC_MCO2CFGR,		12,	0),
	GATE_CFG(GATE_DBGCK,		RCC_DBGCFGR,		8,	0),
	GATE_CFG(GATE_TRACECK,		RCC_DBGCFGR,		9,	0),
	GATE_CFG(GATE_PLL1,		RCC_PLL1CR,		0,	0),
	GATE_CFG(GATE_PLL1_RDY,		RCC_PLL1CR,		1,	0),
	GATE_CFG(GATE_PLL1_DIVP,	RCC_PLL1CR,		4,	0),
	GATE_CFG(GATE_PLL1_DIVQ,	RCC_PLL1CR,		5,	0),
	GATE_CFG(GATE_PLL1_DIVR,	RCC_PLL1CR,		6,	0),
	GATE_CFG(GATE_PLL2,		RCC_PLL2CR,		0,	0),
	GATE_CFG(GATE_PLL2_RDY,		RCC_PLL2CR,		1,	0),
	GATE_CFG(GATE_PLL2_DIVP,	RCC_PLL2CR,		4,	0),
	GATE_CFG(GATE_PLL2_DIVQ,	RCC_PLL2CR,		5,	0),
	GATE_CFG(GATE_PLL2_DIVR,	RCC_PLL2CR,		6,	0),
	GATE_CFG(GATE_PLL3,		RCC_PLL3CR,		0,	0),
	GATE_CFG(GATE_PLL3_RDY,		RCC_PLL3CR,		1,	0),
	GATE_CFG(GATE_PLL3_DIVP,	RCC_PLL3CR,		4,	0),
	GATE_CFG(GATE_PLL3_DIVQ,	RCC_PLL3CR,		5,	0),
	GATE_CFG(GATE_PLL3_DIVR,	RCC_PLL3CR,		6,	0),
	GATE_CFG(GATE_PLL4,		RCC_PLL4CR,		0,	0),
	GATE_CFG(GATE_PLL4_RDY,		RCC_PLL4CR,		1,	0),
	GATE_CFG(GATE_PLL4_DIVP,	RCC_PLL4CR,		4,	0),
	GATE_CFG(GATE_PLL4_DIVQ,	RCC_PLL4CR,		5,	0),
	GATE_CFG(GATE_PLL4_DIVR,	RCC_PLL4CR,		6,	0),
	GATE_CFG(GATE_DDRC1,		RCC_DDRITFCR,		0,	0),
	GATE_CFG(GATE_DDRC1LP,		RCC_DDRITFCR,		1,	0),
	GATE_CFG(GATE_DDRPHYC,		RCC_DDRITFCR,		4,	0),
	GATE_CFG(GATE_DDRPHYCLP,	RCC_DDRITFCR,		5,	0),
	GATE_CFG(GATE_DDRCAPB,		RCC_DDRITFCR,		6,	0),
	GATE_CFG(GATE_DDRCAPBLP,	RCC_DDRITFCR,		7,	0),
	GATE_CFG(GATE_AXIDCG,		RCC_DDRITFCR,		8,	0),
	GATE_CFG(GATE_DDRPHYCAPB,	RCC_DDRITFCR,		9,	0),
	GATE_CFG(GATE_DDRPHYCAPBLP,	RCC_DDRITFCR,		10,	0),
	GATE_CFG(GATE_TIM2,		RCC_MP_APB1ENSETR,	0,	1),
	GATE_CFG(GATE_TIM3,		RCC_MP_APB1ENSETR,	1,	1),
	GATE_CFG(GATE_TIM4,		RCC_MP_APB1ENSETR,	2,	1),
	GATE_CFG(GATE_TIM5,		RCC_MP_APB1ENSETR,	3,	1),
	GATE_CFG(GATE_TIM6,		RCC_MP_APB1ENSETR,	4,	1),
	GATE_CFG(GATE_TIM7,		RCC_MP_APB1ENSETR,	5,	1),
	GATE_CFG(GATE_LPTIM1,		RCC_MP_APB1ENSETR,	9,	1),
	GATE_CFG(GATE_SPI2,		RCC_MP_APB1ENSETR,	11,	1),
	GATE_CFG(GATE_SPI3,		RCC_MP_APB1ENSETR,	12,	1),
	GATE_CFG(GATE_USART3,		RCC_MP_APB1ENSETR,	15,	1),
	GATE_CFG(GATE_UART4,		RCC_MP_APB1ENSETR,	16,	1),
	GATE_CFG(GATE_UART5,		RCC_MP_APB1ENSETR,	17,	1),
	GATE_CFG(GATE_UART7,		RCC_MP_APB1ENSETR,	18,	1),
	GATE_CFG(GATE_UART8,		RCC_MP_APB1ENSETR,	19,	1),
	GATE_CFG(GATE_I2C1,		RCC_MP_APB1ENSETR,	21,	1),
	GATE_CFG(GATE_I2C2,		RCC_MP_APB1ENSETR,	22,	1),
	GATE_CFG(GATE_SPDIF,		RCC_MP_APB1ENSETR,	26,	1),
	GATE_CFG(GATE_TIM1,		RCC_MP_APB2ENSETR,	0,	1),
	GATE_CFG(GATE_TIM8,		RCC_MP_APB2ENSETR,	1,	1),
	GATE_CFG(GATE_SPI1,		RCC_MP_APB2ENSETR,	8,	1),
	GATE_CFG(GATE_USART6,		RCC_MP_APB2ENSETR,	13,	1),
	GATE_CFG(GATE_SAI1,		RCC_MP_APB2ENSETR,	16,	1),
	GATE_CFG(GATE_SAI2,		RCC_MP_APB2ENSETR,	17,	1),
	GATE_CFG(GATE_DFSDM,		RCC_MP_APB2ENSETR,	20,	1),
	GATE_CFG(GATE_ADFSDM,		RCC_MP_APB2ENSETR,	21,	1),
	GATE_CFG(GATE_FDCAN,		RCC_MP_APB2ENSETR,	24,	1),
	GATE_CFG(GATE_LPTIM2,		RCC_MP_APB3ENSETR,	0,	1),
	GATE_CFG(GATE_LPTIM3,		RCC_MP_APB3ENSETR,	1,	1),
	GATE_CFG(GATE_LPTIM4,		RCC_MP_APB3ENSETR,	2,	1),
	GATE_CFG(GATE_LPTIM5,		RCC_MP_APB3ENSETR,	3,	1),
	GATE_CFG(GATE_VREF,		RCC_MP_APB3ENSETR,	13,	1),
	GATE_CFG(GATE_DTS,		RCC_MP_APB3ENSETR,	16,	1),
	GATE_CFG(GATE_PMBCTRL,		RCC_MP_APB3ENSETR,	17,	1),
	GATE_CFG(GATE_HDP,		RCC_MP_APB3ENSETR,	20,	1),
	GATE_CFG(GATE_SYSCFG,		RCC_MP_S_APB3ENSETR,	0,	1),
	GATE_CFG(GATE_DCMIPP,		RCC_MP_APB4ENSETR,	1,	1),
	GATE_CFG(GATE_DDRPERFM,		RCC_MP_APB4ENSETR,	8,	1),
	GATE_CFG(GATE_IWDG2APB,		RCC_MP_APB4ENSETR,	15,	1),
	GATE_CFG(GATE_USBPHY,		RCC_MP_APB4ENSETR,	16,	1),
	GATE_CFG(GATE_STGENRO,		RCC_MP_APB4ENSETR,	20,	1),
	GATE_CFG(GATE_LTDC,		RCC_MP_S_APB4ENSETR,	0,	1),
	GATE_CFG(GATE_RTCAPB,		RCC_MP_APB5ENSETR,	8,	1),
	GATE_CFG(GATE_TZC,		RCC_MP_APB5ENSETR,	11,	1),
	GATE_CFG(GATE_ETZPC,		RCC_MP_APB5ENSETR,	13,	1),
	GATE_CFG(GATE_IWDG1APB,		RCC_MP_APB5ENSETR,	15,	1),
	GATE_CFG(GATE_BSEC,		RCC_MP_APB5ENSETR,	16,	1),
	GATE_CFG(GATE_STGENC,		RCC_MP_APB5ENSETR,	20,	1),
	GATE_CFG(GATE_USART1,		RCC_MP_APB6ENSETR,	0,	1),
	GATE_CFG(GATE_USART2,		RCC_MP_APB6ENSETR,	1,	1),
	GATE_CFG(GATE_SPI4,		RCC_MP_APB6ENSETR,	2,	1),
	GATE_CFG(GATE_SPI5,		RCC_MP_APB6ENSETR,	3,	1),
	GATE_CFG(GATE_I2C3,		RCC_MP_APB6ENSETR,	4,	1),
	GATE_CFG(GATE_I2C4,		RCC_MP_APB6ENSETR,	5,	1),
	GATE_CFG(GATE_I2C5,		RCC_MP_APB6ENSETR,	6,	1),
	GATE_CFG(GATE_TIM12,		RCC_MP_APB6ENSETR,	7,	1),
	GATE_CFG(GATE_TIM13,		RCC_MP_APB6ENSETR,	8,	1),
	GATE_CFG(GATE_TIM14,		RCC_MP_APB6ENSETR,	9,	1),
	GATE_CFG(GATE_TIM15,		RCC_MP_APB6ENSETR,	10,	1),
	GATE_CFG(GATE_TIM16,		RCC_MP_APB6ENSETR,	11,	1),
	GATE_CFG(GATE_TIM17,		RCC_MP_APB6ENSETR,	12,	1),
	GATE_CFG(GATE_DMA1,		RCC_MP_AHB2ENSETR,	0,	1),
	GATE_CFG(GATE_DMA2,		RCC_MP_AHB2ENSETR,	1,	1),
	GATE_CFG(GATE_DMAMUX1,		RCC_MP_AHB2ENSETR,	2,	1),
	GATE_CFG(GATE_DMA3,		RCC_MP_AHB2ENSETR,	3,	1),
	GATE_CFG(GATE_DMAMUX2,		RCC_MP_AHB2ENSETR,	4,	1),
	GATE_CFG(GATE_ADC1,		RCC_MP_AHB2ENSETR,	5,	1),
	GATE_CFG(GATE_ADC2,		RCC_MP_AHB2ENSETR,	6,	1),
	GATE_CFG(GATE_USBO,		RCC_MP_AHB2ENSETR,	8,	1),
	GATE_CFG(GATE_TSC,		RCC_MP_AHB4ENSETR,	15,	1),
	GATE_CFG(GATE_GPIOA,		RCC_MP_S_AHB4ENSETR,	0,	1),
	GATE_CFG(GATE_GPIOB,		RCC_MP_S_AHB4ENSETR,	1,	1),
	GATE_CFG(GATE_GPIOC,		RCC_MP_S_AHB4ENSETR,	2,	1),
	GATE_CFG(GATE_GPIOD,		RCC_MP_S_AHB4ENSETR,	3,	1),
	GATE_CFG(GATE_GPIOE,		RCC_MP_S_AHB4ENSETR,	4,	1),
	GATE_CFG(GATE_GPIOF,		RCC_MP_S_AHB4ENSETR,	5,	1),
	GATE_CFG(GATE_GPIOG,		RCC_MP_S_AHB4ENSETR,	6,	1),
	GATE_CFG(GATE_GPIOH,		RCC_MP_S_AHB4ENSETR,	7,	1),
	GATE_CFG(GATE_GPIOI,		RCC_MP_S_AHB4ENSETR,	8,	1),
	GATE_CFG(GATE_PKA,		RCC_MP_AHB5ENSETR,	2,	1),
	GATE_CFG(GATE_SAES,		RCC_MP_AHB5ENSETR,	3,	1),
	GATE_CFG(GATE_CRYP1,		RCC_MP_AHB5ENSETR,	4,	1),
	GATE_CFG(GATE_HASH1,		RCC_MP_AHB5ENSETR,	5,	1),
	GATE_CFG(GATE_RNG1,		RCC_MP_AHB5ENSETR,	6,	1),
	GATE_CFG(GATE_BKPSRAM,		RCC_MP_AHB5ENSETR,	8,	1),
	GATE_CFG(GATE_AXIMC,		RCC_MP_AHB5ENSETR,	16,	1),
	GATE_CFG(GATE_MCE,		RCC_MP_AHB6ENSETR,	1,	1),
	GATE_CFG(GATE_ETH1CK,		RCC_MP_AHB6ENSETR,	7,	1),
	GATE_CFG(GATE_ETH1TX,		RCC_MP_AHB6ENSETR,	8,	1),
	GATE_CFG(GATE_ETH1RX,		RCC_MP_AHB6ENSETR,	9,	1),
	GATE_CFG(GATE_ETH1MAC,		RCC_MP_AHB6ENSETR,	10,	1),
	GATE_CFG(GATE_FMC,		RCC_MP_AHB6ENSETR,	12,	1),
	GATE_CFG(GATE_QSPI,		RCC_MP_AHB6ENSETR,	14,	1),
	GATE_CFG(GATE_SDMMC1,		RCC_MP_AHB6ENSETR,	16,	1),
	GATE_CFG(GATE_SDMMC2,		RCC_MP_AHB6ENSETR,	17,	1),
	GATE_CFG(GATE_CRC1,		RCC_MP_AHB6ENSETR,	20,	1),
	GATE_CFG(GATE_USBH,		RCC_MP_AHB6ENSETR,	24,	1),
	GATE_CFG(GATE_ETH2CK,		RCC_MP_AHB6ENSETR,	27,	1),
	GATE_CFG(GATE_ETH2TX,		RCC_MP_AHB6ENSETR,	28,	1),
	GATE_CFG(GATE_ETH2RX,		RCC_MP_AHB6ENSETR,	29,	1),
	GATE_CFG(GATE_ETH2MAC,		RCC_MP_AHB6ENSETR,	30,	1),
	GATE_CFG(GATE_MDMA,		RCC_MP_S_AHB6ENSETR,	0,	1),
};

/*
 * MUX CONFIG
 */
#define MUXRDY_CFG(_id, _offset, _shift, _witdh, _rdy)\
	[(_id)] = {\
			.offset	= (_offset),\
			.shift	= (_shift),\
			.width	= (_witdh),\
			.ready	= (_rdy),\
	}

#define MUX_CFG(_id, _offset, _shift, _witdh)\
	MUXRDY_CFG(_id, _offset, _shift, _witdh, MUX_NO_RDY)

static const struct mux_cfg parent_mp13[MUX_NB] = {
	MUXRDY_CFG(MUX_MPU,	RCC_MPCKSELR,		0, 2, GATE_MPUSRCRDY),
	MUXRDY_CFG(MUX_AXI,	RCC_ASSCKSELR,		0, 3, GATE_AXISSRCRDY),
	MUXRDY_CFG(MUX_MLAHB,	RCC_MSSCKSELR,		0, 2, GATE_MCUSSRCRDY),
	MUXRDY_CFG(MUX_PLL12,	RCC_RCK12SELR,		0, 2, GATE_PLL12SRCRDY),
	MUXRDY_CFG(MUX_PLL3,	RCC_RCK3SELR,		0, 2, GATE_PLL3SRCRDY),
	MUXRDY_CFG(MUX_PLL4,	RCC_RCK4SELR,		0, 2, GATE_PLL4SRCRDY),
	MUX_CFG(MUX_ADC1,	RCC_ADC12CKSELR,	0, 2),
	MUX_CFG(MUX_ADC2,	RCC_ADC12CKSELR,	2, 2),
	MUX_CFG(MUX_CKPER,	RCC_CPERCKSELR,		0, 2),
	MUX_CFG(MUX_DCMIPP,	RCC_DCMIPPCKSELR,	0, 2),
	MUX_CFG(MUX_ETH1,	RCC_ETH12CKSELR,	0, 2),
	MUX_CFG(MUX_ETH2,	RCC_ETH12CKSELR,	8, 2),
	MUX_CFG(MUX_FDCAN,	RCC_FDCANCKSELR,	0, 2),
	MUX_CFG(MUX_FMC,	RCC_FMCCKSELR,		0, 2),
	MUX_CFG(MUX_I2C12,	RCC_I2C12CKSELR,	0, 3),
	MUX_CFG(MUX_I2C3,	RCC_I2C345CKSELR,	0, 3),
	MUX_CFG(MUX_I2C4,	RCC_I2C345CKSELR,	3, 3),
	MUX_CFG(MUX_I2C5,	RCC_I2C345CKSELR,	6, 3),
	MUX_CFG(MUX_LPTIM1,	RCC_LPTIM1CKSELR,	0, 3),
	MUX_CFG(MUX_LPTIM2,	RCC_LPTIM23CKSELR,	0, 3),
	MUX_CFG(MUX_LPTIM3,	RCC_LPTIM23CKSELR,	3, 3),
	MUX_CFG(MUX_LPTIM45,	RCC_LPTIM45CKSELR,	0, 3),
	MUX_CFG(MUX_MCO1,	RCC_MCO1CFGR,		0, 3),
	MUX_CFG(MUX_MCO2,	RCC_MCO2CFGR,		0, 3),
	MUX_CFG(MUX_QSPI,	RCC_QSPICKSELR,		0, 2),
	MUX_CFG(MUX_RNG1,	RCC_RNG1CKSELR,		0, 2),
	MUX_CFG(MUX_RTC,	RCC_BDCR,		16, 2),
	MUX_CFG(MUX_SAES,	RCC_SAESCKSELR,		0, 2),
	MUX_CFG(MUX_SAI1,	RCC_SAI1CKSELR,		0, 3),
	MUX_CFG(MUX_SAI2,	RCC_SAI2CKSELR,		0, 3),
	MUX_CFG(MUX_SDMMC1,	RCC_SDMMC12CKSELR,	0, 3),
	MUX_CFG(MUX_SDMMC2,	RCC_SDMMC12CKSELR,	3, 3),
	MUX_CFG(MUX_SPDIF,	RCC_SPDIFCKSELR,	0, 2),
	MUX_CFG(MUX_SPI1,	RCC_SPI2S1CKSELR,	0, 3),
	MUX_CFG(MUX_SPI23,	RCC_SPI2S23CKSELR,	0, 3),
	MUX_CFG(MUX_SPI4,	RCC_SPI45CKSELR,	0, 3),
	MUX_CFG(MUX_SPI5,	RCC_SPI45CKSELR,	3, 3),
	MUX_CFG(MUX_STGEN,	RCC_STGENCKSELR,	0, 2),
	MUX_CFG(MUX_UART1,	RCC_UART12CKSELR,	0, 3),
	MUX_CFG(MUX_UART2,	RCC_UART12CKSELR,	3, 3),
	MUX_CFG(MUX_UART35,	RCC_UART35CKSELR,	0, 3),
	MUX_CFG(MUX_UART4,	RCC_UART4CKSELR,	0, 3),
	MUX_CFG(MUX_UART6,	RCC_UART6CKSELR,	0, 3),
	MUX_CFG(MUX_UART78,	RCC_UART78CKSELR,	0, 3),
	MUX_CFG(MUX_USBO,	RCC_USBCKSELR,		4, 1),
	MUX_CFG(MUX_USBPHY,	RCC_USBCKSELR,		0, 2),
};

/*
 * DIV CONFIG
 */
static const struct div_table_cfg axi_div_table[] = {
	{ 0, 1 }, { 1, 2 }, { 2, 3 }, { 3, 4 },
	{ 4, 4 }, { 5, 4 }, { 6, 4 }, { 7, 4 },
	{ 0 },
};

static const struct div_table_cfg mlahb_div_table[] = {
	{ 0, 1 }, { 1, 2 }, { 2, 4 }, { 3, 8 },
	{ 4, 16 }, { 5, 32 }, { 6, 64 }, { 7, 128 },
	{ 8, 256 }, { 9, 512 }, { 10, 512}, { 11, 512 },
	{ 12, 512 }, { 13, 512 }, { 14, 512}, { 15, 512 },
	{ 0 },
};

static const struct div_table_cfg apb_div_table[] = {
	{ 0, 1 }, { 1, 2 }, { 2, 4 }, { 3, 8 },
	{ 4, 16 }, { 5, 16 }, { 6, 16 }, { 7, 16 },
	{ 0 },
};

#define DIVRDY_CFG(_id, _offset, _shift, _width, _flags, _table, _ready)\
	[(_id)] = {\
		.offset	= (_offset),\
		.shift	= (_shift),\
		.width	= (_width),\
		.flags	= (_flags),\
		.table	= (_table),\
		.ready	= (_ready),\
	}

#define DIV_CFG(_id, _offset, _shift, _width, _flags, _table)\
	DIVRDY_CFG(_id, _offset, _shift, _width, _flags, _table, DIV_NO_RDY)

static const struct div_cfg dividers_mp13[] = {
	DIVRDY_CFG(DIV_MPU, RCC_MPCKDIVR, 0, 4, 0, NULL,
		   GATE_MPUDIVRDY),
	DIVRDY_CFG(DIV_AXI, RCC_AXIDIVR, 0, 3, 0, axi_div_table,
		   GATE_AXIDIVRDY),
	DIVRDY_CFG(DIV_MLAHB, RCC_MLAHBDIVR, 0, 4, 0, mlahb_div_table,
		   GATE_MLAHBDIVRDY),
	DIVRDY_CFG(DIV_APB1, RCC_APB1DIVR, 0, 3, 0, apb_div_table,
		   GATE_APB1DIVRDY),
	DIVRDY_CFG(DIV_APB2, RCC_APB2DIVR, 0, 3, 0, apb_div_table,
		   GATE_APB2DIVRDY),
	DIVRDY_CFG(DIV_APB3, RCC_APB3DIVR, 0, 3, 0, apb_div_table,
		   GATE_APB3DIVRDY),
	DIVRDY_CFG(DIV_APB4, RCC_APB4DIVR, 0, 3, 0, apb_div_table,
		   GATE_APB4DIVRDY),
	DIVRDY_CFG(DIV_APB5, RCC_APB5DIVR, 0, 3, 0, apb_div_table,
		   GATE_APB5DIVRDY),
	DIVRDY_CFG(DIV_APB6, RCC_APB6DIVR, 0, 3, 0, apb_div_table,
		   GATE_APB6DIVRDY),
	DIVRDY_CFG(DIV_HSI, RCC_HSICFGR, 0, 2, CLK_DIVIDER_POWER_OF_TWO, NULL,
		   GATE_HSIDIVRDY),
	DIV_CFG(DIV_PLL1DIVP, RCC_PLL1CFGR2, 0, 7, 0, NULL),
	DIV_CFG(DIV_PLL2DIVP, RCC_PLL2CFGR2, 0, 7, 0, NULL),
	DIV_CFG(DIV_PLL2DIVQ, RCC_PLL2CFGR2, 8, 7, 0, NULL),
	DIV_CFG(DIV_PLL2DIVR, RCC_PLL2CFGR2, 16, 7, 0, NULL),
	DIV_CFG(DIV_PLL3DIVP, RCC_PLL3CFGR2, 0, 7, 0, NULL),
	DIV_CFG(DIV_PLL3DIVQ, RCC_PLL3CFGR2, 8, 7, 0, NULL),
	DIV_CFG(DIV_PLL3DIVR, RCC_PLL3CFGR2, 16, 7, 0, NULL),
	DIV_CFG(DIV_PLL4DIVP, RCC_PLL4CFGR2, 0, 7, 0, NULL),
	DIV_CFG(DIV_PLL4DIVQ, RCC_PLL4CFGR2, 8, 7, 0, NULL),
	DIV_CFG(DIV_PLL4DIVR, RCC_PLL4CFGR2, 16, 7, 0, NULL),
	DIV_CFG(DIV_RTC, RCC_RTCDIVR, 0, 6, 0, NULL),
	DIV_CFG(DIV_MCO1, RCC_MCO1CFGR, 4, 4, 0, NULL),
	DIV_CFG(DIV_MCO2, RCC_MCO2CFGR, 4, 4, 0, NULL),
	DIV_CFG(DIV_TRACE, RCC_DBGCFGR, 0, 3, CLK_DIVIDER_POWER_OF_TWO, NULL),
	DIV_CFG(DIV_ETH1PTP, RCC_ETH12CKSELR, 4, 4, 0, NULL),
	DIV_CFG(DIV_ETH2PTP, RCC_ETH12CKSELR, 12, 4, 0, NULL),
};

enum stm32_osc {
	OSC_HSI,
	OSC_HSE,
	OSC_CSI,
	OSC_LSI,
	OSC_LSE,
	NB_OSCILLATOR
};

struct stm32_osc_cfg {
	int osc_id;
};

struct clk_stm32_bypass {
	uint16_t offset;
	uint8_t bit_byp;
	uint8_t bit_digbyp;
};

struct clk_stm32_css {
	uint16_t offset;
	uint8_t bit_css;
};

struct clk_stm32_drive {
	uint16_t offset;
	uint8_t drv_shift;
	uint8_t drv_width;
	uint8_t drv_default;
};

struct clk_oscillator_data {
	const char *name;
	unsigned long frequency;
	uint16_t gate_id;
	struct clk_stm32_bypass *bypass;
	struct clk_stm32_css *css;
	struct clk_stm32_drive *drive;
};

#define BYPASS(_offset, _bit_byp, _bit_digbyp) (&(struct clk_stm32_bypass){\
	.offset		= (_offset),\
	.bit_byp	= (_bit_byp),\
	.bit_digbyp	= (_bit_digbyp),\
})

#define CSS(_offset, _bit_css) (&(struct clk_stm32_css){\
	.offset		= (_offset),\
	.bit_css	= (_bit_css),\
})

#define DRIVE(_offset, _shift, _width, _default) (&(struct clk_stm32_drive){\
	.offset		= (_offset),\
	.drv_shift	= (_shift),\
	.drv_width	= (_width),\
	.drv_default	= (_default),\
})

#define OSCILLATOR(idx_osc, _name, _gate_id, _bypass, _css, _drive) \
	[(idx_osc)] = (struct clk_oscillator_data){\
		.name		= (_name),\
		.gate_id	= (_gate_id),\
		.bypass		= (_bypass),\
		.css		= (_css),\
		.drive		= (_drive),\
	}

static struct clk_oscillator_data stm32mp13_osc_data[NB_OSCILLATOR] = {
	OSCILLATOR(OSC_HSI, "clk-hsi", GATE_HSI,
		   NULL, NULL, NULL),

	OSCILLATOR(OSC_LSI, "clk-lsi", GATE_LSI,
		   NULL, NULL, NULL),

	OSCILLATOR(OSC_CSI, "clk-csi", GATE_CSI,
		   NULL, NULL, NULL),

	OSCILLATOR(OSC_LSE, "clk-lse", GATE_LSE,
		   BYPASS(RCC_BDCR, 1, 3),
		   CSS(RCC_BDCR, 8),
		   DRIVE(RCC_BDCR, 4, 2, 2)),

	OSCILLATOR(OSC_HSE, "clk-hse", GATE_HSE,
		   BYPASS(RCC_OCENSETR, 10, 7),
		   CSS(RCC_OCENSETR, 11),
		   NULL),
};

static struct clk_oscillator_data *clk_oscillator_get_data(int osc_id)
{
	assert(osc_id >= 0 && osc_id < (int)ARRAY_SIZE(stm32mp13_osc_data));

	return &stm32mp13_osc_data[osc_id];
}

static unsigned long clk_stm32_get_rate_oscillateur(int osc_id)
{
	struct clk_stm32_priv *priv = clk_stm32_get_priv();
	struct stm32_clk_platdata *pdata = priv->pdata;
	struct stm32_osci_dt_cfg *osci = &pdata->osci[osc_id];

	return osci->freq;
}

static void clk_oscillator_set_bypass(struct clk_stm32_priv *priv,
				      struct clk_oscillator_data *osc_data,
				      bool digbyp, bool bypass)
{
	struct clk_stm32_bypass *bypass_data = osc_data->bypass;
	uintptr_t address = 0;

	if (!bypass_data)
		return;

	address = priv->base + bypass_data->offset;

	if (digbyp)
		io_setbits32(address, BIT(bypass_data->bit_digbyp));

	if (bypass || digbyp)
		io_setbits32(address, BIT(bypass_data->bit_byp));
}

static void clk_oscillator_set_css(struct clk_stm32_priv *priv,
				   struct clk_oscillator_data *osc_data,
				   bool css)
{
	struct clk_stm32_css *css_data = osc_data->css;
	uintptr_t address = 0;

	if (!css_data)
		return;

	address = priv->base + css_data->offset;

	if (css)
		io_setbits32(address, BIT(css_data->bit_css));
}

static void clk_oscillator_set_drive(struct clk_stm32_priv *priv,
				     struct clk_oscillator_data *osc_data,
				     uint8_t lsedrv)
{
	struct clk_stm32_drive *drive_data = osc_data->drive;
	uintptr_t address = 0;
	uint32_t mask = 0;
	uint32_t value = 0;

	if (!drive_data)
		return;

	address = priv->base + drive_data->offset;

	mask = (BIT(drive_data->drv_width) - 1U) << drive_data->drv_shift;

	/*
	 * Warning: not recommended to switch directly from "high drive"
	 * to "medium low drive", and vice-versa.
	 */
	value = (io_read32(address) & mask) >> drive_data->drv_shift;

	while (value != lsedrv) {
		if (value > lsedrv)
			value--;
		else
			value++;

		io_clrsetbits32(address, mask, value << drive_data->drv_shift);
	}
}

static void stm32_enable_oscillator_hse(struct clk_stm32_priv *priv,
					struct stm32_clk_platdata *pdata)
{
	struct clk_oscillator_data *osc_data = clk_oscillator_get_data(OSC_HSE);
	struct stm32_osci_dt_cfg *osci = &pdata->osci[OSC_HSE];

	if (osci->freq == 0U)
		return;

	clk_oscillator_set_bypass(priv, osc_data,  osci->digbyp, osci->bypass);

	/* Enable clock and wait ready bit */
	if (stm32_gate_rdy_enable(osc_data->gate_id)) {
		EMSG("timeout to enable hse clock");
		panic();
	}

	clk_oscillator_set_css(priv, osc_data, osci->css);
}

static void stm32_enable_oscillator_lse(struct clk_stm32_priv *priv,
					struct stm32_clk_platdata *pdata)
{
	struct clk_oscillator_data *osc_data = clk_oscillator_get_data(OSC_LSE);
	struct stm32_osci_dt_cfg *osci = &pdata->osci[OSC_LSE];

	if (osci->freq == 0U)
		return;

	clk_oscillator_set_bypass(priv, osc_data, osci->digbyp, osci->bypass);

	clk_oscillator_set_drive(priv, osc_data,  osci->drive);

	/* Enable lse clock, but don't wait ready bit */
	stm32_gate_enable(osc_data->gate_id);
}

static void
stm32_enable_oscillator_lsi(struct clk_stm32_priv *priv __maybe_unused,
			    struct stm32_clk_platdata *pdata)
{
	struct clk_oscillator_data *osc_data = clk_oscillator_get_data(OSC_LSI);
	struct stm32_osci_dt_cfg *osci = &pdata->osci[OSC_LSI];

	if (osci->freq == 0U)
		return;

	/* Enable clock and wait ready bit */
	if (stm32_gate_rdy_enable(osc_data->gate_id)) {
		EMSG("timeout to enable lsi clock");
		panic();
	}
}

static void
stm32_enable_oscillator_csi(struct clk_stm32_priv *priv __maybe_unused,
			    struct stm32_clk_platdata *pdata)
{
	struct clk_oscillator_data *osc_data = clk_oscillator_get_data(OSC_CSI);
	struct stm32_osci_dt_cfg *osci = &pdata->osci[OSC_CSI];

	if (osci->freq == 0U)
		return;

	/* Enable clock and wait ready bit */
	if (stm32_gate_rdy_enable(osc_data->gate_id)) {
		EMSG("timeout to enable csi clock");
		panic();
	}
}

static int stm32_clk_oscillators_lse_set_css(struct clk_stm32_priv *priv,
					     struct stm32_clk_platdata *pdata)

{
	struct clk_oscillator_data *osc_data = clk_oscillator_get_data(OSC_LSE);
	struct stm32_osci_dt_cfg *osci = &pdata->osci[OSC_LSE];

	clk_oscillator_set_css(priv, osc_data, osci->css);

	return 0;
}

static int
stm32_clk_oscillators_wait_lse_ready(struct clk_stm32_priv *priv __maybe_unused,
				     struct stm32_clk_platdata *pdata)
{
	struct clk_oscillator_data *osc_data = clk_oscillator_get_data(OSC_LSE);
	struct stm32_osci_dt_cfg *osci = &pdata->osci[OSC_LSE];

	if (osci->freq == 0U)
		return 0;

	if (stm32_gate_wait_ready(osc_data->gate_id, true))
		return -1;

	return 0;
}

static void stm32_clk_oscillators_enable(struct clk_stm32_priv *priv,
					 struct stm32_clk_platdata *pdata)
{
	stm32_enable_oscillator_hse(priv, pdata);
	stm32_enable_oscillator_lse(priv, pdata);
	stm32_enable_oscillator_lsi(priv, pdata);
	stm32_enable_oscillator_csi(priv, pdata);
}

enum stm32_pll_id {
	PLL1_ID,
	PLL2_ID,
	PLL3_ID,
	PLL4_ID,
	PLL_NB
};

enum stm32mp1_plltype {
	PLL_800,
	PLL_1600,
	PLL_2000,
	PLL_TYPE_NB
};

#define RCC_OFFSET_PLLXCR		0
#define RCC_OFFSET_PLLXCFGR1		4
#define RCC_OFFSET_PLLXCFGR2		8
#define RCC_OFFSET_PLLXFRACR		12
#define RCC_OFFSET_PLLXCSGR		16

struct stm32_clk_pll {
	enum stm32mp1_plltype plltype;
	uint16_t gate_id;
	uint16_t mux_id;
	uint16_t reg_pllxcr;
};

struct stm32mp1_pll {
	uint8_t refclk_min;
	uint8_t refclk_max;
};

/* Define characteristic of PLL according type */
static const struct stm32mp1_pll stm32mp1_pll[PLL_TYPE_NB] = {
	[PLL_800] = {
		.refclk_min = 4,
		.refclk_max = 16,
	},
	[PLL_1600] = {
		.refclk_min = 8,
		.refclk_max = 16,
	},
	[PLL_2000] = {
		.refclk_min = 8,
		.refclk_max = 16,
	}
};

#define CLK_PLL_CFG(_idx, _type, _gate_id, _mux_id, _reg)\
	[(_idx)] = {\
		.gate_id = (_gate_id),\
		.mux_id = (_mux_id),\
		.plltype = (_type),\
		.reg_pllxcr = (_reg),\
	}

static const struct stm32_clk_pll stm32_mp13_clk_pll[PLL_NB] = {
	CLK_PLL_CFG(PLL1_ID, PLL_2000, GATE_PLL1, MUX_PLL12, RCC_PLL1CR),
	CLK_PLL_CFG(PLL2_ID, PLL_1600, GATE_PLL2, MUX_PLL12, RCC_PLL2CR),
	CLK_PLL_CFG(PLL3_ID, PLL_800, GATE_PLL3, MUX_PLL3, RCC_PLL3CR),
	CLK_PLL_CFG(PLL4_ID, PLL_800, GATE_PLL4, MUX_PLL4, RCC_PLL4CR),
};

static const struct stm32_clk_pll *clk_stm32_pll_data(unsigned int idx)
{
	return &stm32_mp13_clk_pll[idx];
}

/* Clock TREE configuration */

static unsigned int stm32_clk_configure_clk_get_binding_id(uint32_t data)
{
	return (data & CLK_ID_MASK) >> CLK_ID_SHIFT;
}

static int stm32_clk_configure_clk(struct clk_stm32_priv *priv __maybe_unused,
				   uint32_t data)
{
	int sel = (data & CLK_SEL_MASK) >> CLK_SEL_SHIFT;
	int enable = (data & CLK_ON_MASK) >> CLK_ON_SHIFT;
	int clk_id = 0;
	int ret = 0;
	int mux = -1;
	int gate = -1;

	clk_id = stm32_clk_configure_clk_get_binding_id(data);

	switch (clk_id)	{
	case CK_MCO1:
		mux = MUX_MCO1;
		gate = GATE_MCO1;
		break;

	case CK_MCO2:
		mux = MUX_MCO2;
		gate = GATE_MCO2;
		break;
	default:
		ret = -1;
		break;
	}

	if (ret != 0)
		return ret;

	if (stm32_mux_set_parent(mux, sel))
		return -1;

	if (enable)
		stm32_gate_enable(gate);
	else
		stm32_gate_disable(gate);

	return 0;
}

static int stm32_clk_configure_mux(__unused struct clk_stm32_priv *priv,
				   uint32_t data)
{
	int mux = (data & MUX_ID_MASK) >> MUX_ID_SHIFT;
	int sel = (data & MUX_SEL_MASK) >> MUX_SEL_SHIFT;

	if (mux == MUX_RTC) {
		/* Mux RTC clock only is selector is valid and RTC not yet
		 * enabled
		 */
		if (sel == 0)
			return 0;

		if (stm32_gate_is_enabled(GATE_RTCCK))
			return 0;
	}

	if (stm32_mux_set_parent(mux, sel))
		return -1;

	return 0;
}

static TEE_Result
stm32_clk_configure_div(struct clk_stm32_priv *priv __maybe_unused,
			uint32_t data)
{
	int div_id = (data & DIV_ID_MASK) >> DIV_ID_SHIFT;
	int div_n = (data & DIV_DIVN_MASK) >> DIV_DIVN_SHIFT;

	return stm32_div_set_value(div_id, div_n);
}

static int stm32_clk_dividers_configure(struct clk_stm32_priv *priv)
{
	struct stm32_clk_platdata *pdata = priv->pdata;
	unsigned int i = 0;

	for (i = 0; i < pdata->nclkdiv; i++) {
		if (stm32_clk_configure_div(priv, pdata->clkdiv[i]))
			return -1;
	}

	return 0;
}

static int stm32_clk_source_configure(struct clk_stm32_priv *priv)
{
	struct stm32_clk_platdata *pdata = priv->pdata;
	bool ckper_disabled = false;
	int ret = 0;
	size_t i = 0;

	for (i = 0; i < pdata->nclksrc; i++) {
		uint32_t val = pdata->clksrc[i];
		uint32_t cmd = 0;
		uint32_t cmd_data = 0;

		if (val == (uint32_t)CLK_CKPER_DISABLED) {
			ckper_disabled = true;
			continue;
		}

		cmd = (val & CMD_MASK) >> CMD_SHIFT;
		cmd_data = val & ~CMD_MASK;

		switch (cmd) {
		case CMD_MUX:
			ret = stm32_clk_configure_mux(priv, cmd_data);
			break;

		case CMD_CLK:
			ret = stm32_clk_configure_clk(priv, cmd_data);
			break;
		default:
			ret = -1;
			break;
		}

		if (ret != 0)
			return ret;
	}

	/*
	 * CKPER is source for some peripheral clocks
	 * (FMC-NAND / QPSI-NOR) and switching source is allowed
	 * only if previous clock is still ON
	 * => deactivate CKPER only after switching clock
	 */
	if (ckper_disabled) {
		ret = stm32_clk_configure_mux(priv,
					      CLK_CKPER_DISABLED & CMD_MASK);
		if (ret != 0)
			return ret;
	}

	return 0;
}

static unsigned long clk_stm32_pll_get_oscillator_rate(int sel)
{
	const int osc[] = { OSC_HSI, OSC_HSE, OSC_CSI };

	assert(sel >= 0 && sel < (int)ARRAY_SIZE(osc));

	return clk_stm32_get_rate_oscillateur(osc[sel]);
}

static int clk_stm32_pll_compute_cfgr1(const struct stm32_clk_pll *pll,
				       struct stm32_pll_vco *vco,
				       uint32_t *value)
{
	int sel = (vco->src & MUX_SEL_MASK) >> MUX_SEL_SHIFT;
	uint32_t divm = vco->div_mn[PLL_CFG_M];
	uint32_t divn = vco->div_mn[PLL_CFG_N];
	unsigned long refclk = 0UL;

	refclk = clk_stm32_pll_get_oscillator_rate(sel) / (divm + 1U);

	if ((refclk < (stm32mp1_pll[pll->plltype].refclk_min * 1000000U)) ||
	    (refclk > (stm32mp1_pll[pll->plltype].refclk_max * 1000000U)))
		return -1;

	*value = 0;

	if (pll->plltype == PLL_800 && refclk >= 8000000U)
		*value = 1U << RCC_PLLNCFGR1_IFRGE_SHIFT;

	*value |= (divn << RCC_PLLNCFGR1_DIVN_SHIFT) & RCC_PLLNCFGR1_DIVN_MASK;
	*value |= (divm << RCC_PLLNCFGR1_DIVM_SHIFT) & RCC_PLLNCFGR1_DIVM_MASK;

	return 0;
}

static uint32_t  clk_stm32_pll_compute_cfgr2(struct stm32_pll_output *out)
{
	uint32_t value = 0;

	value |= (out->output[PLL_CFG_P] << RCC_PLLNCFGR2_DIVP_SHIFT) &
		 RCC_PLLNCFGR2_DIVP_MASK;
	value |= (out->output[PLL_CFG_Q] << RCC_PLLNCFGR2_DIVQ_SHIFT) &
		 RCC_PLLNCFGR2_DIVQ_MASK;
	value |= (out->output[PLL_CFG_R] << RCC_PLLNCFGR2_DIVR_SHIFT) &
		 RCC_PLLNCFGR2_DIVR_MASK;

	return value;
}

/*
 * Check if PLL1 can be configured on the fly.
 * @result (-1) => config on the fly is not possible.
 *         (0)  => config on the fly is possible.
 *         (+1) => same parameters, no need to reconfigure.
 * Return value is 0 if no error.
 */
static int clk_stm32_is_pll_config_on_the_fly(struct clk_stm32_priv *priv,
					      const struct stm32_clk_pll *pll,
					      struct stm32_pll_dt_cfg *pll_conf,
					      int *result)
{
	uintptr_t pll_base = priv->base + pll->reg_pllxcr;
	struct stm32_pll_vco *vco = &pll_conf->vco;
	struct stm32_pll_output *out = &pll_conf->output;
	uint32_t fracr = 0;
	uint32_t value = 0;
	int ret = 0;
	size_t sel = 0;

	ret = clk_stm32_pll_compute_cfgr1(pll, vco, &value);
	if (ret != 0)
		return ret;

	sel = (vco->src & MUX_SEL_MASK) >> MUX_SEL_SHIFT;
	if (sel != stm32_mux_get_parent(pll->mux_id)) {
		/* Clock source of the PLL is different */
		*result = -1;
		return 0;
	}

	if (io_read32(pll_base + RCC_OFFSET_PLLXCFGR1) != value) {
		/* Different DIVN/DIVM, can't config on the fly */
		*result = -1;
		return 0;
	}

	*result = 1;

	fracr = vco->frac << RCC_PLLNFRACR_FRACV_SHIFT;
	fracr |= RCC_PLLNCFGR1_DIVM_MASK;
	value = clk_stm32_pll_compute_cfgr2(out);

	if ((io_read32(pll_base + RCC_OFFSET_PLLXFRACR) == fracr) &&
	    (io_read32(pll_base + RCC_OFFSET_PLLXCFGR2) == value)) {
		/* Same parameters, no need to config */
		*result = 1;
	} else {
		*result = 0;
	}

	return 0;
}

static int stm32_clk_hsidiv_configure(struct clk_stm32_priv *priv)
{
	struct stm32_clk_platdata *pdata = priv->pdata;
	struct stm32_osci_dt_cfg *osci = &pdata->osci[OSC_HSI];

	return stm32_div_set_rate(DIV_HSI, osci->freq, MAX_HSI_HZ);
}

static void clk_stm32_pll_config_vco(struct clk_stm32_priv *priv,
				     const struct stm32_clk_pll *pll,
				     struct stm32_pll_vco *vco)
{
	uintptr_t pll_base = priv->base + pll->reg_pllxcr;
	uint32_t value = 0;

	if (clk_stm32_pll_compute_cfgr1(pll, vco, &value) != 0) {
		EMSG("Invalid Vref clock");
		panic();
	}

	/* Write N / M / IFREGE fields */
	io_write32(pll_base + RCC_OFFSET_PLLXCFGR1, value);

	/* Fractional configuration */
	io_write32(pll_base + RCC_OFFSET_PLLXFRACR, 0);

	/* Frac must be enabled only once its configuration is loaded */
	io_write32(pll_base + RCC_OFFSET_PLLXFRACR,
		   vco->frac << RCC_PLLNFRACR_FRACV_SHIFT);

	io_setbits32(pll_base + RCC_OFFSET_PLLXFRACR, RCC_PLLNFRACR_FRACLE);
}

static void clk_stm32_pll_config_csg(struct clk_stm32_priv *priv,
				     const struct stm32_clk_pll *pll,
				     struct stm32_pll_vco *vco)
{
	uintptr_t pll_base = priv->base + pll->reg_pllxcr;
	uint32_t mod_per = 0;
	uint32_t inc_step = 0;
	uint32_t sscg_mode = 0;
	uint32_t value = 0;

	if (!vco->csg_enabled)
		return;

	mod_per = vco->csg[PLL_CSG_MOD_PER];
	inc_step = vco->csg[PLL_CSG_INC_STEP];
	sscg_mode = vco->csg[PLL_CSG_SSCG_MODE];

	value |= (mod_per << RCC_PLLNCSGR_MOD_PER_SHIFT) &
		 RCC_PLLNCSGR_MOD_PER_MASK;
	value |= (inc_step << RCC_PLLNCSGR_INC_STEP_SHIFT) &
		 RCC_PLLNCSGR_INC_STEP_MASK;
	value |= (sscg_mode << RCC_PLLNCSGR_SSCG_MODE_SHIFT) &
		 RCC_PLLNCSGR_SSCG_MODE_MASK;

	io_write32(pll_base + RCC_OFFSET_PLLXCSGR, value);
	io_setbits32(pll_base + RCC_OFFSET_PLLXCR, RCC_PLLNCR_SSCG_CTRL);
}

static void clk_stm32_pll_config_out(struct clk_stm32_priv *priv,
				     const struct stm32_clk_pll *pll,
				     struct stm32_pll_output *out)
{
	uintptr_t pll_base = priv->base + pll->reg_pllxcr;
	uint32_t value = 0;

	value = clk_stm32_pll_compute_cfgr2(out);

	io_write32(pll_base + RCC_OFFSET_PLLXCFGR2, value);
}

static struct stm32_pll_dt_cfg *clk_stm32_pll_get_pdata(int pll_idx)
{
	struct clk_stm32_priv *priv = clk_stm32_get_priv();
	struct stm32_clk_platdata *pdata = priv->pdata;

	return &pdata->pll[pll_idx];
}

static int clk_stm32_pll_init_switch_to_hsi_clk_system(int mux_sys)
{
	int sel = 0;

	if (mux_sys == -1)
		return -1;

	/* Make a backup to the current parent */
	sel = stm32_mux_get_parent(mux_sys);

	/* Switch to HSI */
	if (stm32_mux_set_parent(mux_sys, 0))
		return -1;

	return sel;
}

static uint32_t
clk_stm32_pll_backup_output_diven(const struct stm32_clk_pll *pll)
{
	struct clk_stm32_priv *priv = clk_stm32_get_priv();
	uintptr_t addr = priv->base + pll->reg_pllxcr;

	return io_read32(addr + RCC_OFFSET_PLLXCR) &
			 (RCC_PLLNCR_DIVPEN | RCC_PLLNCR_DIVQEN |
			  RCC_PLLNCR_DIVREN);
}

static void clk_stm32_pll_restore_output_diven(const struct stm32_clk_pll *pll,
					       uint32_t value)
{
	struct clk_stm32_priv *priv = clk_stm32_get_priv();
	uintptr_t addr = priv->base + pll->reg_pllxcr;
	const uint32_t mask = RCC_PLLNCR_DIVPEN | RCC_PLLNCR_DIVQEN |
			      RCC_PLLNCR_DIVREN;

	io_clrsetbits32(addr, mask, value & mask);
}

static int clk_stm32_pll_init(struct clk_stm32_priv *priv, int pll_idx,
			      struct stm32_pll_dt_cfg *pll_conf)
{
	const struct stm32_clk_pll *pll = clk_stm32_pll_data(pll_idx);
	int config_on_the_fly = -1;
	int ret = 0;
	uint8_t sel = 0;
	uint32_t save_div_pqr_en = 0;
	int mux_system[] = { MUX_MPU, MUX_AXI, MUX_MLAHB, -1 };
	int mux_sys  = mux_system[pll_idx];

	ret = clk_stm32_is_pll_config_on_the_fly(priv, pll, pll_conf,
						 &config_on_the_fly);
	if (ret != 0)
		return ret;

	/* Backup status of DIV DIVPEN / DIVQEN / DIVREN */
	save_div_pqr_en = clk_stm32_pll_backup_output_diven(pll);

	if (config_on_the_fly == -1) {
		/* Make a backup to the current parent and switch to HSI */
		sel = clk_stm32_pll_init_switch_to_hsi_clk_system(mux_sys);

		/* Stop the PLL before */
		if (stm32_gate_is_enabled(pll->gate_id))  {
			io_clrbits32(priv->base + pll->reg_pllxcr,
				     RCC_PLLNCR_DIVPEN | RCC_PLLNCR_DIVQEN |
				     RCC_PLLNCR_DIVREN);

			if (stm32_gate_rdy_disable(pll->gate_id))
				return -1;
		}

		/* Configure PLLs source */
		ret = stm32_clk_configure_mux(priv, pll_conf->vco.src);
		if (ret)
			return ret;

		clk_stm32_pll_config_vco(priv, pll, &pll_conf->vco);
	}

	if (config_on_the_fly != 1) {
		clk_stm32_pll_config_out(priv, pll, &pll_conf->output);
		clk_stm32_pll_config_csg(priv, pll, &pll_conf->vco);
	}

	if (!stm32_gate_is_enabled(pll->gate_id)) {
		if (stm32_gate_rdy_enable(pll->gate_id))
			return -1;

		clk_stm32_pll_restore_output_diven(pll, save_div_pqr_en);
	}

	if ((config_on_the_fly == -1) && (mux_sys != -1)) {
		/* Restore to backup parent */
		if (stm32_mux_set_parent(mux_sys, sel))
			return -1;
	}

	return 0;
}

static int stm32_clk_pll_configure(struct clk_stm32_priv *priv)
{
	struct stm32_pll_dt_cfg *pll_conf = NULL;
	size_t i = 0;
	const int plls[] = { PLL1_ID, PLL3_ID, PLL4_ID };

	for (i = 0; i < ARRAY_SIZE(plls); i++) {
		pll_conf = clk_stm32_pll_get_pdata(plls[i]);

		if (pll_conf->vco.status) {
			int err = 0;

			err = clk_stm32_pll_init(priv, plls[i], pll_conf);
			if (err)
				return err;
		}
	}

	return 0;
}

static int stm32mp1_init_clock_tree(struct clk_stm32_priv *priv,
				    struct stm32_clk_platdata *pdata)
{
	int ret = 0;

	/*
	 * Switch ON oscillators found in device-tree.
	 * Note: HSI already ON after BootROM stage.
	 */
	stm32_clk_oscillators_enable(priv, pdata);

	ret = stm32_clk_hsidiv_configure(priv);
	if (ret != 0)
		return ret;

	ret = stm32_clk_dividers_configure(priv);
	if (ret != 0)
		panic();

	ret = stm32_clk_pll_configure(priv);
	if (ret != 0)
		panic();

	/* Wait LSE ready before to use it */
	ret = stm32_clk_oscillators_wait_lse_ready(priv, pdata);
	if (ret != 0)
		panic();

	/* Configure with expected clock source */
	ret = stm32_clk_source_configure(priv);
	if (ret != 0)
		panic();

	/* Configure LSE CSS after RTC source configuration */
	ret = stm32_clk_oscillators_lse_set_css(priv, pdata);
	if (ret != 0)
		panic();

	/* Software Self-Refresh mode (SSR) during DDR initilialization */
	io_clrsetbits32(priv->base + RCC_DDRITFCR, RCC_DDRITFCR_DDRCKMOD_MASK,
			RCC_DDRITFCR_DDRCKMOD_SSR <<
			RCC_DDRITFCR_DDRCKMOD_SHIFT);

	return 0;
}

static int clk_stm32_parse_oscillator_fdt(const void *fdt, int node,
					  const char *name,
					  struct stm32_osci_dt_cfg *osci)
{
	int subnode = 0;

	fdt_for_each_subnode(subnode, fdt, node) {
		const char *cchar = NULL;
		const fdt32_t *cuint = NULL;
		int ret = 0;

		cchar = fdt_get_name(fdt, subnode, &ret);
		if (!cchar)
			return ret;

		if (strncmp(cchar, name, (size_t)ret) ||
		    _fdt_get_status(fdt, subnode) == DT_STATUS_DISABLED)
			continue;

		cuint = fdt_getprop(fdt, subnode, "clock-frequency", &ret);
		if (!cuint)
			panic();

		osci->freq = fdt32_to_cpu(*cuint);

		if (fdt_getprop(fdt, subnode, "st,bypass", NULL))
			osci->bypass = true;

		if (fdt_getprop(fdt, subnode, "st,digbypass", NULL))
			osci->digbyp = true;

		if (fdt_getprop(fdt, subnode, "st,css", NULL))
			osci->css = true;

		osci->drive = _fdt_read_uint32_default(fdt, subnode, "st,drive",
						       LSEDRV_MEDIUM_HIGH);

		return 0;
	}

	return -FDT_ERR_NOTFOUND;
}

static int stm32_clk_parse_fdt_all_oscillator(const void *fdt,
					      int node __maybe_unused,
					      struct stm32_clk_platdata *pdata)
{
	int fdt_err = 0;
	size_t i = 0;
	int osc_node = 0;

	osc_node = fdt_path_offset(fdt, "/clocks");
	if (osc_node < 0)
		return -FDT_ERR_NOTFOUND;

	for (i = 0; i < NB_OSCILLATOR; i++) {
		struct stm32_osci_dt_cfg *osci = &pdata->osci[i];
		struct clk_oscillator_data *osc_data = NULL;

		osc_data = clk_oscillator_get_data(i);

		fdt_err = clk_stm32_parse_oscillator_fdt(fdt, osc_node,
							 osc_data->name, osci);
		if (fdt_err < 0)
			panic();
	}

	return 0;
}

static int clk_stm32_load_vco_config_fdt(const void *fdt, int subnode,
					 struct stm32_pll_vco *vco)
{
	int ret = 0;

	ret = _fdt_read_uint32_array(fdt, subnode, "divmn", vco->div_mn,
				     PLL_DIV_MN_NB);
	if (ret != 0)
		return ret;

	ret = _fdt_read_uint32_array(fdt, subnode, "csg", vco->csg,
				     PLL_CSG_NB);

	vco->csg_enabled = (ret == 0);

	if (ret == -FDT_ERR_NOTFOUND)
		ret = 0;

	if (ret != 0)
		return ret;

	vco->status = RCC_PLLNCR_DIVPEN | RCC_PLLNCR_DIVQEN |
		      RCC_PLLNCR_DIVREN | RCC_PLLNCR_PLLON;

	vco->frac = _fdt_read_uint32_default(fdt, subnode, "frac", 0);

	vco->src = _fdt_read_uint32_default(fdt, subnode, "src", UINT32_MAX);

	return 0;
}

static int clk_stm32_load_output_config_fdt(const void *fdt, int subnode,
					    struct stm32_pll_output *output)
{
	return _fdt_read_uint32_array(fdt, subnode, "st,pll_div_pqr",
				      output->output, (int)PLL_DIV_PQR_NB);
}

static int clk_stm32_parse_pll_fdt(const void *fdt, int subnode,
				   struct stm32_pll_dt_cfg *pll)
{
	const fdt32_t *cuint = NULL;
	int subnode_pll = 0;
	int subnode_vco = 0;
	int err = 0;

	cuint = fdt_getprop(fdt, subnode, "st,pll", NULL);
	if (!cuint)
		return -FDT_ERR_NOTFOUND;

	subnode_pll = fdt_node_offset_by_phandle(fdt, fdt32_to_cpu(*cuint));
	if (subnode_pll < 0)
		return -FDT_ERR_NOTFOUND;

	cuint = fdt_getprop(fdt, subnode_pll, "st,pll_vco", NULL);
	if (!cuint)
		return -FDT_ERR_NOTFOUND;

	subnode_vco = fdt_node_offset_by_phandle(fdt, fdt32_to_cpu(*cuint));
	if (subnode_vco < 0)
		return -FDT_ERR_NOTFOUND;

	err = clk_stm32_load_vco_config_fdt(fdt, subnode_vco, &pll->vco);
	if (err != 0)
		return err;

	err = clk_stm32_load_output_config_fdt(fdt, subnode_pll, &pll->output);
	if (err != 0)
		return err;

	return 0;
}

static int stm32_clk_parse_fdt_all_pll(const void *fdt, int node,
				       struct stm32_clk_platdata *pdata)
{
	size_t i = 0;

	for (i = PLL1_ID; i < pdata->npll; i++) {
		struct stm32_pll_dt_cfg *pll = pdata->pll + i;
		char name[RCC_PLL_NAME_SIZE] = { 0 };
		int subnode = 0;
		int err = 0;

		snprintf(name, sizeof(name), "st,pll@%d", i);

		subnode = fdt_subnode_offset(fdt, node, name);
		if (subnode < 0)
			continue;

		err = clk_stm32_parse_pll_fdt(fdt, subnode, pll);
		if (err != 0)
			panic();
	}

	return 0;
}

static int stm32_clk_parse_fdt_opp(const void *fdt, int node,
				   const char *opp_name,
				   struct stm32_clk_opp_cfg *opp_cfg)
{
	int subnode = 0;
	int nb_opp = 0;
	int ret = 0;

	node = fdt_subnode_offset(fdt, node, opp_name);
	if (node == -FDT_ERR_NOTFOUND)
		return 0;
	if (node < 0)
		return node;

	fdt_for_each_subnode(subnode, fdt, node) {
		if (nb_opp >= MAX_OPP) {
			EMSG("%d MAX opp in %s", MAX_OPP, opp_name);
			panic();
		}

		opp_cfg->frq = _fdt_read_uint32_default(fdt, subnode,
							"hz",
							UINT32_MAX);

		opp_cfg->src = _fdt_read_uint32_default(fdt, subnode,
							"st,clksrc",
							UINT32_MAX);

		opp_cfg->div = _fdt_read_uint32_default(fdt, subnode,
							"st,clkdiv",
							UINT32_MAX);

		ret = clk_stm32_parse_pll_fdt(fdt, subnode, &opp_cfg->pll_cfg);
		if (ret)
			return ret;

		opp_cfg++;
		nb_opp++;
	}

	return 0;
}

static int stm32_clk_parse_fdt_all_opp(const void *fdt, int node,
				       struct stm32_clk_platdata *pdata)
{
	struct stm32_clk_opp_dt_cfg *opp = pdata->opp;
	int ret = 0;

	node = fdt_subnode_offset(fdt, node, "st,clk_opp");
	/* No opp are defined */
	if (node == -FDT_ERR_NOTFOUND)
		return 0;
	if (node < 0)
		return node;

	ret = stm32_clk_parse_fdt_opp(fdt, node, "st,ck_mpu", opp->mpu_opp);
	if (ret)
		return ret;

	ret = stm32_clk_parse_fdt_opp(fdt, node, "st,ck_axi", opp->axi_opp);
	if (ret)
		return ret;

	ret = stm32_clk_parse_fdt_opp(fdt, node, "st,ck_mlahbs",
				      opp->mlahbs_opp);
	if (ret)
		return ret;

	return 0;
}

static int stm32_clk_parse_fdt(const void *fdt, int node,
			       struct stm32_clk_platdata *pdata)
{
	int err = 0;

	err = stm32_clk_parse_fdt_all_oscillator(fdt, node, pdata);
	if (err != 0)
		return err;

	err = stm32_clk_parse_fdt_all_pll(fdt, node, pdata);
	if (err != 0)
		return err;

	err = stm32_clk_parse_fdt_all_opp(fdt, node, pdata);
	if (err != 0)
		return err;

	err = clk_stm32_parse_fdt_by_name(fdt, node, "st,clkdiv", pdata->clkdiv,
					  &pdata->nclkdiv);
	if (err != 0)
		return err;

	err = clk_stm32_parse_fdt_by_name(fdt, node, "st,clksrc", pdata->clksrc,
					  &pdata->nclksrc);
	if (err != 0)
		return err;

	return 0;
}

static struct stm32_pll_dt_cfg mp13_pll[PLL_NB];
static struct stm32_clk_opp_dt_cfg mp13_clk_opp;
static struct stm32_osci_dt_cfg mp13_osci[NB_OSCILLATOR];
static uint32_t mp13_clksrc[MUX_NB];
static uint32_t mp13_clkdiv[DIV_NB];

static struct stm32_clk_platdata stm32mp13_clock_pdata = {
	.osci		= mp13_osci,
	.nosci		= NB_OSCILLATOR,
	.pll		= mp13_pll,
	.opp		= &mp13_clk_opp,
	.npll		= PLL_NB,
	.clksrc		= mp13_clksrc,
	.nclksrc	= MUX_NB,
	.clkdiv		= mp13_clkdiv,
	.nclkdiv	= DIV_NB,
};

static struct clk_stm32_priv stm32mp13_clock_data = {
	.muxes			= parent_mp13,
	.nb_muxes		= ARRAY_SIZE(parent_mp13),
	.gates			= gates_mp13,
	.nb_gates		= ARRAY_SIZE(gates_mp13),
	.div			= dividers_mp13,
	.nb_div			= ARRAY_SIZE(dividers_mp13),
	.pdata			= &stm32mp13_clock_pdata,
};

static TEE_Result stm32mp13_clk_probe(const void *fdt, int node,
				      const void *compat_data __unused)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	int fdt_rc = 0;
	int rc = 0;
	struct clk_stm32_priv *priv = &stm32mp13_clock_data;
	struct stm32_clk_platdata *pdata = &stm32mp13_clock_pdata;

	fdt_rc = stm32_clk_parse_fdt(fdt, node, pdata);
	if (fdt_rc) {
		EMSG("Failed to parse clock node: %d", fdt_rc);
		return TEE_ERROR_GENERIC;
	}

	res = clk_stm32_init(priv, stm32_rcc_base());
	if (res)
		return res;

	rc = stm32mp1_init_clock_tree(priv, pdata);
	if (rc)
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

CLK_DT_DECLARE(stm32mp13_clk, "st,stm32mp13-rcc", stm32mp13_clk_probe);
