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
		    fdt_get_status(fdt, subnode) == DT_STATUS_DISABLED)
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

		osci->drive = fdt_read_uint32_default(fdt, subnode, "st,drive",
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
		if (fdt_err) {
			if (fdt_err == -FDT_ERR_NOTFOUND) {
				/* Oscillator not found means it is not wired */
				osci->freq = 0;
			} else {
				panic();
			}
		}
	}

	return 0;
}

static int clk_stm32_load_vco_config_fdt(const void *fdt, int subnode,
					 struct stm32_pll_vco *vco)
{
	int ret = 0;

	ret = fdt_read_uint32_array(fdt, subnode, "divmn", vco->div_mn,
				    PLL_DIV_MN_NB);
	if (ret != 0)
		return ret;

	ret = fdt_read_uint32_array(fdt, subnode, "csg", vco->csg,
				    PLL_CSG_NB);

	vco->csg_enabled = (ret == 0);

	if (ret == -FDT_ERR_NOTFOUND)
		ret = 0;

	if (ret != 0)
		return ret;

	vco->status = RCC_PLLNCR_DIVPEN | RCC_PLLNCR_DIVQEN |
		      RCC_PLLNCR_DIVREN | RCC_PLLNCR_PLLON;

	vco->frac = fdt_read_uint32_default(fdt, subnode, "frac", 0);

	vco->src = fdt_read_uint32_default(fdt, subnode, "src", UINT32_MAX);

	return 0;
}

static int clk_stm32_load_output_config_fdt(const void *fdt, int subnode,
					    struct stm32_pll_output *output)
{
	return fdt_read_uint32_array(fdt, subnode, "st,pll_div_pqr",
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

		opp_cfg->frq = fdt_read_uint32_default(fdt, subnode,
						       "hz",
						       UINT32_MAX);

		opp_cfg->src = fdt_read_uint32_default(fdt, subnode,
						       "st,clksrc",
						       UINT32_MAX);

		opp_cfg->div = fdt_read_uint32_default(fdt, subnode,
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

struct clk_stm32_pll_cfg {
	uint32_t reg_pllxcr;
	int gate_id;
	int mux_id;
};

static size_t clk_stm32_pll_get_parent(struct clk *clk)
{
	struct clk_stm32_pll_cfg *cfg = clk->priv;

	return stm32_mux_get_parent(cfg->mux_id);
}

static unsigned long clk_stm32_pll_get_rate(struct clk *clk,
					    unsigned long prate)
{
	struct clk_stm32_priv *priv = clk_stm32_get_priv();
	struct clk_stm32_pll_cfg *cfg = clk->priv;
	uintptr_t pll_base = priv->base + cfg->reg_pllxcr;
	uint32_t cfgr1 = 0;
	uint32_t fracr = 0;
	uint32_t divm = 0;
	uint32_t divn = 0;
	unsigned long fvco = 0UL;

	cfgr1 = io_read32(pll_base + RCC_OFFSET_PLLXCFGR1);
	fracr = io_read32(pll_base + RCC_OFFSET_PLLXFRACR);

	divm = (cfgr1 & (RCC_PLLNCFGR1_DIVM_MASK)) >> RCC_PLLNCFGR1_DIVM_SHIFT;
	divn = cfgr1 & RCC_PLLNCFGR1_DIVN_MASK;

	/*
	 * With FRACV :
	 *   Fvco = Fck_ref * ((DIVN + 1) + FRACV / 2^13) / (DIVM + 1)
	 * Without FRACV
	 *   Fvco = Fck_ref * ((DIVN + 1) / (DIVM + 1)
	 */
	if ((fracr & RCC_PLLNFRACR_FRACLE) != 0U) {
		uint32_t fracv = (fracr & RCC_PLLNFRACR_FRACV_MASK) >>
				 RCC_PLLNFRACR_FRACV_SHIFT;
		unsigned long long numerator = 0UL;
		unsigned long long denominator = 0UL;

		numerator = (((unsigned long long)divn + 1U) << 13) + fracv;
		numerator = prate * numerator;
		denominator = ((unsigned long long)divm + 1U) << 13;
		fvco = (unsigned long)(numerator / denominator);
	} else {
		fvco = (unsigned long)(prate * (divn + 1U) / (divm + 1U));
	}

	return UDIV_ROUND_NEAREST(fvco, 100000) * 100000;
};

static bool clk_stm32_pll_is_enabled(struct clk *clk)
{
	struct clk_stm32_pll_cfg *cfg = clk->priv;

	return stm32_gate_is_enabled(cfg->gate_id);
}

static TEE_Result clk_stm32_pll_enable(struct clk *clk)
{
	struct clk_stm32_pll_cfg *cfg = clk->priv;

	if (clk_stm32_pll_is_enabled(clk))
		return TEE_SUCCESS;

	return stm32_gate_rdy_enable(cfg->gate_id);
}

static void clk_stm32_pll_disable(struct clk *clk)
{
	struct clk_stm32_pll_cfg *cfg = clk->priv;
	struct clk_stm32_priv *priv = clk_stm32_get_priv();
	uintptr_t pll_base = priv->base + cfg->reg_pllxcr;

	if (!clk_stm32_pll_is_enabled(clk))
		return;

	/* Stop all output */
	io_clrbits32(pll_base, RCC_PLLNCR_DIVPEN | RCC_PLLNCR_DIVQEN |
		     RCC_PLLNCR_DIVREN);

	stm32_gate_rdy_disable(cfg->gate_id);
}

static const struct clk_ops clk_stm32_pll_ops = {
	.get_parent	= clk_stm32_pll_get_parent,
	.get_rate	= clk_stm32_pll_get_rate,
	.enable		= clk_stm32_pll_enable,
	.disable	= clk_stm32_pll_disable,
};

static TEE_Result
clk_stm32_composite_get_duty_cycle(struct clk *clk,
				   struct clk_duty_cycle *duty_cycle)
{
	struct clk_stm32_composite_cfg *cfg = clk->priv;
	uint32_t val = stm32_div_get_value(cfg->div_id);

	duty_cycle->num = (val + 1) / 2;
	duty_cycle->den = val + 1;

	return TEE_SUCCESS;
}

static const struct clk_ops clk_stm32_composite_duty_cycle_ops = {
	.get_parent	= clk_stm32_composite_get_parent,
	.set_parent	= clk_stm32_composite_set_parent,
	.get_rate	= clk_stm32_composite_get_rate,
	.set_rate	= clk_stm32_composite_set_rate,
	.enable		= clk_stm32_composite_gate_enable,
	.disable	= clk_stm32_composite_gate_disable,
	.get_duty_cycle	= clk_stm32_composite_get_duty_cycle,
};

static struct
stm32_clk_opp_cfg *clk_stm32_get_opp_config(struct stm32_clk_opp_cfg *opp_cfg,
					    unsigned long rate)
{
	unsigned int i = 0;

	for (i = 0; i < MAX_OPP; i++, opp_cfg++) {
		if (opp_cfg->frq == 0UL)
			break;

		if (opp_cfg->frq == rate)
			return opp_cfg;
	}

	return NULL;
}

static TEE_Result clk_stm32_pll1_set_rate(struct clk *clk __maybe_unused,
					  unsigned long rate,
					  unsigned long prate __maybe_unused)
{
	const struct stm32_clk_pll *pll = clk_stm32_pll_data(PLL1_ID);
	struct clk_stm32_priv *priv = clk_stm32_get_priv();
	struct stm32_clk_platdata *pdata = priv->pdata;
	struct stm32_pll_dt_cfg *pll_conf = NULL;
	struct stm32_clk_opp_cfg *opp = NULL;
	int config_on_the_fly = -1;
	int err = 0;
	size_t sel = stm32_mux_get_parent(MUX_MPU);

	opp = clk_stm32_get_opp_config(pdata->opp->mpu_opp, rate);
	if (!opp)
		return TEE_ERROR_GENERIC;

	pll_conf = &opp->pll_cfg;

	err = clk_stm32_is_pll_config_on_the_fly(priv, pll, pll_conf,
						 &config_on_the_fly);
	if (err)
		return TEE_ERROR_GENERIC;

	if (config_on_the_fly == 1)
		return TEE_SUCCESS;

	if (config_on_the_fly == -1) {
		/* Switch to HSI and stop PLL1 before reconfiguration */
		if (stm32_mux_set_parent(MUX_MPU, 0))
			return TEE_ERROR_GENERIC;

		stm32_gate_disable(GATE_PLL1_DIVP);
		stm32_gate_rdy_disable(GATE_PLL1);
		clk_stm32_pll_config_vco(priv, pll, &pll_conf->vco);
	}

	clk_stm32_pll_config_out(priv, pll, &pll_conf->output);
	if (stm32_gate_rdy_enable(GATE_PLL1)) {
		EMSG("timeout to enable PLL1 clock");
		panic();
	}
	stm32_gate_enable(GATE_PLL1_DIVP);

	/* Restore MPU source */
	if (stm32_mux_set_parent(MUX_MPU, sel))
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

static const struct clk_ops clk_stm32_pll1_ops = {
	.set_rate	= clk_stm32_pll1_set_rate,
	.get_parent	= clk_stm32_pll_get_parent,
	.get_rate	= clk_stm32_pll_get_rate,
	.enable		= clk_stm32_pll_enable,
	.disable	= clk_stm32_pll_disable,
};

static const struct clk_ops clk_stm32_pll1p_ops = {
	.get_rate	= clk_stm32_composite_get_rate,
	.enable		= clk_stm32_composite_gate_enable,
	.disable	= clk_stm32_composite_gate_disable,
};

static const struct clk_ops clk_stm32_mpu_ops = {
	.get_parent	= clk_stm32_composite_get_parent,
	.set_parent	= clk_stm32_composite_set_parent,
};

static const struct clk_ops clk_stm32_axi_ops = {
	.get_parent	= clk_stm32_composite_get_parent,
	.set_parent	= clk_stm32_composite_set_parent,
	.set_rate	= clk_stm32_composite_set_rate,
	.get_rate	= clk_stm32_composite_get_rate,
};

const struct clk_ops clk_stm32_mlahb_ops = {
	.get_parent	= clk_stm32_composite_get_parent,
	.set_parent	= clk_stm32_composite_set_parent,
	.set_rate	= clk_stm32_composite_set_rate,
	.get_rate	= clk_stm32_composite_get_rate,
};

#define APB_DIV_MASK	GENMASK_32(2, 0)
#define TIM_PRE_MASK	BIT(0)

static unsigned long ck_timer_get_rate_ops(struct clk *clk, unsigned long prate)
{
	struct clk_stm32_priv *priv = clk_stm32_get_priv();
	struct clk_stm32_timer_cfg *cfg = clk->priv;
	uint32_t prescaler, timpre;
	uintptr_t rcc_base = priv->base;

	prescaler = io_read32(rcc_base + cfg->apbdiv) & APB_DIV_MASK;

	timpre = io_read32(rcc_base + cfg->timpre) & TIM_PRE_MASK;

	if (prescaler == 0U)
		return prate;

	return prate * (timpre + 1U) * 2U;
};

const struct clk_ops ck_timer_ops = {
	.get_rate	= ck_timer_get_rate_ops,
};

#define STM32_TIMER(_name, _parent, _flags, _apbdiv, _timpre)\
	struct clk _name = {\
		.ops	= &ck_timer_ops,\
		.priv	= &(struct clk_stm32_timer_cfg) {\
			.apbdiv		= (_apbdiv),\
			.timpre		= (_timpre),\
		},\
		.name		= #_name,\
		.flags		= (_flags),\
		.num_parents	= 1,\
		.parents	= { _parent },\
	}

#define STM32_KCLK(_name, _nb_parents, _parents, _flags, _gate_id, _mux_id)\
	struct clk _name = {\
		.ops	= &clk_stm32_composite_ops,\
		.priv	= &(struct clk_stm32_composite_cfg) {\
			.gate_id	= (_gate_id),\
			.div_id		= (NO_DIV),\
			.mux_id		= (_mux_id),\
		},\
		.name		= #_name,\
		.flags		= (_flags),\
		.num_parents	= (_nb_parents),\
		.parents	=  _parents,\
	}

#define STM32_PLL_VCO(_name, _nb_parents, _parents, _flags, _reg,\
		      _gate_id, _mux_id)\
	struct clk _name = {\
		.ops	= &clk_stm32_pll_ops,\
		.priv	= &(struct clk_stm32_pll_cfg) {\
			.reg_pllxcr	= (_reg),\
			.gate_id	= (_gate_id),\
			.mux_id		= (_mux_id),\
		},\
		.name		= #_name,\
		.flags		= (_flags),\
		.num_parents	= (_nb_parents),\
		.parents	=  _parents,\
	}

#define STM32_PLL_OUPUT(_name, _nb_parents, _parents, _flags,\
			_gate_id, _div_id, _mux_id)\
	struct clk _name = {\
		.ops	= &clk_stm32_composite_duty_cycle_ops,\
		.priv	= &(struct clk_stm32_composite_cfg) {\
			.gate_id	= (_gate_id),\
			.div_id		= (_div_id),\
			.mux_id		= (_mux_id),\
		},\
		.name		= #_name,\
		.flags		= (_flags),\
		.num_parents	= (_nb_parents),\
		.parents	=  _parents,\
	}

/* Oscillator clocks */

static TEE_Result clk_stm32_oscillator_enable(struct clk *clk)
{
	struct clk_stm32_gate_cfg *cfg = clk->priv;

	if (clk->rate == 0U)
		return TEE_SUCCESS;

	return stm32_gate_rdy_enable(cfg->gate_id);
}

static void clk_stm32_oscillator_disable(struct clk *clk)
{
	struct clk_stm32_gate_cfg *cfg = clk->priv;

	if (clk->rate == 0U)
		return;

	if (stm32_gate_rdy_disable(cfg->gate_id))
		panic();
}

static const struct clk_ops clk_stm32_oscillator_ops = {
	.enable		= clk_stm32_oscillator_enable,
	.disable	= clk_stm32_oscillator_disable,
};

/*
 * Each oscillator has 1 parent which reference is NULL here
 * but set during initialization.
 */
#define STM32_OSCILLATOR(_name, _gate_id)\
	struct clk _name = {\
		.ops = &clk_stm32_oscillator_ops,\
		.priv = &(struct clk_stm32_gate_cfg) {\
			.gate_id = (_gate_id),\
		},\
		.name = #_name,\
		.num_parents = 1, \
		.parents = { NULL }, \
	}

static STM32_OSCILLATOR(ck_hsi, GATE_HSI);
static STM32_OSCILLATOR(ck_hse, GATE_HSE);
static STM32_OSCILLATOR(ck_csi, GATE_CSI);
static STM32_OSCILLATOR(ck_lsi, GATE_LSI);
static STM32_OSCILLATOR(ck_lse, GATE_LSE);

static STM32_FIXED_FACTOR(ck_i2sckin, NULL, 0, 1, 1);
static STM32_FIXED_FACTOR(ck_hse_div2, &ck_hse, 0, 1, 2);

static STM32_FIXED_RATE(ck_off, 0UL);
static STM32_FIXED_RATE(ck_usb_phy_48Mhz, USB_PHY_48_MHZ);

/* PLL1 clocks */
static struct clk ck_pll1_vco = {
	.ops	= &clk_stm32_pll1_ops,
	.priv		= &(struct clk_stm32_pll_cfg) {
		.reg_pllxcr	= RCC_PLL1CR,
		.gate_id	= GATE_PLL1,
		.mux_id		= MUX_PLL12,
	},
	.name		= "ck_pll1_vco",
	.flags		= 0,
	.num_parents	= 2,
	.parents	= { &ck_hsi, &ck_hse },
};

static struct clk ck_pll1p = {
	.ops	= &clk_stm32_pll1p_ops,
	.priv		= &(struct clk_stm32_composite_cfg) {
		.gate_id	= GATE_PLL1_DIVP,
		.div_id		= DIV_PLL1DIVP,
		.mux_id		= NO_MUX,
	},
	.name		= "ck_pll1p",
	.flags		= CLK_SET_RATE_PARENT,
	.num_parents	= 1,
	.parents	= { &ck_pll1_vco },
};

const struct clk_ops clk_stm32_pll1p_div_ops = {
	.get_rate	= clk_stm32_divider_get_rate,
};

static struct clk ck_pll1p_div = {
	.ops	= &clk_stm32_pll1p_div_ops,
	.priv		= &(struct clk_stm32_div_cfg) {
		.div_id	= DIV_MPU,
	},
	.name	= "ck_pll1p_div",
	.flags	= CLK_SET_RATE_PARENT,
	.num_parents	= 1,
	.parents	= { &ck_pll1p },
};

/* Other PLLs */
static STM32_PLL_VCO(ck_pll2_vco, 2, PARENT(&ck_hsi, &ck_hse),
		     0, RCC_PLL2CR, GATE_PLL2, MUX_PLL12);

static STM32_PLL_VCO(ck_pll3_vco, 3,
		     PARENT(&ck_hsi, &ck_hse, &ck_csi),
			    0, RCC_PLL3CR, GATE_PLL3, MUX_PLL3);

static STM32_PLL_VCO(ck_pll4_vco, 4,
		     PARENT(&ck_hsi, &ck_hse, &ck_csi, &ck_i2sckin),
			    0, RCC_PLL4CR, GATE_PLL4, MUX_PLL4);

static STM32_PLL_OUPUT(ck_pll2p, 1, PARENT(&ck_pll2_vco), 0,
		       GATE_PLL2_DIVP, DIV_PLL2DIVP, NO_MUX);

static STM32_PLL_OUPUT(ck_pll2q, 1, PARENT(&ck_pll2_vco), 0,
		       GATE_PLL2_DIVQ, DIV_PLL2DIVQ, NO_MUX);

static STM32_PLL_OUPUT(ck_pll2r, 1, PARENT(&ck_pll2_vco), 0,
		       GATE_PLL2_DIVR, DIV_PLL2DIVR, NO_MUX);

static STM32_PLL_OUPUT(ck_pll3p, 1, PARENT(&ck_pll3_vco), 0,
		       GATE_PLL3_DIVP, DIV_PLL3DIVP, NO_MUX);

static STM32_PLL_OUPUT(ck_pll3q, 1, PARENT(&ck_pll3_vco), 0,
		       GATE_PLL3_DIVQ, DIV_PLL3DIVQ, NO_MUX);

static STM32_PLL_OUPUT(ck_pll3r, 1, PARENT(&ck_pll3_vco), 0,
		       GATE_PLL3_DIVR, DIV_PLL3DIVR, NO_MUX);

static STM32_PLL_OUPUT(ck_pll4p, 1, PARENT(&ck_pll4_vco), 0,
		       GATE_PLL4_DIVP, DIV_PLL4DIVP, NO_MUX);

static STM32_PLL_OUPUT(ck_pll4q, 1, PARENT(&ck_pll4_vco), 0,
		       GATE_PLL4_DIVQ, DIV_PLL4DIVQ, NO_MUX);

static STM32_PLL_OUPUT(ck_pll4r, 1, PARENT(&ck_pll4_vco), 0,
		       GATE_PLL4_DIVR, DIV_PLL4DIVR, NO_MUX);

/* System clocks */
static struct clk ck_mpu = {
	.ops		= &clk_stm32_mpu_ops,
	.priv		= &(struct clk_stm32_composite_cfg) {
		.mux_id	= MUX_MPU,
	},
	.name		= "ck_mpu",
	.flags		= CLK_SET_PARENT_PRE_ENABLE | CLK_SET_RATE_PARENT,
	.num_parents	= 4,
	.parents	= { &ck_hsi, &ck_hse, &ck_pll1p, &ck_pll1p_div },
};

static struct clk ck_axi = {
	.ops		= &clk_stm32_axi_ops,
	.priv		= &(struct clk_stm32_composite_cfg) {
		.mux_id	= MUX_AXI,
		.div_id	= DIV_AXI,
	},
	.name		= "ck_axi",
	.flags		= CLK_SET_PARENT_PRE_ENABLE | CLK_SET_RATE_PARENT,
	.num_parents	= 3,
	.parents	= { &ck_hsi, &ck_hse, &ck_pll2p },
};

static struct clk ck_mlahb = {
	.ops		= &clk_stm32_mlahb_ops,
	.priv		= &(struct clk_stm32_composite_cfg) {
		.mux_id	= MUX_MLAHB,
		.div_id	= DIV_MLAHB,
	},
	.name		= "ck_mlahb",
	.flags		= CLK_SET_PARENT_PRE_ENABLE | CLK_SET_RATE_PARENT,
	.num_parents	= 4,
	.parents	= { &ck_hsi, &ck_hse, &ck_csi, &ck_pll3p },
};

static STM32_MUX(ck_per, 4, PARENT(&ck_hsi, &ck_csi, &ck_hse, &ck_off),
		 0, MUX_CKPER);

/* Bus clocks */
static STM32_DIVIDER(ck_pclk1, &ck_mlahb, 0, DIV_APB1);
static STM32_DIVIDER(ck_pclk2, &ck_mlahb, 0, DIV_APB2);
static STM32_DIVIDER(ck_pclk3, &ck_mlahb, 0, DIV_APB3);
static STM32_DIVIDER(ck_pclk4, &ck_axi, 0, DIV_APB4);
static STM32_DIVIDER(ck_pclk5, &ck_axi, 0, DIV_APB5);
static STM32_DIVIDER(ck_pclk6, &ck_mlahb, 0, DIV_APB6);

/* Timer Clocks */
static STM32_TIMER(ck_timg1, &ck_pclk1, 0, RCC_APB1DIVR, RCC_TIMG1PRER);
static STM32_TIMER(ck_timg2, &ck_pclk2, 0, RCC_APB2DIVR, RCC_TIMG2PRER);
static STM32_TIMER(ck_timg3, &ck_pclk6, 0, RCC_APB6DIVR, RCC_TIMG3PRER);

/* Peripheral and Kernel Clocks */
static STM32_GATE(ck_ddrc1, &ck_axi, 0, GATE_DDRC1);
static STM32_GATE(ck_ddrc1lp, &ck_axi, 0, GATE_DDRC1LP);
static STM32_GATE(ck_ddrphyc, &ck_pll2r, 0, GATE_DDRPHYC);
static STM32_GATE(ck_ddrphyclp, &ck_pll2r, 0, GATE_DDRPHYCLP);
static STM32_GATE(ck_ddrcapb, &ck_pclk4, 0, GATE_DDRCAPB);
static STM32_GATE(ck_ddrcapblp, &ck_pclk4, 0, GATE_DDRCAPBLP);
static STM32_GATE(ck_axidcg, &ck_axi, 0, GATE_AXIDCG);
static STM32_GATE(ck_ddrphycapb, &ck_pclk4, 0, 0);
static STM32_GATE(ck_ddrphycapblp, &ck_pclk4, 0, GATE_DDRPHYCAPBLP);
static STM32_GATE(ck_syscfg, &ck_pclk3, 0, GATE_SYSCFG);
static STM32_GATE(ck_ddrperfm, &ck_pclk4, 0, GATE_DDRPERFM);
static STM32_GATE(ck_iwdg2, &ck_pclk4, 0, GATE_IWDG2APB);
static STM32_GATE(ck_rtcapb, &ck_pclk5, 0, GATE_RTCAPB);
static STM32_GATE(ck_tzc, &ck_pclk5, 0, GATE_TZC);
static STM32_GATE(ck_etzpcb, &ck_pclk5, 0, GATE_ETZPC);
static STM32_GATE(ck_iwdg1apb, &ck_pclk5, 0, GATE_IWDG1APB);
static STM32_GATE(ck_bsec, &ck_pclk5, 0, GATE_BSEC);
static STM32_GATE(ck_tim12_k, &ck_timg3, 0, GATE_TIM12);
static STM32_GATE(ck_tim15_k, &ck_timg3, 0, GATE_TIM15);
static STM32_GATE(ck_gpioa, &ck_mlahb, 0, GATE_GPIOA);
static STM32_GATE(ck_gpiob, &ck_mlahb, 0, GATE_GPIOB);
static STM32_GATE(ck_gpioc, &ck_mlahb, 0, GATE_GPIOC);
static STM32_GATE(ck_gpiod, &ck_mlahb, 0, GATE_GPIOD);
static STM32_GATE(ck_gpioe, &ck_mlahb, 0, GATE_GPIOE);
static STM32_GATE(ck_gpiof, &ck_mlahb, 0, GATE_GPIOF);
static STM32_GATE(ck_gpiog, &ck_mlahb, 0, GATE_GPIOG);
static STM32_GATE(ck_gpioh, &ck_mlahb, 0, GATE_GPIOH);
static STM32_GATE(ck_gpioi, &ck_mlahb, 0, GATE_GPIOI);
static STM32_GATE(ck_pka, &ck_axi, 0, GATE_PKA);
static STM32_GATE(ck_cryp1, &ck_pclk5, 0, GATE_CRYP1);
static STM32_GATE(ck_hash1, &ck_pclk5, 0, GATE_HASH1);
static STM32_GATE(ck_bkpsram, &ck_pclk5, 0, GATE_BKPSRAM);
static STM32_GATE(ck_dbg, &ck_axi, 0, GATE_DBGCK);
static STM32_GATE(ck_mce, &ck_axi, 0, GATE_MCE);
static STM32_GATE(ck_tim2_k, &ck_timg1, 0, GATE_TIM2);
static STM32_GATE(ck_tim3_k, &ck_timg1, 0, GATE_TIM3);
static STM32_GATE(ck_tim4_k, &ck_timg1, 0, GATE_TIM4);
static STM32_GATE(ck_tim5_k, &ck_timg1, 0, GATE_TIM5);
static STM32_GATE(ck_tim6_k, &ck_timg1, 0, GATE_TIM6);
static STM32_GATE(ck_tim7_k, &ck_timg1, 0, GATE_TIM7);
static STM32_GATE(ck_tim13_k, &ck_timg3, 0, GATE_TIM13);
static STM32_GATE(ck_tim14_k, &ck_timg3, 0, GATE_TIM14);
static STM32_GATE(ck_tim1_k, &ck_timg2, 0, GATE_TIM1);
static STM32_GATE(ck_tim8_k, &ck_timg2, 0, GATE_TIM8);
static STM32_GATE(ck_tim16_k, &ck_timg3, 0, GATE_TIM16);
static STM32_GATE(ck_tim17_k, &ck_timg3, 0, GATE_TIM17);
static STM32_GATE(ck_ltdc_px, &ck_pll4q, 0, GATE_LTDC);
static STM32_GATE(ck_dma1, &ck_mlahb, 0, GATE_DMA1);
static STM32_GATE(ck_dma2, &ck_mlahb, 0, GATE_DMA2);
static STM32_GATE(ck_adc1, &ck_mlahb, 0, GATE_ADC1);
static STM32_GATE(ck_adc2, &ck_mlahb, 0, GATE_ADC2);
static STM32_GATE(ck_mdma, &ck_axi, 0, GATE_MDMA);
static STM32_GATE(ck_eth1mac, &ck_axi, 0, GATE_ETH1MAC);
static STM32_GATE(ck_usbh, &ck_axi, 0, GATE_USBH);
static STM32_GATE(ck_vref, &ck_pclk3, 0, GATE_VREF);
static STM32_GATE(ck_tmpsens, &ck_pclk3, 0, GATE_DTS);
static STM32_GATE(ck_pmbctrl, &ck_pclk3, 0, GATE_PMBCTRL);
static STM32_GATE(ck_hdp, &ck_pclk3, 0, GATE_HDP);
static STM32_GATE(ck_stgenro, &ck_pclk4, 0, GATE_STGENRO);
static STM32_GATE(ck_dmamux1, &ck_axi, 0, GATE_DMAMUX1);
static STM32_GATE(ck_dmamux2, &ck_axi, 0, GATE_DMAMUX2);
static STM32_GATE(ck_dma3, &ck_axi, 0, GATE_DMA3);
static STM32_GATE(ck_tsc, &ck_axi, 0, GATE_TSC);
static STM32_GATE(ck_aximc, &ck_axi, 0, GATE_AXIMC);
static STM32_GATE(ck_crc1, &ck_axi, 0, GATE_CRC1);
static STM32_GATE(ck_eth1tx, &ck_axi, 0, GATE_ETH1TX);
static STM32_GATE(ck_eth1rx, &ck_axi, 0, GATE_ETH1RX);
static STM32_GATE(ck_eth2tx, &ck_axi, 0, GATE_ETH2TX);
static STM32_GATE(ck_eth2rx, &ck_axi, 0, GATE_ETH2RX);
static STM32_GATE(ck_eth2mac, &ck_axi, 0, GATE_ETH2MAC);
static STM32_GATE(ck_spi1, &ck_pclk2, 0, GATE_SPI1);
static STM32_GATE(ck_spi2, &ck_pclk1, 0, GATE_SPI2);
static STM32_GATE(ck_spi3, &ck_pclk1, 0, GATE_SPI3);
static STM32_GATE(ck_spi4, &ck_pclk6, 0, GATE_SPI4);
static STM32_GATE(ck_spi5, &ck_pclk6, 0, GATE_SPI5);

/* Kernel Clocks */
static STM32_KCLK(ck_usbphy_k, 3,
		  PARENT(&ck_hse, &ck_pll4r, &ck_hse_div2),
		  0, GATE_USBPHY, MUX_USBPHY);

static STM32_KCLK(ck_usbo_k, 2,
		  PARENT(&ck_pll4r, &ck_usb_phy_48Mhz), 0,
		  GATE_USBO, MUX_USBO);

static STM32_KCLK(ck_stgen_k, 2,
		  PARENT(&ck_hsi, &ck_hse), 0, GATE_STGENC, MUX_STGEN);

static STM32_KCLK(ck_usart1_k, 6,
		  PARENT(&ck_pclk6, &ck_pll3q, &ck_hsi,
			 &ck_csi, &ck_pll4q, &ck_hse),
		  0, GATE_USART1, MUX_UART1);

static STM32_KCLK(ck_usart2_k, 6,
		  PARENT(&ck_pclk6, &ck_pll3q, &ck_hsi, &ck_csi, &ck_pll4q,
			 &ck_hse),
		  0, GATE_USART2, MUX_UART2);

static STM32_KCLK(ck_i2c4_k, 4,
		  PARENT(&ck_pclk6, &ck_pll4r, &ck_hsi, &ck_csi),
		  0, GATE_I2C4, MUX_I2C4);

static STM32_KCLK(ck_rtc, 4,
		  PARENT(&ck_off, &ck_lse, &ck_lsi, &ck_hse),
		  0, GATE_RTCCK, MUX_RTC);

static STM32_KCLK(ck_saes_k, 4,
		  PARENT(&ck_axi, &ck_per, &ck_pll4r, &ck_lsi),
		  0, GATE_SAES, MUX_SAES);

static STM32_KCLK(ck_rng1_k, 4,
		  PARENT(&ck_csi, &ck_pll4r, &ck_off, &ck_lsi),
		  0, GATE_RNG1, MUX_RNG1);

static STM32_KCLK(ck_sdmmc1_k, 4,
		  PARENT(&ck_axi, &ck_pll3r, &ck_pll4p, &ck_hsi),
		  0, GATE_SDMMC1, MUX_SDMMC1);

static STM32_KCLK(ck_sdmmc2_k, 4,
		  PARENT(&ck_axi, &ck_pll3r, &ck_pll4p, &ck_hsi),
		  0, GATE_SDMMC2, MUX_SDMMC2);

static STM32_KCLK(ck_usart3_k, 5,
		  PARENT(&ck_pclk1, &ck_pll4q, &ck_hsi, &ck_csi, &ck_hse),
		  0, GATE_USART3, MUX_UART35);

static STM32_KCLK(ck_uart4_k, 5,
		  PARENT(&ck_pclk1, &ck_pll4q, &ck_hsi, &ck_csi, &ck_hse),
		  0, GATE_UART4, MUX_UART4);

static STM32_KCLK(ck_uart5_k, 5,
		  PARENT(&ck_pclk1, &ck_pll4q, &ck_hsi, &ck_csi, &ck_hse),
		  0, GATE_UART5, MUX_UART35);

static STM32_KCLK(ck_uart7_k, 5,
		  PARENT(&ck_pclk1, &ck_pll4q, &ck_hsi, &ck_csi, &ck_hse),
		  0, GATE_UART7, MUX_UART78);

static STM32_KCLK(ck_uart8_k, 5,
		  PARENT(&ck_pclk1, &ck_pll4q, &ck_hsi, &ck_csi, &ck_hse),
		  0, GATE_UART8, MUX_UART78);

static STM32_KCLK(ck_usart6_k, 5,
		  PARENT(&ck_pclk2, &ck_pll4q, &ck_hsi, &ck_csi, &ck_hse),
		  0, GATE_USART6, MUX_UART6);

static STM32_KCLK(ck_fmc_k, 4,
		  PARENT(&ck_axi, &ck_pll3r, &ck_pll4p, &ck_per),
		  0, GATE_FMC, MUX_FMC);

static STM32_KCLK(ck_qspi_k, 4,
		  PARENT(&ck_axi, &ck_pll3r, &ck_pll4p, &ck_per),
		  0, GATE_QSPI, MUX_QSPI);

static STM32_KCLK(ck_lptim1_k, 6,
		  PARENT(&ck_pclk1, &ck_pll4p, &ck_pll3q, &ck_lse, &ck_lsi,
			 &ck_per),
		  0, GATE_LPTIM1, MUX_LPTIM1);

static STM32_KCLK(ck_spi2_k, 5,
		  PARENT(&ck_pll4p, &ck_pll3q, &ck_i2sckin, &ck_per, &ck_pll3r),
		  0, GATE_SPI2, MUX_SPI23);

static STM32_KCLK(ck_spi3_k, 5,
		  PARENT(&ck_pll4p, &ck_pll3q, &ck_i2sckin, &ck_per, &ck_pll3r),
		  0, GATE_SPI3, MUX_SPI23);

static STM32_KCLK(ck_spdif_k, 3,
		  PARENT(&ck_pll4p, &ck_pll3q, &ck_hsi),
		  0, GATE_SPDIF, MUX_SPDIF);

static STM32_KCLK(ck_spi1_k, 5,
		  PARENT(&ck_pll4p, &ck_pll3q, &ck_i2sckin, &ck_per, &ck_pll3r),
		  0, GATE_SPI1, MUX_SPI1);

static STM32_KCLK(ck_spi4_k, 6,
		  PARENT(&ck_pclk6, &ck_pll4q, &ck_hsi, &ck_csi, &ck_hse,
			 &ck_i2sckin),
		  0, GATE_SPI4, MUX_SPI4);

static STM32_KCLK(ck_spi5_k, 5,
		  PARENT(&ck_pclk6, &ck_pll4q, &ck_hsi, &ck_csi, &ck_hse),
		  0, GATE_SPI5, MUX_SPI5);

static STM32_KCLK(ck_sai1_k, 5,
		  PARENT(&ck_pll4q, &ck_pll3q, &ck_i2sckin, &ck_per, &ck_pll3r),
		  0, GATE_SAI1, MUX_SAI1);

static STM32_KCLK(ck_sai2_k, 6,
		  PARENT(&ck_pll4q, &ck_pll3q, &ck_i2sckin, &ck_per, &ck_off,
			 &ck_pll3r),
		  0, GATE_SAI2, MUX_SAI2);

static STM32_KCLK(ck_dfsdm_k, 5,
		  PARENT(&ck_pll4q, &ck_pll3q, &ck_i2sckin, &ck_per, &ck_pll3r),
		  0, GATE_DFSDM, MUX_SAI1);

static STM32_KCLK(ck_fdcan_k, 4,
		  PARENT(&ck_hse, &ck_pll3q, &ck_pll4q, &ck_pll4r),
		  0, GATE_FDCAN, MUX_FDCAN);

static STM32_KCLK(ck_i2c1_k, 4,
		  PARENT(&ck_pclk1, &ck_pll4r, &ck_hsi, &ck_csi),
		  0, GATE_I2C1, MUX_I2C12);

static STM32_KCLK(ck_i2c2_k, 4,
		  PARENT(&ck_pclk1, &ck_pll4r, &ck_hsi, &ck_csi),
		  0, GATE_I2C2, MUX_I2C12);

static STM32_KCLK(ck_adfsdm_k, 5,
		  PARENT(&ck_pll4q, &ck_pll3q, &ck_i2sckin, &ck_per, &ck_pll3r),
		  0, GATE_ADFSDM, MUX_SAI1);

static STM32_KCLK(ck_lptim2_k, 5,
		  PARENT(&ck_pclk3, &ck_pll4q, &ck_per, &ck_lse, &ck_lsi),
		  0, GATE_LPTIM2, MUX_LPTIM2);

static STM32_KCLK(ck_lptim3_k, 5,
		  PARENT(&ck_pclk3, &ck_pll4q, &ck_per, &ck_lse, &ck_lsi),
		  0, GATE_LPTIM3, MUX_LPTIM3);

static STM32_KCLK(ck_lptim4_k, 6,
		  PARENT(&ck_pclk3, &ck_pll4p, &ck_pll3q, &ck_lse, &ck_lsi,
			 &ck_per),
		  0, GATE_LPTIM4, MUX_LPTIM45);

static STM32_KCLK(ck_lptim5_k, 6,
		  PARENT(&ck_pclk3, &ck_pll4p, &ck_pll3q, &ck_lse, &ck_lsi,
			 &ck_per),
		  0, GATE_LPTIM5, MUX_LPTIM45);

static STM32_KCLK(ck_i2c3_k, 4,
		  PARENT(&ck_pclk6, &ck_pll4r, &ck_hsi, &ck_csi),
		  0, GATE_I2C3, MUX_I2C3);

static STM32_KCLK(ck_i2c5_k, 4,
		  PARENT(&ck_pclk6, &ck_pll4r, &ck_hsi, &ck_csi),
		  0, GATE_I2C5, MUX_I2C5);

static STM32_KCLK(ck_dcmipp_k, 4,
		  PARENT(&ck_axi, &ck_pll2q, &ck_pll4p, &ck_per),
		  0, GATE_DCMIPP, MUX_DCMIPP);

static STM32_KCLK(ck_adc1_k, 3, PARENT(&ck_pll4r, &ck_per, &ck_pll3q),
		  0, GATE_ADC1, MUX_ADC1);

static STM32_KCLK(ck_adc2_k, 3, PARENT(&ck_pll4r, &ck_per, &ck_pll3q),
		  0, GATE_ADC2, MUX_ADC2);

static STM32_KCLK(ck_eth1ck_k, 2, PARENT(&ck_pll4p, &ck_pll3q),
		  0, GATE_ETH1CK, MUX_ETH1);

static STM32_KCLK(ck_eth2ck_k, 2, PARENT(&ck_pll4p, &ck_pll3q),
		  0, GATE_ETH2CK, MUX_ETH2);

static STM32_COMPOSITE(ck_mco1, 5,
		       PARENT(&ck_hsi, &ck_hse, &ck_csi, &ck_lsi, &ck_lse),
		       0, GATE_MCO1, DIV_MCO1, MUX_MCO1);

static STM32_COMPOSITE(ck_mco2, 6,
		       PARENT(&ck_mpu, &ck_axi, &ck_mlahb,
			      &ck_pll4p, &ck_hse, &ck_hsi),
		       0, GATE_MCO2, DIV_MCO2, MUX_MCO2);

static STM32_COMPOSITE(ck_trace, 1, PARENT(&ck_axi),
		       0, GATE_TRACECK, DIV_TRACE, NO_MUX);

enum {
	USB_PHY_48 = STM32MP1_LAST_CLK,
	PLL1P_DIV,
	CK_OFF,
	I2S_CKIN,
	STM32MP13_ALL_CLK_NB
};

static struct clk *stm32mp13_clk_provided[STM32MP13_ALL_CLK_NB] = {
	[CK_HSE]	= &ck_hse,
	[CK_CSI]	= &ck_csi,
	[CK_LSI]	= &ck_lsi,
	[CK_LSE]	= &ck_lse,
	[CK_HSI]	= &ck_hsi,
	[CK_HSE_DIV2]	= &ck_hse_div2,
	[PLL1]		= &ck_pll1_vco,
	[PLL2]		= &ck_pll2_vco,
	[PLL3]		= &ck_pll3_vco,
	[PLL4]		= &ck_pll4_vco,
	[PLL1_P]	= &ck_pll1p,
	[PLL2_P]	= &ck_pll2p,
	[PLL2_Q]	= &ck_pll2q,
	[PLL2_R]	= &ck_pll2r,
	[PLL3_P]	= &ck_pll3p,
	[PLL3_Q]	= &ck_pll3q,
	[PLL3_R]	= &ck_pll3r,
	[PLL4_P]	= &ck_pll4p,
	[PLL4_Q]	= &ck_pll4q,
	[PLL4_R]	= &ck_pll4r,
	[PLL1P_DIV]	= &ck_pll1p_div,
	[CK_MPU]	= &ck_mpu,
	[CK_AXI]	= &ck_axi,
	[CK_MLAHB]	= &ck_mlahb,
	[CK_PER]	= &ck_per,
	[PCLK1]		= &ck_pclk1,
	[PCLK2]		= &ck_pclk2,
	[PCLK3]		= &ck_pclk3,
	[PCLK4]		= &ck_pclk4,
	[PCLK5]		= &ck_pclk5,
	[PCLK6]		= &ck_pclk6,
	[CK_TIMG1]	= &ck_timg1,
	[CK_TIMG2]	= &ck_timg2,
	[CK_TIMG3]	= &ck_timg3,
	[DDRC1]		= &ck_ddrc1,
	[DDRC1LP]	= &ck_ddrc1lp,
	[DDRPHYC]	= &ck_ddrphyc,
	[DDRPHYCLP]	= &ck_ddrphyclp,
	[DDRCAPB]	= &ck_ddrcapb,
	[DDRCAPBLP]	= &ck_ddrcapblp,
	[AXIDCG]	= &ck_axidcg,
	[DDRPHYCAPB]	= &ck_ddrphycapb,
	[DDRPHYCAPBLP]	= &ck_ddrphycapblp,
	[SYSCFG]	= &ck_syscfg,
	[DDRPERFM]	= &ck_ddrperfm,
	[IWDG2]		= &ck_iwdg2,
	[USBPHY_K]	= &ck_usbphy_k,
	[USBO_K]	= &ck_usbo_k,
	[RTCAPB]	= &ck_rtcapb,
	[TZC]		= &ck_tzc,
	[TZPC]		= &ck_etzpcb,
	[IWDG1]		= &ck_iwdg1apb,
	[BSEC]		= &ck_bsec,
	[STGEN_K]	= &ck_stgen_k,
	[USART1_K]	= &ck_usart1_k,
	[USART2_K]	= &ck_usart2_k,
	[I2C4_K]	= &ck_i2c4_k,
	[TIM12_K]	= &ck_tim12_k,
	[TIM15_K]	= &ck_tim15_k,
	[RTC]		= &ck_rtc,
	[GPIOA]		= &ck_gpioa,
	[GPIOB]		= &ck_gpiob,
	[GPIOC]		= &ck_gpioc,
	[GPIOD]		= &ck_gpiod,
	[GPIOE]		= &ck_gpioe,
	[GPIOF]		= &ck_gpiof,
	[GPIOG]		= &ck_gpiog,
	[GPIOH]		= &ck_gpioh,
	[GPIOI]		= &ck_gpioi,
	[PKA]		= &ck_pka,
	[SAES_K]	= &ck_saes_k,
	[CRYP1]		= &ck_cryp1,
	[HASH1]		= &ck_hash1,
	[RNG1_K]	= &ck_rng1_k,
	[BKPSRAM]	= &ck_bkpsram,
	[SDMMC1_K]	= &ck_sdmmc1_k,
	[SDMMC2_K]	= &ck_sdmmc2_k,
	[CK_DBG]	= &ck_dbg,
	[MCE]		= &ck_mce,
	[TIM2_K]	= &ck_tim2_k,
	[TIM3_K]	= &ck_tim3_k,
	[TIM4_K]	= &ck_tim4_k,
	[TIM5_K]	= &ck_tim5_k,
	[TIM6_K]	= &ck_tim6_k,
	[TIM7_K]	= &ck_tim7_k,
	[TIM13_K]	= &ck_tim13_k,
	[TIM14_K]	= &ck_tim14_k,
	[TIM1_K]	= &ck_tim1_k,
	[TIM8_K]	= &ck_tim8_k,
	[TIM16_K]	= &ck_tim16_k,
	[TIM17_K]	= &ck_tim17_k,
	[LTDC_PX]	= &ck_ltdc_px,
	[DMA1]		= &ck_dma1,
	[DMA2]		= &ck_dma2,
	[ADC1]		= &ck_adc1,
	[ADC2]		= &ck_adc2,
	[MDMA]		= &ck_mdma,
	[ETH1MAC]	= &ck_eth1mac,
	[USBH]		= &ck_usbh,
	[VREF]		= &ck_vref,
	[TMPSENS]	= &ck_tmpsens,
	[PMBCTRL]	= &ck_pmbctrl,
	[HDP]		= &ck_hdp,
	[STGENRO]	= &ck_stgenro,
	[DMAMUX1]	= &ck_dmamux1,
	[DMAMUX2]	= &ck_dmamux2,
	[DMA3]		= &ck_dma3,
	[TSC]		= &ck_tsc,
	[AXIMC]		= &ck_aximc,
	[CRC1]		= &ck_crc1,
	[ETH1TX]	= &ck_eth1tx,
	[ETH1RX]	= &ck_eth1rx,
	[ETH2TX]	= &ck_eth2tx,
	[ETH2RX]	= &ck_eth2rx,
	[ETH2MAC]	= &ck_eth2mac,
	[USART3_K]	= &ck_usart3_k,
	[UART4_K]	= &ck_uart4_k,
	[UART5_K]	= &ck_uart5_k,
	[UART7_K]	= &ck_uart7_k,
	[UART8_K]	= &ck_uart8_k,
	[USART6_K]	= &ck_usart6_k,
	[FMC_K]		= &ck_fmc_k,
	[QSPI_K]	= &ck_qspi_k,
	[LPTIM1_K]	= &ck_lptim1_k,
	[SPI2_K]	= &ck_spi2_k,
	[SPI3_K]	= &ck_spi3_k,
	[SPDIF_K]	= &ck_spdif_k,
	[SPI1_K]	= &ck_spi1_k,
	[SPI4_K]	= &ck_spi4_k,
	[SPI5_K]	= &ck_spi5_k,
	[SAI1_K]	= &ck_sai1_k,
	[SAI2_K]	= &ck_sai2_k,
	[DFSDM_K]	= &ck_dfsdm_k,
	[FDCAN_K]	= &ck_fdcan_k,
	[I2C1_K]	= &ck_i2c1_k,
	[I2C2_K]	= &ck_i2c2_k,
	[ADFSDM_K]	= &ck_adfsdm_k,
	[LPTIM2_K]	= &ck_lptim2_k,
	[LPTIM3_K]	= &ck_lptim3_k,
	[LPTIM4_K]	= &ck_lptim4_k,
	[LPTIM5_K]	= &ck_lptim5_k,
	[I2C3_K]	= &ck_i2c3_k,
	[I2C5_K]	= &ck_i2c5_k,
	[DCMIPP_K]	= &ck_dcmipp_k,
	[ADC1_K]	= &ck_adc1_k,
	[ADC2_K]	= &ck_adc2_k,
	[ETH1CK_K]	= &ck_eth1ck_k,
	[ETH2CK_K]	= &ck_eth2ck_k,
	[SPI1]		= &ck_spi1,
	[SPI2]		= &ck_spi2,
	[SPI3]		= &ck_spi3,
	[SPI4]		= &ck_spi4,
	[SPI5]		= &ck_spi5,
	[CK_MCO1]	= &ck_mco1,
	[CK_MCO2]	= &ck_mco2,
	[CK_TRACE]	= &ck_trace,
	[CK_OFF]	= &ck_off,
	[USB_PHY_48]	= &ck_usb_phy_48Mhz,
	[I2S_CKIN]	= &ck_i2sckin,
};

static bool clk_stm32_clock_is_critical(struct clk *clk __maybe_unused)
{
	struct clk *clk_criticals[] = {
		&ck_hsi,
		&ck_hse,
		&ck_csi,
		&ck_lsi,
		&ck_lse,
		&ck_pll2r,
		&ck_mpu,
		&ck_ddrc1,
		&ck_ddrc1lp,
		&ck_ddrphyc,
		&ck_ddrphyclp,
		&ck_ddrcapb,
		&ck_ddrcapblp,
		&ck_axidcg,
		&ck_ddrphycapb,
		&ck_ddrphycapblp,
		&ck_rtcapb,
		&ck_tzc,
		&ck_etzpcb,
		&ck_iwdg1apb,
		&ck_bsec,
		&ck_stgen_k,
		&ck_bkpsram,
		&ck_mce,
		&ck_mco1,
		&ck_rng1_k,
		&ck_mlahb,
	};
	size_t i = 0;

	for (i = 0; i < ARRAY_SIZE(clk_criticals); i++) {
		struct clk *clk_critical = clk_criticals[i];

		if (clk == clk_critical)
			return true;
	}

	return false;
}

static void clk_stm32_init_oscillators(const void *fdt, int node)
{
	size_t i = 0;
	const char *name[6] = { "clk-hse", "clk-hsi", "clk-lse",
				"clk-lsi", "clk-csi", "clk-i2sin" };
	struct clk *clks[6] = { &ck_hse, &ck_hsi, &ck_lse,
				&ck_lsi, &ck_csi, &ck_i2sckin };

	for (i = 0; i < ARRAY_SIZE(clks); i++) {
		struct clk *clk = NULL;

		clk_dt_get_by_name(fdt, node, name[i], &clk);

		clks[i]->parents[0] = clk;
	}
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
	.nb_clk_refs		= STM32MP13_ALL_CLK_NB,
	.clk_refs		= stm32mp13_clk_provided,
	.is_critical		= clk_stm32_clock_is_critical,
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

	clk_stm32_init_oscillators(fdt, node);

	stm32mp_clk_provider_probe_final(fdt, node, priv);

	return TEE_SUCCESS;
}

CLK_DT_DECLARE(stm32mp13_clk, "st,stm32mp13-rcc", stm32mp13_clk_probe);
