/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2017, Fuzhou Rockchip Electronics Co., Ltd.
 */

#ifndef PLAT_ROCKCHIP_CRU_H
#define PLAT_ROCKCHIP_CRU_H

#include <common.h>
#include <platform_config.h>

#if defined(PLATFORM_FLAVOR_rk322x)

enum plls_id {
	APLL_ID,
	DPLL_ID,
	CPLL_ID,
	GPLL_ID,
	PLL_END,
};

#define CRU_SOFTRST_CON(i) (0x110 + ((i)*4))
#define CRU_MODE_CON 0x040
#define CRU_GLBRST_CFG_BASE 0x140
#define CRU_FSTRST_VAL_BASE 0x1f0
#define CRU_SNDRST_VAL_BASE 0x1f4
#define CRU_FSTRST_VAL 0xfdb9
#define CRU_SNDRST_VAL 0xeca8
#define PLLS_SLOW_MODE 0x11030000

#define CORE_SOFT_RESET(core) SHIFT_U32(0x100010, (core))
#define CORE_SOFT_RELEASE(core) SHIFT_U32(0x100000, (core))
#define CORE_HELD_IN_RESET(core) SHIFT_U32(0x000010, (core))
#define NONBOOT_CORES_SOFT_RESET 0x00e000e0

#define CRU_CLKGATE_CON_CNT 16
#define CRU_CLKSEL_CON(i) (0x044 + ((i)*4))
#define CRU_CLKGATE_CON(i) (0x0d0 + ((i)*4))
#define CRU_PLL_CON0(pll) ((pll)*0x0c + 0x0)
#define CRU_PLL_CON1(pll) ((pll)*0x0c + 0x4)
#define CRU_PLL_CON2(pll) ((pll)*0x0c + 0x8)

#define PLL_LOCK BIT(10)
#define PLL_POWER_UP BITS_WITH_WMASK(0, 1, 13)
#define PLL_POWER_DOWN BITS_WITH_WMASK(1, 1, 13)

#define PLL_MODE_BIT(pll) ((pll)*4)
#define PLL_MODE_MSK(pll) BIT(PLL_MODE_BIT(pll))
#define PLL_SLOW_MODE(pll) BITS_WITH_WMASK(0, 1, PLL_MODE_BIT(pll))
#define PLL_NORM_MODE(pll) BITS_WITH_WMASK(1, 1, PLL_MODE_BIT(pll))

#elif defined(PLATFORM_FLAVOR_rk3568)

#define CRU_GATE_CON(n) (0x0300u + (n * 4))

#define CRU_S_CON(n) (0x180 + (n * 4))

/* CRU controller register */
#define CLK_NS_OTP_USER_EN BIT(11)
#define CLK_NS_OTP_SBPI_EN BIT(10)
#define PCLK_NS_OTP_EN BIT(9)
#define PCLK_PHY_OTP_EN BIT(13)

#define OTP_PHY_SRSTN 15
#define OTP_PHY_SRSTN_SET BIT_WITH_WMSK(15)
#define OTP_PHY_SRSTN_CLR WMSK_BIT(15)

/* SCRU controller register */
#define CLK_S_OTP_USER_EN BIT(7)
#define CLK_S_OTP_SBPI_EN BIT(6)
#define PCLK_S_OTP_EN BIT(5)

#endif

#endif
