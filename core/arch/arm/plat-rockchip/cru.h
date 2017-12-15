/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2017, Fuzhou Rockchip Electronics Co., Ltd.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
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

#define CRU_SOFTRST_CON(i)		(0x110 + ((i) * 4))
#define CRU_MODE_CON			0x040
#define CRU_GLBRST_CFG_BASE		0x140
#define CRU_FSTRST_VAL_BASE		0x1f0
#define CRU_SNDRST_VAL_BASE		0x1f4
#define CRU_FSTRST_VAL			0xfdb9
#define CRU_SNDRST_VAL			0xeca8
#define PLLS_SLOW_MODE			0x11030000

#define CORE_SOFT_RESET(core)		SHIFT_U32(0x100010, (core))
#define CORE_SOFT_RELEASE(core)		SHIFT_U32(0x100000, (core))
#define CORE_HELD_IN_RESET(core)	SHIFT_U32(0x000010, (core))
#define NONBOOT_CORES_SOFT_RESET	0x00e000e0

#define CRU_CLKGATE_CON_CNT		16
#define CRU_CLKSEL_CON(i)		(0x044 + ((i) * 4))
#define CRU_CLKGATE_CON(i)		(0x0d0 + ((i) * 4))
#define CRU_PLL_CON0(pll)		((pll) * 0x0c + 0x0)
#define CRU_PLL_CON1(pll)		((pll) * 0x0c + 0x4)
#define CRU_PLL_CON2(pll)		((pll) * 0x0c + 0x8)

#define PLL_LOCK			BIT(10)
#define PLL_POWER_UP			BITS_WITH_WMASK(0, 1, 13)
#define PLL_POWER_DOWN			BITS_WITH_WMASK(1, 1, 13)

#define PLL_MODE_BIT(pll)		((pll) * 4)
#define PLL_MODE_MSK(pll)		BIT(PLL_MODE_BIT(pll))
#define PLL_SLOW_MODE(pll)		BITS_WITH_WMASK(0, 1, PLL_MODE_BIT(pll))
#define PLL_NORM_MODE(pll)		BITS_WITH_WMASK(1, 1, PLL_MODE_BIT(pll))
#endif

#endif
