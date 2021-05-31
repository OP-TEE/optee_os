/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2015 Freescale Semiconductor, Inc.
 * Copyright (c) 2016, Wind River Systems.
 * All rights reserved.
 * Copyright 2019 NXP
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
#ifndef PLAT_IMX_IMX_REGS_H
#define PLAT_IMX_IMX_REGS_H

#ifdef CFG_MX6
#include <registers/imx6.h>
#elif defined(CFG_MX7)
#include <registers/imx7.h>
#elif defined(CFG_MX7ULP)
#include <registers/imx7ulp.h>
#elif defined(CFG_MX8MQ) || defined(CFG_MX8MM) || defined(CFG_MX8MN) || \
	defined(CFG_MX8MP)
#include <registers/imx8m.h>
#elif defined(CFG_MX8QX) || defined(CFG_MX8QM) || defined(CFG_MX8DXL)
#include <registers/imx8q.h>
#elif defined(CFG_MX8ULP)
#include <registers/imx8ulp.h>
#else
#error "CFG_MX6/7/7ULP or CFG_MX8MQ/8MM/8MN/8MP/8QX/8QM/8DXL/8ULP not defined"
#endif

#define IOMUXC_GPR4_OFFSET	0x10
#define IOMUXC_GPR5_OFFSET	0x14
#define ARM_WFI_STAT_MASK(n)	BIT(n)

#define ARM_WFI_STAT_MASK_7D(n)	BIT(25 + ((n) & 1))

#define SRC_SCR				0x000
#define SRC_GPR1			0x020
#define SRC_GPR2			0x024
#define SRC_SCR_CORE1_RST_OFFSET	14
#define SRC_SCR_CORE1_ENABLE_OFFSET	22
#define SRC_SCR_CPU_ENABLE_ALL		SHIFT_U32(0x7, 22)

#define SRC_GPR1_MX7			0x074
#define SRC_A7RCR0			0x004
#define SRC_A7RCR1			0x008
#define SRC_A7RCR0_A7_CORE_RESET0_OFFSET	0
#define SRC_A7RCR1_A7_CORE1_ENABLE_OFFSET	1

#define SNVS_LPCR_OFF			0x38
#define SNVS_LPCR_TOP_MASK		BIT(6)
#define SNVS_LPCR_DP_EN_MASK		BIT(5)
#define SNVS_LPCR_SRTC_ENV_MASK		1

#define WCR_OFF				0

/* GPC V2 */
#define GPC_PGC_C1			0x840
#define GPC_PGC_C1_PUPSCR		0x844

#define GPC_PGC_PCG_MASK		BIT(0)

#define GPC_CPU_PGC_SW_PUP_REQ		0xf0
#define GPC_PU_PGC_SW_PUP_REQ		0xf8
#define GPC_CPU_PGC_SW_PDN_REQ		0xfc
#define GPC_PU_PGC_SW_PDN_REQ		0x104
#define GPC_PGC_SW_PDN_PUP_REQ_CORE1_MASK BIT(1)
#endif
