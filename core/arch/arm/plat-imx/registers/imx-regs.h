/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2015 Freescale Semiconductor, Inc.
 * All rights reserved.
 * Copyright (c) 2016, Wind River Systems.
 * All rights reserved.
 * Copyright 2017-2018 NXP
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
#include <registers/imx6-regs.h>
#elif defined(CFG_MX7)
#include <registers/imx7-regs.h>
#else
#error "PLATFORM not defined"
#endif

/* Register offset used to get the CPU Type and Revision */
#define HW_ANADIG_DIGPROG			(0x260)
#define HW_ANADIG_DIGPROG_IMX6SL	(0x280)
#define HW_ANADIG_DIGPROG_IMX7D		(0x800)

#define SNVS_LPCR_OFF			0x38
#define SNVS_LPCR_TOP_MASK		BIT(6)
#define SNVS_LPCR_DP_EN_MASK		BIT(5)
#define SNVS_LPCR_SRTC_ENV_MASK		1


#define IOMUXC_GPR4_OFFSET	0x10
#define IOMUXC_GPR5_OFFSET	0x14
#define ARM_WFI_STAT_MASK(n)	BIT(n)

#define ARM_WFI_STAT_MASK_7D(n)	BIT(25 + ((n) & 1))

#endif
