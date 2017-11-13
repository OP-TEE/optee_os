/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2015 Freescale Semiconductor, Inc.
 * All rights reserved.
 * Copyright (c) 2016, Wind River Systems.
 * All rights reserved.
 * Copyright 2017-2018 NXP
 *
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
