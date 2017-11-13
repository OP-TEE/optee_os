/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2017-2018 NXP
 *
 */

#ifndef __MX7_IOMUX_REGS_H__
#define __MX7_IOMUX_REGS_H__

/*
 * Macros definition
 */
#define IOMUX_GPRx_OFFSET(idx)	(idx * 4)

/*
 * DDR PHY control PD pins
 * TrustZone Address Space Controller Select
 */
#define IOMUX_GPR_TZASC_ID		(9)
#define BP_IOMUX_GPR_DDR_PHY_CTRL_PD	(1)
#define BM_IOMUX_GPR_DDR_PHY_CTRL_PD	(0x1F << BP_IOMUX_GPR_DDR_PHY_CTRL_PD)
#define BP_IOMUX_GPR_TZASC1_MUX_CTRL	(0)
#define BM_IOMUX_GPR_TZASC1_MUX_CTRL	(0x1 << BP_IOMUX_GPR_TZASC1_MUX_CTRL)

/*
 * OCRAM Configuration
 */
#define IOMUX_GPR_OCRAM_ID		(11)

/* State Retention configuration */
#define BP_IOMUX_GPR_OCRAM_S_TZ_ADDR	(11)
#define BM_IOMUX_GPR_OCRAM_S_TZ_ADDR	(0x7 << BP_IOMUX_GPR_OCRAM_S_TZ_ADDR)
#define BP_IOMUX_GPR_OCRAM_S_TZ_EN	(10)
#define BM_IOMUX_GPR_OCRAM_S_TZ_EN	(0x1 << BP_IOMUX_GPR_OCRAM_S_TZ_EN)
#define IOMUX_GPR_OCRAM_S_TZ_ENABLE	(1 << BP_IOMUX_GPR_OCRAM_S_TZ_EN)
#define IOMUX_GPR_OCRAM_S_TZ_DISABLE	(0 << BP_IOMUX_GPR_OCRAM_S_TZ_EN)

/* PXP configuration */
#define BP_IOMUX_GPR_OCRAM_PXP_TZ_ADDR	(7)
#define BM_IOMUX_GPR_OCRAM_PXP_TZ_ADDR	(0x7 << BP_IOMUX_GPR_OCRAM_PXP_TZ_ADDR)
#define BP_IOMUX_GPR_OCRAM_PXP_TZ_EN	(6)
#define BM_IOMUX_GPR_OCRAM_PXP_TZ_EN	(0x1 << BP_IOMUX_GPR_OCRAM_PXP_TZ_EN)
#define IOMUX_GPR_OCRAM_PXP_TZ_ENABLE	(1 << BP_IOMUX_GPR_OCRAM_PXP_TZ_EN)
#define IOMUX_GPR_OCRAM_PXP_TZ_DISABLE	(0 << BP_IOMUX_GPR_OCRAM_PXP_TZ_EN)

/* Running configuration */
#define BP_IOMUX_GPR_OCRAM_TZ_ADDR	(1)
#define BM_IOMUX_GPR_OCRAM_TZ_ADDR	(0x1F << BP_IOMUX_GPR_OCRAM_TZ_ADDR)
#define BP_IOMUX_GPR_OCRAM_TZ_EN	(0)
#define BM_IOMUX_GPR_OCRAM_TZ_EN	(0x1 << BP_IOMUX_GPR_OCRAM_TZ_EN)
#define IOMUX_GPR_OCRAM_TZ_ENABLE	(1 << BP_IOMUX_GPR_OCRAM_TZ_EN)
#define IOMUX_GPR_OCRAM_TZ_DISABLE	(0 << BP_IOMUX_GPR_OCRAM_TZ_EN)

/* The configuration is locked with register bits 16 to 29 as mirror
 * of bits 0 to 13
 */
#define BP_IOMUX_GPR_OCRAM_LOCK		(16)
#define IOMUX_GPR_OCRAM_LOCK(value)	(value << BP_IOMUX_GPR_OCRAM_LOCK)

#endif /* __MX7_IOMUX_REGS_H__ */
