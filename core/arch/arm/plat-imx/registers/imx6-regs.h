/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2017-2018 NXP
 *
 */
#ifndef __IMX6_REGS_H__
#define __IMX6_REGS_H__
#include <registers/imx6-src_regs.h>
#include <registers/imx6-mmdc_regs.h>

#define UART1_BASE		0x02020000
#define SRC_BASE		0x020D8000
#define ANATOP_BASE		0x020C8000
#define SNVS_BASE		0x020CC000
#define UART2_BASE		0x021E8000
#define MMDC_P0_BASE		0x021B0000
#define SCU_BASE		0x00A00000
#define PL310_BASE		0x00A02000
#define GIC_BASE		0x00A00000
#define GICD_OFFSET		0x1000

#if defined(CFG_MX6UL) || defined(CFG_MX6ULL)
#define GICC_OFFSET		0x2000
#else
#define GICC_OFFSET		0x100
#endif

/* Central Security Unit register values */
#define CSU_BASE		0x021C0000
#define CSU_CSL_START		0x0
#define CSU_CSL_END		0xA0
#define CSU_ACCESS_ALL		0x00FF00FF
#define CSU_SETTING_LOCK	0x01000100

#if defined(CFG_MX6UL) || defined(CFG_MX6ULL) || defined(CFG_MX6SX)
#define DRAM0_BASE			0x80000000
#else
#define DRAM0_BASE			0x10000000
#endif

#endif /* __IMX6_REGS_H__ */
