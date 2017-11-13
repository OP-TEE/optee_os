/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2017-2018 NXP
 *
 */

#ifndef __IMX6_REGS_H__
#define __IMX6_REGS_H__
#include <imx6-crm_regs.h>
#include <imx6-gpc_regs.h>
#include <imx6-src_regs.h>
#include <imx6-iomux_regs.h>
#include <imx6-mmdc_regs.h>

#define UART1_BASE		0x2020000
#define IOMUXC_BASE		0x020E0000
#define IOMUXC_SIZE		0x4000
#define IOMUXC_GPR_BASE		0x020E4000
#define SRC_BASE		0x020D8000
#define SRC_SIZE		0x4000
#define CCM_BASE		0x020C4000
#define CCM_SIZE		0x4000
#define ANATOP_BASE		0x020C8000
#define ANATOP_SIZE		0x1000
#define SNVS_BASE		0x020CC000
#define GPC_BASE		0x020DC000
#define GPC_SIZE		0x4000
#define WDOG_BASE		0x020BC000
#define SEMA4_BASE		0x02290000
#define SEMA4_SIZE		0x4000
#define MMDC_P0_BASE		0x021B0000
#define MMDC_P0_SIZE		0x4000
#define MMDC_P1_BASE		0x021B4000
#define MMDC_P1_SIZE		0x4000
#define TZASC_BASE		0x21D0000
#define TZASC2_BASE		0x21D4000
#define UART2_BASE		0x021E8000
#define UART3_BASE		0x021EC000
#define UART4_BASE		0x021F0000
#define UART5_BASE		0x021F4000
#define AIPS1_BASE		0x02000000
#define AIPS1_SIZE		0x100000
#define AIPS2_BASE		0x02100000
#define AIPS2_SIZE		0x100000
#define AIPS3_BASE		0x02200000
#define AIPS3_SIZE		0x100000

#define SCU_BASE		0x00A00000
#define PL310_BASE		0x00A02000
#define IRAM_BASE		0x00900000

/* on i.MX6SX 16KB */
#define IRAM_6SX_S_BASE		0x008f8000
#define IRAM_6SX_S_SIZE		(16 * 1024)

#define OCOTP_BASE		0x021BC000

#define GIC_BASE		0x00A00000
#define GICD_OFFSET		0x1000

#if defined(CFG_MX6UL) || defined(CFG_MX6ULL)
#define GICC_OFFSET		0x2000
/* No CAAM on i.MX6ULL */
#define CAAM_BASE		0x02140000
#else
#define GICC_OFFSET		0x100
#define CAAM_BASE		0x02100000
#endif

#define GIC_CPU_BASE		(GIC_BASE + GICC_OFFSET)
#define GIC_DIST_BASE		(GIC_BASE + GICD_OFFSET)

#if defined(CFG_MX6UL) || defined(CFG_MX6ULL)
/* 128K OCRAM */
#define TRUSTZONE_OCRAM_START		0x918000
#elif defined(CFG_MX6DL)
#define TRUSTZONE_OCRAM_START		0x918000
#elif defined(CFG_MX6QP)
#define TRUSTZONE_OCRAM_START		0x938000
#elif defined(CFG_MX6SX)
#define TRUSTZONE_OCRAM_START		0x8f8000
#elif defined(CFG_MX6SL)
#define TRUSTZONE_OCRAM_START		0x918000
#elif defined(CFG_MX6SLL)
#define TRUSTZONE_OCRAM_START		0x918000
#else
/* 256K OCRAM */
#define TRUSTZONE_OCRAM_START		0x938000
#endif

/* Central Security Unit register values */
#define CSU_BASE			0x021C0000
#define CSU_CSL_START		0x0
#define CSU_CSL_END			0xA0
#define	CSU_ACCESS_ALL		0x00FF00FF
#define CSU_SETTING_LOCK	0x01000100

/* Used in suspend/resume and low power idle */
#define MX6Q_SRC_GPR1			0x20
#define MX6Q_SRC_GPR2			0x24
#define MX6Q_MMDC_MISC			0x18
#define MX6Q_MMDC_MAPSR			0x404
#define MX6Q_MMDC_MPDGCTRL0		0x83c
#define MX6Q_GPC_IMR1			0x08
#define MX6Q_GPC_IMR2			0x0c
#define MX6Q_GPC_IMR3			0x10
#define MX6Q_GPC_IMR4			0x14
#define MX6Q_CCM_CCR			0x0
#define MX6Q_ANATOP_CORE		0x140

#if defined(CFG_MX6UL) || defined(CFG_MX6ULL) || defined(CFG_MX6SX) || \
	defined(CFG_MX6SL) || defined(CFG_MX6SLL)
#define DRAM0_BASE			0x80000000
#else
#define DRAM0_BASE			0x10000000
#endif

#endif /* __IMX6_REGS_H__ */
