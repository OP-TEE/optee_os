/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2017-2018 NXP
 *
 */

#ifndef __IMX7_SRC_REGS_H__
#define __IMX7_SRC_REGS_H__

#define SRC_REGISTER_OFFSET_MASK	0xFFFF

#define SRC_SCR				0x0000
#define SRC_A7RCR0			0x0004
#define SRC_A7RCR1			0x0008
#define SRC_M4RCR			0x000C
#define SRC_ERCR			0x0014
#define SRC_HSICPHY_RCR			0x001C
#define SRC_USBOPHY1_RCR		0x0020
#define SRC_USBOPHY2_RCR		0x0024
#define SRC_MIPIPHY_RCR			0x0028
#define SRC_PCIEPHY_RCR			0x002C
#define SRC_SBMR1			0x0058
#define SRC_SRSR			0x005C
#define SRC_SISR			0x0064
#define SRC_SIMR			0x0068
#define SRC_SBMR2			0x006C
#define SRC_GPR1			0x0074
#define SRC_GPR2			0x0078
#define SRC_GPR3			0x007C
#define SRC_GPR4			0x0080
#define SRC_GPR5			0x0084
#define SRC_GPR6			0x0088
#define SRC_GPR7			0x008C
#define SRC_GPR8			0x0090
#define SRC_GPR9			0x0094
#define SRC_GPR10			0x0098
#define SRC_DDRC_RCR			0x1000


#define BP_SRC_A7RCR1_A7_CORE1_ENABLE		(1)
#define BP_SRC_M4RCR_SW_M4C_NON_SCLR_RST	(0)
#define BM_SRC_M4RCR_SW_M4C_NON_SCLR_RST	\
		(1 << BP_SRC_M4RCR_SW_M4C_NON_SCLR_RST)
#define BP_SRC_M4RCR_ENABLE_M4			(3)
#define BM_SRC_M4RCR_ENABLE_M4			(1 << BP_SRC_M4RCR_ENABLE_M4)

#endif /*  __IMX7_SRC_REGS_H__ */
