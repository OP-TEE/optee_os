/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2017-2019 NXP
 */

#ifndef __IMX7_CRM_H__
#define __IMX7_CRM_H__

/*
 * GPRx Registers
 */
#define CCM_GPR0			0x0
#define CCM_GPRx_OFFSET			0x10
#define CCM_GPRx(idx)			(((idx) * CCM_GRPx_OFFSET) + CCM_GPR0)
#define CCM_GPRx_SET(idx)		(CCM_GPRx(idx) + 0x4)
#define CCM_GPRx_CLR(idx)		(CCM_GPRx(idx) + 0x8)
#define CCM_GPRx_TOG(idx)		(CCM_GPRx(idx) + 0xC)

/*
 * PLL_CTRLx Registers (PLL Control)
 */
#define CCM_PLL_CTRL0		0x800
#define CCM_PLL_CTRLx_OFFSET	0x10
#define CCM_PLL_CTRLx(idx)	(((idx) * CCM_PLL_CTRLx_OFFSET) + CCM_PLL_CTRL0)
#define CCM_PLL_CTRLx_SET(idx)	(CCM_PLL_CTRLx(idx) + 0x4)
#define CCM_PLL_CTRLx_CLR(idx)	(CCM_PLL_CTRLx(idx) + 0x8)
#define CCM_PLL_CTRLx_TOG(idx)	(CCM_PLL_CTRLx(idx) + 0xC)

/*
 * CCGRx Registers (Clock Gating)
 */
#define CCM_CCGR0		0x4000
#define CCM_CCGRx_OFFSET	0x10
#define CCM_CCGRx(idx)		(((idx) * CCM_CCGRx_OFFSET) + CCM_CCGR0)
#define CCM_CCGRx_SET(idx)	(CCM_CCGRx(idx) + 0x4)
#define CCM_CCGRx_CLR(idx)	(CCM_CCGRx(idx) + 0x8)
#define CCM_CCGRx_TOG(idx)	(CCM_CCGRx(idx) + 0xC)

#define BS_CCM_CCGRx_SETTING(idx)	((idx) * 4)
#define BM_CCM_CCGRx_SETTING(idx)	\
			SHIFT_U32(0x3, BS_CCM_CCGRx_SETTING(idx))
#define CCM_CCGRx_DISABLE(idx)		\
			SHIFT_U32(0, BS_CCM_CCGRx_SETTING(idx))
#define CCM_CCGRx_RUN(idx)		\
			BIT32(BS_CCM_CCGRx_SETTING(idx))
#define CCM_CCGRx_RUN_WAIT(idx)		\
			SHIFT_U32(0x2, BS_CCM_CCGRx_SETTING(idx))
#define CCM_CCGRx_ALWAYS_ON(idx)	\
			SHIFT_U32(0x3, BS_CCM_CCGRx_SETTING(idx))

/*
 * TARGET_ROOTx Registers (Target)
 */
#define CCM_TARGET_ROOT0		0x8000
#define CCM_TARGET_ROOTx_OFFSET		0x80
#define CCM_TARGET_ROOTx(idx)		\
		(((idx) * CCM_TARGET_ROOTx_OFFSET) + CCM_TARGET_ROOT0)
#define CCM_TARGET_ROOTx_SET(idx)	(CCM_TARGET_ROOTx(idx) + 0x4)
#define CCM_TARGET_ROOTx_CLR(idx)	(CCM_TARGET_ROOTx(idx) + 0x8)
#define CCM_TARGET_ROOTx_TOG(idx)	(CCM_TARGET_ROOTx(idx) + 0xC)

/*
 * MISC_ROOTx Registers (Miscellaneous)
 */
#define CCM_MISC_ROOT0			0x8010
#define CCM_MISC_ROOTx_OFFSET		0x80
#define CCM_MISC_ROOTx(idx)		\
		(((idx) * CCM_MISC_ROOTx_OFFSET) + CCM_MISC_ROOT0)
#define CCM_MISC_ROOTx_SET(idx)		(CCM_MISC_ROOTx(idx) + 0x4)
#define CCM_MISC_ROOTx_CLR(idx)		(CCM_MISC_ROOTx(idx) + 0x8)
#define CCM_MISC_ROOTx_TOG(idx)		(CCM_MISC_ROOTx(idx) + 0xC)

/*
 * POST_ROOTx Registers (Post Divider)
 */
#define CCM_POST_ROOT0			0x8020
#define CCM_POST_ROOTx_OFFSET		0x80
#define CCM_POST_ROOTx(idx)		\
		(((idx) * CCM_POST_ROOTx_OFFSET) + CCM_POST_ROOT0)
#define CCM_POST_ROOTx_SET(idx)		(CCM_POST_ROOTx(idx) + 0x4)
#define CCM_POST_ROOTx_CLR(idx)		(CCM_POST_ROOTx(idx) + 0x8)
#define CCM_POST_ROOTx_TOG(idx)		(CCM_POST_ROOTx(idx) + 0xC)

/*
 * PRE_ROOTx Registers (Pre Divider)
 */
#define CCM_PRE_ROOT0			0x8030
#define CCM_PRE_ROOTx_OFFSET		0x80
#define CCM_PRE_ROOTx(idx)		\
		(((idx) * CCM_PRE_ROOTx_OFFSET) + CCM_PRE_ROOT0)
#define CCM_PRE_ROOTx_SET(idx)		(CCM_PRE_ROOTx(idx) + 0x4)
#define CCM_PRE_ROOTx_CLR(idx)		(CCM_PRE_ROOTx(idx) + 0x8)
#define CCM_PRE_ROOTx_TOG(idx)		(CCM_PRE_ROOTx(idx) + 0xC)

/*
 * ACCESS_CTRL_ROOTx Registers (Access Control)
 */
#define CCM_ACCESS_CTRL_ROOT0		0x8030
#define CCM_ACCESS_CTRL_ROOTx_OFFSET	0x80
#define CCM_ACCESS_CTRL_ROOTx(idx)	\
		(((idx) * CCM_ACCESS_CTRL_ROOTx_OFFSET) + CCM_ACCESS_CTRL_ROOT0)
#define CCM_ACCESS_CTRL_ROOTx_SET(idx)	(CCM_ACCESS_CTRL_ROOTx(idx) + 0x4)
#define CCM_ACCESS_CTRL_ROOTx_CLR(idx)	(CCM_ACCESS_CTRL_ROOTx(idx) + 0x8)
#define CCM_ACCESS_CTRL_ROOTx_TOG(idx)	(CCM_ACCESS_CTRL_ROOTx(idx) + 0xC)

/*
 * Clock Domain ID
 */
#define CCM_CLOCK_DOMAIN_OCOTP		35
#define CCM_CLOCK_DOMAIN_CAAM		36

#endif /* __IMX7_CRM_H__ */
