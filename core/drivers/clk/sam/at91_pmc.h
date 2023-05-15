/* SPDX-License-Identifier: GPL-2.0+ or BSD-3-Clause */
/*
 * Copyright (C) 2005 Ivan Kokshaysky
 * Copyright (C) SAN People
 *
 * Power Management Controller (PMC) - System peripherals registers.
 * Based on AT91RM9200 datasheet revision E.
 */

#ifndef DRIVERS_CLK_SAM_AT91_PM_H
#define DRIVERS_CLK_SAM_AT91_PM_H

#include <util.h>

#define AT91_PMC_V1				(1)
#define AT91_PMC_V2				(2)

#define	AT91_PMC_SCER				0x00
#define	AT91_PMC_SCDR				0x04

#define	AT91_PMC_SCSR				0x08
#define	  AT91_PMC_PCK				BIT(0)
#define	  AT91RM9200_PMC_UDP			BIT(1)
#define	  AT91RM9200_PMC_MCKUDP			BIT(2)
#define	  AT91RM9200_PMC_UHP			BIT(4)
#define	  AT91SAM926x_PMC_UHP			BIT(6)
#define	  AT91SAM926x_PMC_UDP			BIT(7)
#define	  AT91_PMC_PCK0				BIT(8)
#define	  AT91_PMC_PCK1				BIT(9)
#define	  AT91_PMC_PCK2				BIT(10)
#define	  AT91_PMC_PCK3				BIT(11)
#define	  AT91_PMC_PCK4				BIT(12)
#define	  AT91_PMC_HCK0				BIT(16)
#define	  AT91_PMC_HCK1				BIT(17)

#define AT91_PMC_PLL_CTRL0			0x0C
#define	  AT91_PMC_PLL_CTRL0_ENPLL		BIT(28)
#define	  AT91_PMC_PLL_CTRL0_ENPLLCK		BIT(29)
#define	  AT91_PMC_PLL_CTRL0_ENLOCK		BIT(31)

#define AT91_PMC_PLL_CTRL1			0x10

#define	AT91_PMC_PCER				0x10
#define	AT91_PMC_PCDR				0x14
#define	AT91_PMC_PCSR				0x18

#define AT91_PMC_PLL_ACR			0x18
#define	  AT91_PMC_PLL_ACR_DEFAULT_UPLL		0x12020010UL
#define	  AT91_PMC_PLL_ACR_DEFAULT_PLLA		0x00020010UL
#define	  AT91_PMC_PLL_ACR_UTMIVR		BIT(12)
#define	  AT91_PMC_PLL_ACR_UTMIBG		BIT(13)

#define	AT91_CKGR_UCKR				0x1C
#define	  AT91_PMC_UPLLEN			BIT(16)
#define	  AT91_PMC_UPLLCOUNT			(0xf << 20)
#define	  AT91_PMC_BIASEN			BIT(24)
#define	  AT91_PMC_BIASCOUNT			(0xf << 28)

#define AT91_PMC_PLL_UPDT			0x1C
#define	  AT91_PMC_PLL_UPDT_UPDATE		BIT(8)
#define	  AT91_PMC_PLL_UPDT_ID			BIT(0)
#define	  AT91_PMC_PLL_UPDT_ID_MSK		(0xf)
#define	  AT91_PMC_PLL_UPDT_STUPTIM		(0xff << 16)

#define	AT91_CKGR_MOR				0x20
#define	  AT91_PMC_MOSCEN			BIT(0)
#define	  AT91_PMC_OSCBYPASS			BIT(1)
#define	  AT91_PMC_WAITMODE			BIT(2)
#define	  AT91_PMC_MOSCRCEN			BIT(3)
#define	  AT91_PMC_OSCOUNT			(0xff << 8)
#define	  AT91_PMC_KEY_MASK			(0xff << 16)
#define	  AT91_PMC_KEY				(0x37 << 16)
#define	  AT91_PMC_MOSCSEL			BIT(24)
#define	  AT91_PMC_CFDEN			BIT(25)

#define	AT91_CKGR_MCFR				0x24
#define	  AT91_PMC_MAINF			(0xffff << 0)
#define	  AT91_PMC_MAINRDY			BIT(16)

#define	AT91_CKGR_PLLAR				0x28
#define	AT91_CKGR_PLLBR				0x2c
#define	  AT91_PMC_DIV				(0xff << 0)
#define	  AT91_PMC_PLLCOUNT			(0x3f << 8)
#define	  AT91_PMC_OUT				(3 << 14)
#define	  AT91_PMC_MUL				(0x7ff << 16)
#define	  AT91_PMC_MUL_GET(n)			((n) >> 16 & 0x7ff)
#define	  AT91_PMC3_MUL				(0x7f << 18)
#define	  AT91_PMC3_MUL_GET(n)			((n) >> 18 & 0x7f)
#define	  AT91_PMC_USBDIV			(3 << 28)
#define     AT91_PMC_USBDIV_1			(0 << 28)
#define     AT91_PMC_USBDIV_2			BIT(28)
#define     AT91_PMC_USBDIV_4			(2 << 28)
#define	  AT91_PMC_USB96M			BIT(28)

#define AT91_PMC_CPU_CKR			0x28

#define	AT91_PMC_MCKR				0x30
#define	  AT91_PMC_CSS				(3 << 0)
#define     AT91_PMC_CSS_SLOW			(0 << 0)
#define     AT91_PMC_CSS_MAIN			BIT(0)
#define     AT91_PMC_CSS_PLLA			(2 << 0)
#define     AT91_PMC_CSS_PLLB			(3 << 0)
#define     AT91_PMC_CSS_UPLL			(3 << 0)
#define	  PMC_PRES_OFFSET			2
#define	  AT91_PMC_PRES				(7 << PMC_PRES_OFFSET)
#define     AT91_PMC_PRES_1			(0 << PMC_PRES_OFFSET)
#define     AT91_PMC_PRES_2			BIT(PMC_PRES_OFFSET)
#define     AT91_PMC_PRES_4			(2 << PMC_PRES_OFFSET)
#define     AT91_PMC_PRES_8			(3 << PMC_PRES_OFFSET)
#define     AT91_PMC_PRES_16			(4 << PMC_PRES_OFFSET)
#define     AT91_PMC_PRES_32			(5 << PMC_PRES_OFFSET)
#define     AT91_PMC_PRES_64			(6 << PMC_PRES_OFFSET)
#define	  PMC_ALT_PRES_OFFSET			4
#define	  AT91_PMC_ALT_PRES			(7 << PMC_ALT_PRES_OFFSET)
#define     AT91_PMC_ALT_PRES_1			(0 << PMC_ALT_PRES_OFFSET)
#define     AT91_PMC_ALT_PRES_2			BIT(PMC_ALT_PRES_OFFSET)
#define     AT91_PMC_ALT_PRES_4			(2 << PMC_ALT_PRES_OFFSET)
#define     AT91_PMC_ALT_PRES_8			(3 << PMC_ALT_PRES_OFFSET)
#define     AT91_PMC_ALT_PRES_16		(4 << PMC_ALT_PRES_OFFSET)
#define     AT91_PMC_ALT_PRES_32		(5 << PMC_ALT_PRES_OFFSET)
#define     AT91_PMC_ALT_PRES_64		(6 << PMC_ALT_PRES_OFFSET)
#define	  AT91_PMC_MDIV				(3 << 8)
#define     AT91RM9200_PMC_MDIV_1		(0 << 8)
#define     AT91RM9200_PMC_MDIV_2		BIT(8)
#define     AT91RM9200_PMC_MDIV_3		(2 << 8)
#define     AT91RM9200_PMC_MDIV_4		(3 << 8)
#define     AT91SAM9_PMC_MDIV_1			(0 << 8)
#define     AT91SAM9_PMC_MDIV_2			BIT(8)
#define     AT91SAM9_PMC_MDIV_4			(2 << 8)
#define     AT91SAM9_PMC_MDIV_6			(3 << 8)
#define     AT91SAM9_PMC_MDIV_3			(3 << 8)
#define	  AT91_PMC_PDIV				BIT(12)
#define     AT91_PMC_PDIV_1			(0 << 12)
#define     AT91_PMC_PDIV_2			BIT(12)
#define	  AT91_PMC_PLLADIV2			BIT(12)
#define     AT91_PMC_PLLADIV2_OFF		(0 << 12)
#define     AT91_PMC_PLLADIV2_ON		BIT(12)
#define	  AT91_PMC_H32MXDIV	BIT(24)

#define AT91_PMC_XTALF				0x34

#define	AT91_PMC_USB				0x38
#define	  AT91_PMC_USBS				(0x1 << 0)
#define     AT91_PMC_USBS_PLLA			(0 << 0)
#define     AT91_PMC_USBS_UPLL			BIT(0)
#define     AT91_PMC_USBS_PLLB			BIT(0)
#define	  AT91_PMC_OHCIUSBDIV			(0xF << 8)
#define     AT91_PMC_OHCIUSBDIV_1		(0x0 << 8)
#define     AT91_PMC_OHCIUSBDIV_2		(0x1 << 8)

#define	AT91_PMC_SMD				0x3c
#define	  AT91_PMC_SMDS				(0x1 << 0)
#define	  AT91_PMC_SMD_DIV			(0x1f << 8)
#define	  AT91_PMC_SMDDIV(n)			(((n) << 8) & AT91_PMC_SMD_DIV)

#define	AT91_PMC_PCKR(n)			(0x40 + ((n) * 4))
#define	  AT91_PMC_ALT_PCKR_CSS			(0x7 << 0)
#define     AT91_PMC_CSS_MASTER			(4 << 0)
#define	  AT91_PMC_CSSMCK			(0x1 << 8)
#define     AT91_PMC_CSSMCK_CSS			(0 << 8)
#define     AT91_PMC_CSSMCK_MCK			BIT(8)

#define	AT91_PMC_IER				0x60
#define	AT91_PMC_IDR				0x64
#define	AT91_PMC_SR				0x68
#define	  AT91_PMC_MOSCS			BIT(0)
#define	  AT91_PMC_LOCKA			BIT(1)
#define	  AT91_PMC_LOCKB			BIT(2)
#define	  AT91_PMC_MCKRDY			BIT(3)
#define	  AT91_PMC_LOCKU			BIT(6)
#define	  AT91_PMC_OSCSEL			BIT(7)
#define	  AT91_PMC_PCK0RDY			BIT(8)
#define	  AT91_PMC_PCK1RDY			BIT(9)
#define	  AT91_PMC_PCK2RDY			BIT(10)
#define	  AT91_PMC_PCK3RDY			BIT(11)
#define	  AT91_PMC_MOSCSELS			BIT(16)
#define	  AT91_PMC_MOSCRCS			BIT(17)
#define	  AT91_PMC_CFDEV			BIT(18)
#define	  AT91_PMC_GCKRDY			BIT(24)
#define	  AT91_PMC_MCKXRDY			BIT(26)
#define	AT91_PMC_IMR				0x6c

#define AT91_PMC_FSMR				0x70
#define AT91_PMC_FSTT(n)			BIT(n)
#define AT91_PMC_RTTAL				BIT(16)
#define AT91_PMC_RTCAL				BIT(17)
#define AT91_PMC_USBAL				BIT(18)
#define AT91_PMC_SDMMC_CD			BIT(19)
#define AT91_PMC_LPM				BIT(20)
#define AT91_PMC_RXLP_MCE			BIT(24)
#define AT91_PMC_ACC_CE				BIT(25)

#define AT91_PMC_FSPR				0x74

#define AT91_PMC_FS_INPUT_MASK			0x7ff

#define AT91_PMC_PLLICPR			0x80

#define AT91_PMC_PROT				0xe4
#define	  AT91_PMC_WPEN				(0x1 << 0)
#define	  AT91_PMC_WPKEY			(0xffffff << 8)
#define	  AT91_PMC_PROTKEY			(0x504d43 << 8)

#define AT91_PMC_WPSR				0xe8
#define	  AT91_PMC_WPVS				(0x1 << 0)
#define	  AT91_PMC_WPVSRC			(0xffff << 8)

#define AT91_PMC_PLL_ISR0			0xEC

#define AT91_PMC_PCER1				0x100
#define AT91_PMC_PCDR1				0x104
#define AT91_PMC_PCSR1				0x108

#define AT91_PMC_PCR				0x10c
#define	  AT91_PMC_PCR_PID_MASK			0x3f
#define	  AT91_PMC_PCR_CMD			(0x1 << 12)
#define	  AT91_PMC_PCR_GCKDIV_SHIFT		20
#define	  AT91_PMC_PCR_GCKDIV_MASK \
				GENMASK_32(27, AT91_PMC_PCR_GCKDIV_SHIFT)
#define	  AT91_PMC_PCR_EN			(0x1 << 28)
#define	  AT91_PMC_PCR_GCKEN			(0x1 << 29)

#define AT91_PMC_AUDIO_PLL0			0x14c
#define	  AT91_PMC_AUDIO_PLL_PLLEN		BIT(0)
#define	  AT91_PMC_AUDIO_PLL_PADEN		BIT(1)
#define	  AT91_PMC_AUDIO_PLL_PMCEN		BIT(2)
#define	  AT91_PMC_AUDIO_PLL_RESETN		BIT(3)
#define	  AT91_PMC_AUDIO_PLL_ND_OFFSET	8
#define	  AT91_PMC_AUDIO_PLL_ND_MASK \
				(0x7f << AT91_PMC_AUDIO_PLL_ND_OFFSET)
#define	  AT91_PMC_AUDIO_PLL_ND(n) \
				SHIFT_U32(n, AT91_PMC_AUDIO_PLL_ND_OFFSET)
#define	  AT91_PMC_AUDIO_PLL_QDPMC_OFFSET	16
#define	  AT91_PMC_AUDIO_PLL_QDPMC_MASK \
				(0x7f << AT91_PMC_AUDIO_PLL_QDPMC_OFFSET)
#define	  AT91_PMC_AUDIO_PLL_QDPMC(n) \
				SHIFT_U32(n, AT91_PMC_AUDIO_PLL_QDPMC_OFFSET)

#define AT91_PMC_AUDIO_PLL1			0x150
#define	  AT91_PMC_AUDIO_PLL_FRACR_MASK		0x3fffff
#define	  AT91_PMC_AUDIO_PLL_QDPAD_OFFSET	24
#define	  AT91_PMC_AUDIO_PLL_QDPAD_MASK \
				(0x7f << AT91_PMC_AUDIO_PLL_QDPAD_OFFSET)
#define	  AT91_PMC_AUDIO_PLL_QDPAD(n) \
				SHIFT_U32(n, AT91_PMC_AUDIO_PLL_QDPAD_OFFSET)
#define	  AT91_PMC_AUDIO_PLL_QDPAD_DIV_OFFSET \
				AT91_PMC_AUDIO_PLL_QDPAD_OFFSET
#define	  AT91_PMC_AUDIO_PLL_QDPAD_DIV_MASK \
				(0x3 << AT91_PMC_AUDIO_PLL_QDPAD_DIV_OFFSET)
#define	  AT91_PMC_AUDIO_PLL_QDPAD_DIV(n) \
			SHIFT_U32(n, AT91_PMC_AUDIO_PLL_QDPAD_DIV_OFFSET)
#define	  AT91_PMC_AUDIO_PLL_QDPAD_EXTDIV_OFFSET	26
#define	  AT91_PMC_AUDIO_PLL_QDPAD_EXTDIV_MAX		0x1f
#define	  AT91_PMC_AUDIO_PLL_QDPAD_EXTDIV_MASK \
				(AT91_PMC_AUDIO_PLL_QDPAD_EXTDIV_MAX << \
				AT91_PMC_AUDIO_PLL_QDPAD_EXTDIV_OFFSET)
#define	  AT91_PMC_AUDIO_PLL_QDPAD_EXTDIV(n) \
			SHIFT_U32(n, AT91_PMC_AUDIO_PLL_QDPAD_EXTDIV_OFFSET)

#endif
