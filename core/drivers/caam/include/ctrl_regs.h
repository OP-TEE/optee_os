/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2017-2018 NXP
 *
 */
#ifndef __CTRL_REGS_H__
#define __CTRL_REGS_H__

/* Master Configuration */
#define MCFGR				(0x0004)

#define BS_MCFGR_SWRST			(31)
#define BM_MCFGR_SWRST			(0x1 << BS_MCFGR_SWRST)
#define BS_MCFGR_WDE			(30)
#define BM_MCFGR_WDE			(0x1 << BS_MCFGR_WDE)
#define BS_MCFGR_WDF			(29)
#define BM_MCFGR_WDF			(0x1 << BS_MCFGR_WDF)
#define BS_MCFGR_DMA_RST		(28)
#define BM_MCFGR_DMA_RST		(0x1 << BS_MCFGR_DMA_RST)
#define BS_MCFGR_WRHD			(27)
#define BM_MCFGR_WRHD			(0x1 << BS_MCFGR_WRHD)
#define BS_MCFGR_DWT			(19)
#define BM_MCFGR_DWT			(0x1 << BS_MCFGR_DWT)
#define BS_MCFGR_ARCACHE		(12)
#define BM_MCFGR_ARCACHE		(0xF << BS_MCFGR_ARCACHE)
#define BS_MCFGR_AWCACHE		(8)
#define BM_MCFGR_AWCACHE		(0xF << BS_MCFGR_AWCACHE)
#define BS_MCFGR_AXIPIPE		(4)
#define BM_MCFGR_AXIPIPE		(0xF << BS_MCFGR_AXIPIPE)
#define BS_MCFGR_LARGE_BURST	(2)
#define BM_MCFGR_LARGE_BURST	(0x1 << BS_MCFGR_LARGE_BURST)

/* Security Configuration */
#define SCFGR				(0x000C)

#define BS_SCFGR_MPCURVE	(28)
#define BM_SCFGR_MPCURVE	(0xF << BS_SCFGR_MPCURVE)
#define BS_SCFGR_MPPKRC		(27)
#define BM_SCFGR_MPPKRC		(0x1 << BS_SCFGR_MPPKRC)
#define BS_SCFGR_MPMRL		(26)
#define BM_SCFGR_MPMRL		(0x1 << BS_SCFGR_MPMRL)
#define BS_SCFGR_LCK_TRNG	(11)
#define BM_SCFGR_LCK_TRNG	(0x1 << BS_SCFGR_LCK_TRNG)
#define BS_SCFGR_RDB		(10)
#define BM_SCFGR_RDB		(0x1 << BS_SCFGR_RDB)
#define BS_SCFGR_RNGSH0		(9)
#define BM_SCFGR_RNGSH0		(0x1 << BS_SCFGR_RNGSH0)
#define BS_SCFGR_RANDDPAR	(8)
#define BM_SCFGR_RANDDPAR	(0x1 << BS_SCFGR_RANDDPAR)
#define BS_SCFGR_PRIBLOB	(0)
#define BM_SCFGR_PRIBLOB	(0x3 << BS_SCFGR_PRIBLOB)

#define SCFGR_PRIBLOB_PRIV_SECURE_BOOT	(0x0)
#define SCFGR_PRIBLOB_PRIV_TYPE_1		(0x1)
#define SCFGR_PRIBLOB_PRIV_TYPE_2		(0x2)
#define SCFGR_PRIBLOB_NORMAL			(0x3)

/* Job Ring x MID */
#define JRxMIDR_SIZE			(0x8)
#define JR0MIDR_MS			(0x0010)
#define JR0MIDR_LS			(0x0014)
#define JRxMIDR_MS(idx)			(JR0MIDR_MS + (idx * JRxMIDR_SIZE))
#define JRxMIDR_LS(idx)			(JR0MIDR_LS + (idx * JRxMIDR_SIZE))

#define BS_JRxMIDR_MS_LMID		(31)
#define BM_JRxMIDR_MS_LMID		(1 << BS_JRxMIDR_MS_LMID)
#define BS_JRxMIDR_MS_LAMTD		(17)
#define BM_JRxMIDR_MS_LAMTD		(1 << BS_JRxMIDR_MS_LAMTD)
#define BS_JRxMIDR_MS_AMTD		(16)
#define BM_JRxMIDR_MS_AMTD		(1 << BS_JRxMIDR_MS_AMTD)
#define BS_JRxMIDR_MS_TZ		(15)
#define BM_JRxMIDR_MS_TZ		(1 << BS_JRxMIDR_MS_TZ)
#if !defined(CFG_MX7ULP)
#define BS_JRxMIDR_MS_SDID_MS		(4)
#define BM_JRxMIDR_MS_SDID_MS		(0xFF << BS_JRxMIDR_MS_SDID_MS)
#define BS_JRxMIDR_MS_JROWN_NS		(3)
#define BM_JRxMIDR_MS_JROWN_NS		(0x1 << BS_JRxMIDR_MS_JROWN_NS)
#define BS_JRxMIDR_MS_JROWN_MID		(0)
#define BM_JRxMIDR_MS_JROWN_MID		(0x7 << BS_JRxMIDR_MS_JROWN_MID)

#define BS_JRxMIDR_LS_NONSEQ_NS		(19)
#define BM_JRxMIDR_LS_NONSEQ_NS		(0x1 << BS_JRxMIDR_LS_NONSEQ_NS)
#define BS_JRxMIDR_LS_NONSEQ_MID	(16)
#define BM_JRxMIDR_LS_NONSEQ_MID	(0x7 << BS_JRxMIDR_LS_NONSEQ_MID)
#define BS_JRxMIDR_LS_SEQ_NS		(3)
#define BM_JRxMIDR_LS_SEQ_NS		(0x1 << BS_JRxMIDR_LS_SEQ_NS)
#define BS_JRxMIDR_LS_SEQ_MID		(0)
#define BM_JRxMIDR_LS_SEQ_MID		(0x7 << BS_JRxMIDR_LS_SEQ_MID)

#define MSTRID_DMA	0
#define MSTRID_ARM	1
#define MSTRID_CAAM	2
#define MSTRID_SDMA	3

#define MSTRID_S_DMA	(MSTRID_DMA)
#define MSTRID_S_ARM	(MSTRID_ARM)
#define MSTRID_S_CAAM	(MSTRID_CAAM)
#define MSTRID_S_SDMA	(MSTRID_SDMA)
#define MSTRID_NS_DMA	(MSTRID_DMA  | BM_JRxMIDR_MS_JROWN_NS)
#define MSTRID_NS_ARM	(MSTRID_ARM  | BM_JRxMIDR_MS_JROWN_NS)
#define MSTRID_NS_CAAM	(MSTRID_CAAM | BM_JRxMIDR_MS_JROWN_NS)
#define MSTRID_NS_SDMA	(MSTRID_SDMA | BM_JRxMIDR_MS_JROWN_NS)

#else

#define BS_JRxMIDR_MS_SDID_MS		(5)
#define BM_JRxMIDR_MS_SDID_MS		(0x7F << BS_JRxMIDR_MS_SDID_MS)
#define BS_JRxMIDR_MS_JROWN_NS		(4)
#define BM_JRxMIDR_MS_JROWN_NS		(0x1 << BS_JRxMIDR_MS_JROWN_NS)
#define BS_JRxMIDR_MS_JROWN_MID		(0)
#define BM_JRxMIDR_MS_JROWN_MID		(0xF << BS_JRxMIDR_MS_JROWN_MID)

#define BS_JRxMIDR_LS_NONSEQ_NS		(20)
#define BM_JRxMIDR_LS_NONSEQ_NS		(0x1 << BS_JRxMIDR_LS_NONSEQ_NS)
#define BS_JRxMIDR_LS_NONSEQ_MID	(16)
#define BM_JRxMIDR_LS_NONSEQ_MID	(0xF << BS_JRxMIDR_LS_NONSEQ_MID)
#define BS_JRxMIDR_LS_SEQ_NS		(4)
#define BM_JRxMIDR_LS_SEQ_NS		(0x1 << BS_JRxMIDR_LS_SEQ_NS)
#define BS_JRxMIDR_LS_SEQ_MID		(0)
#define BM_JRxMIDR_LS_SEQ_MID		(0xF << BS_JRxMIDR_LS_SEQ_MID)

#define MSTRID_CM4	0x0
#define MSTRID_CM4DAP	0x1
#define MSTRID_DMA0	0x2
#define MSTRID_ETR	0x3
#define MSTRID_CA7	0x4
#define MSTRID_DSI	0x5
#define MSTRID_GPU3D	0x6
#define MSTRID_GPU2D	0x7
#define MSTRID_DMA1	0x8
#define MSTRID_CAAM	0x9
#define MSTRID_USB	0xA
#define MSTRID_VIU	0xB
#define MSTRID_uSDHC0	0xC
#define MSTRID_uSDHC1	0xD
#define MSTRID_RSV1	0xE
#define MSTRID_RSV2	0xF


#define MSTRID_S_ARM	(MSTRID_CA7)
#define MSTRID_S_CAAM	(MSTRID_CAAM)

#define MSTRID_NS_ARM	(MSTRID_CA7  | BM_JRxMIDR_MS_JROWN_NS)
#define MSTRID_NS_CAAM	(MSTRID_CAAM | BM_JRxMIDR_MS_JROWN_NS)

#endif

/* Debug Control */
#define DEBUGCTL			(0x0058)
/* Job Ring Start */
#define JRSTARTR			(0x005C)

/* RTIC MID for Block x */
#define RTICxMIDR_SIZE		(0x8)
#define RTICAMIDR_MS		(0x0060)
#define RTICAMIDR_LS		(0x0064)
#define RTICxMIDR_MS(idx)	(RTICAMIDR_MS + (idx * RTICxMIDR_SIZE))
#define RTICxMIDR_LS(idx)	(RTICAMIDR_LS + (idx * RTICxMIDR_SIZE))

/* DECO */
#define DECO_REQ_SRC		(0x0090)
#define DECO_REQUEST		(0x009C)
#define DECO0MIDR_MS		(0x00A0)
#define DECO0MIDR_LS		(0x00A4)
#define DECO_AVAILABLE		(0x0120)
#define DECO_RESET			(0x0124)

#define BS_DECO_REQ_SRC_VALID	(31)
#define BM_DECO_REQ_SRC_VALID	(0x1 << BS_DECO_REQ_SRC_VALID)
#define BS_DECO_REQ_SRC_JR0		(0)
#define BM_DECO_REQ_SRC_JR0		(0x1 << BS_DECO_REQ_SRC_JR0)

#define BS_DECO_REQUEST_DEN0	(16)
#define BM_DECO_REQUEST_DEN0	(0x1 << BS_DECO_REQUEST_DEN0)
#define BS_DECO_REQUEST_RQD0	(0)
#define BM_DECO_REQUEST_RQD0	(0x1 << BS_DECO_REQUEST_RQD0)

/* DMA Aliasing */
#define	ALIAS_DMAC			(0x0204)
#define ALIAS_DMA0AIML_MS	(0x0240)
#define ALIAS_DMA0AIML_LS	(0x0244)
#define ALIAS_DMA0AIMH_MS	(0x0248)
#define ALIAS_DMA0AIMH_LS	(0x024C)
#define ALIAS_DMA0AIE		(0x0254)
#define ALIAS_DMA0ARTC		(0x0260)
#define ALIAS_DMA0ARL		(0x026C)
#define ALIAS_DMA0AWTC		(0x0270)
#define ALIAS_DMA0AWL		(0x027C)

/* Manufacturing Protection Private Key */
#define MPPKR_x_SIZE		(0x0001)
#define MPPKR_0				(0x0300)
#define MPPKR_x(idx)		(MPPKR_0 + (idx * MPPKR_x_SIZE))
/* Manufacturing Protection Message */
#define MPMRx_SIZE			(0x0001)
#define MPMR_0				(0x0380)
#define MPMR_x(idx)			(MPMR_0 + (idx * MPMR_x_SIZE))
/* Manufacturing Protection Test */
#define MPTESTR_x_SIZE		(0x0001)
#define MPTESTR_0			(0x03C0)
#define MPTESTR_x(idx)		(MPTESTR_0 + (idx * MPTESTR_x_SIZE))

/* Job Descriptor Key Encryption Key (JDKEK) */
#define JDKEKR_x_SIZE		(0x0001)
#define JDKEKR_0			(0x0400)
#define JDKEKR_x(idx)		(JDKEKR_0 + (idx * JDKEKR_x_SIZE))
/* Trusted Descriptor Key Encryption Key (TDKEK) */
#define TDKEKR_x_SIZE		(0x0001)
#define TDKEKR_0			(0x0420)
#define TDKEKR_x(idx)		(TDKEKR_0 + (idx * TDKEKR_x_SIZE))
/* Trusted Descriptor Signing Key (TDSK) */
#define TDSKR_x_SIZE		(0x0001)
#define TDSKR_0				(0x0440)
#define TDSKR_x(idx)		(TDSKR_0 + (idx * TDSKR_x_SIZE))
/* Secure Key Nonce (SKN)*/
#define SKNR				(0x04E0)

/* DMA Aliasing */
#define DMA_STA_REG					(0x0500)
#define DMA_CTL_REG					(0x0504)
#define DMA0_AID_7_0_MAP_REG_MS		(0x0510)
#define DMA0_AID_7_0_MAP_REG_LS		(0x0514)
#define DMA0_AID_15_8_MAP_REG_MS	(0x0518)
#define DMA0_AID_15_8_MAP_REG_LS	(0x051C)
#define DMA0_AID_15_0_EN_REG		(0x0524)
#define DMA0ARTC_CTL_REG			(0x0530)
#define DMA0ARTC_LC_REG				(0x0534)
#define DMA0ARTC_SC_REG				(0x0538)
#define DMA0ARTC_LAT_REG			(0x053C)
#define DMA0AWTC_CTL_REG			(0x0540)
#define DMA0AWTC_LC_REG				(0x0544)
#define DMA0AWTC_SC_REG				(0x0548)
#define DMA0AWTC_LAT_REG			(0x054C)

/* Recoverable Error Indication Status */
#define REIS	(0x0B00)
/* Recoverable Error Indication Halt */
#define REIH	(0x0B0C)

/*
 * Debug Registers
 */
/* Holding Tank 0 */
#define	HT0_JD_ADDR		(0x0C00)
#define HT0_SD_ADDR		(0x0C08)
#define HT0_JQ_CTRL_MS	(0x0C10)
#define HT0_JQ_CTRL_LS	(0x0C14)
#define HT0_STATUS		(0x0C1C)
#define JQ_DEBUG_SEL	(0x0C24)
#define JRJIDU_LS		(0x0DBC)
#define JRJDJIFBC		(0x0DC0)
#define JRJDJIF			(0x0DC4)
#define JRJDS1			(0x0DE4)
#define JRJDDA			(0x0E00)

/*
 * Secure Memory
 */
#define SMSTA		(0x0FB4)
#define SMPO		(0x0FBC)

#define BS_SMPO_PO			(2)
#define BM_SMPO_PO			(0x3)

#define BS_SMPO_POx(idx)		(idx * BS_SMPO_PO)
#define BM_SMPO_POx(idx)		(BM_SMPO_PO << BS_SMPO_POx(idx))
#define GET_SMPO_POx(val, idx)	((val >> BS_SMPO_POx(idx)) & BM_SMPO_PO)

#define SMPO_POx_AVAILABLE		(0)
#define SMPO_POx_NOEXIST		(1)
#define SMPO_POx_UNAVAILABLE	(2)
#define SMPO_POx_OURS			(3)

/* Fault Address */
#define FAR			(0x0FC0)
#define FAMR		(0x0FC8)
#define FADR		(0x0FCC)

/* CAAM Status */
#define CSTA		(0x0FD4)

#endif /* __CTRL_REGS_H__ */

