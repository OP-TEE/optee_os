/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2018-2019 NXP
 *
 * Brief   Job Ring Registers.
 */
#ifndef __JR_REGS_H__
#define __JR_REGS_H__

#include <util.h>

/* Job Ring Block Register Size */
#define JRX_BLOCK_SIZE		CFG_JR_BLOCK_SIZE
#define JRX_IDX(offset)		(((offset) - JRX_BLOCK_SIZE) / JRX_BLOCK_SIZE)

/*
 * Input Ring
 */
/* Base Address */
#define JRX_IRBAR			0x0000
/* Size */
#define JRX_IRSR			0x000C
/* Slots Available */
#define JRX_IRSAR			0x0014
/* Jobs Added */
#define JRX_IRJAR			0x001C

/*
 * Output Ring
 */
/* Base Address */
#define JRX_ORBAR			0x0020
/* Size */
#define JRX_ORSR			0x002C
/* Jobs Removed */
#define JRX_ORJRR			0x0034
/* Slots Full */
#define JRX_ORSFR			0x003C

/* Interrupt Status */
#define JRX_JRINTR			0x004C
#define BM_JRX_JRINTR_HALT		SHIFT_U32(0x3, 2)
#define JRINTR_HALT_RESUME		SHIFT_U32(0x2, 2)
#define JRINTR_HALT_ONGOING		SHIFT_U32(0x1, 2)
#define JRINTR_HALT_DONE		SHIFT_U32(0x2, 2)
#define JRX_JRINTR_JRI			BIT32(0)

/* Configuration */
#define JRX_JRCFGR_LS			0x0054
#define JRX_JRCFGR_LS_ICTT(val)		SHIFT_U32((val) & 0xFFFF, 16)
#define JRX_JRCFGR_LS_ICDCT(val)	SHIFT_U32((val) & 0xFF, 8)
#define JRX_JRCFGR_LS_ICEN		BIT32(1)
#define JRX_JRCFGR_LS_IMSK		BIT32(0)

/* Input Ring Read Index */
#define JRX_IRRIR			0x005C

/* Output Ring Write Index */
#define JRX_ORWIR			0x0064

/* Command */
#define JRX_JRCR			0x006C
#define JRX_JRCR_PARK			BIT32(1)
#define JRX_JRCR_RESET			BIT32(0)

/* CAAM Status register - duplicated */
#define JRX_CSTA			0x0FD4
#define JRX_CSTA_TRNG_IDLE		BIT32(2)
#define JRX_CSTA_IDLE			BIT32(1)
#define JRX_CSTA_BSY			BIT32(0)

#endif /* __JR_REGS_H__ */
