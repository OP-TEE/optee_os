/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2018-2019 NXP
 *
 * @file    jr_regs.h
 *
 * @brief   Job Ring Registers.\n
 */
#ifndef __JR_REGS_H__
#define __JR_REGS_H__

/* Global includes */
#include <util.h>

/* Job Ring Block Register Size */
#define JRx_BLOCK_SIZE		CFG_JR_BLOCK_SIZE
#define JRx_IDX(offset)		((offset - JRx_BLOCK_SIZE) / JRx_BLOCK_SIZE)

/*
 * Input Ring
 */
/* Base Address */
#define JRx_IRBAR					0x0000
/* Size */
#define JRx_IRSR					0x000C
/* Slots Available */
#define JRx_IRSAR					0x0014
/* Jobs Added */
#define JRx_IRJAR					0x001C

/*
 * Output Ring
 */
/* Base Address */
#define JRx_ORBAR					0x0020
/* Size */
#define JRx_ORSR					0x002C
/* Jobs Removed */
#define JRx_ORJRR					0x0034
/* Slots Full */
#define JRx_ORSFR					0x003C

/* Interrupt Status */
#define JRx_JRINTR					0x004C
#define BM_JRx_JRINTR_HALT			SHIFT_U32(0x3, 2)
#define JRINTR_HALT_RESUME			SHIFT_U32(0x2, 2)
#define JRINTR_HALT_ONGOING			SHIFT_U32(0x1, 2)
#define JRINTR_HALT_DONE			SHIFT_U32(0x2, 2)
#define JRx_JRINTR_JRI				BIT32(0)

/* Configuration */
#define JRx_JRCFGR_LS				0x0054
#define JRx_JRCFGR_LS_ICTT(val)		SHIFT_U32((val & 0xFFFF), 16)
#define JRx_JRCFGR_LS_ICDCT(val)	SHIFT_U32((val & 0xFF), 8)
#define JRx_JRCFGR_LS_ICEN			BIT32(1)
#define JRx_JRCFGR_LS_IMSK			BIT32(0)

/* Input Ring Read Index */
#define JRx_IRRIR					0x005C

/* Output Ring Write Index */
#define JRx_ORWIR					0x0064

/* Command */
#define JRx_JRCR					0x006C
#define JRx_JRCR_PARK				BIT32(1)
#define JRx_JRCR_RESET				BIT32(0)

/* CAAM Status register - duplicated */
#define JRx_CSTA					0x0FD4
#define JRx_CSTA_TRNG_IDLE			BIT32(2)
#define JRx_CSTA_IDLE				BIT32(1)
#define JRx_CSTA_BSY				BIT32(0)

#endif /* __JR_REGS_H__ */
