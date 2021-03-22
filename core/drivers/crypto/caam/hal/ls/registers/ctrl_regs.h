/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2019, 2021 NXP
 *
 * Brief   Control Registers.
 */
#ifndef __CTRL_REGS_H__
#define __CTRL_REGS_H__

#include <util.h>

/* Master Configuration */
#define MCFGR				0x0004
#define MCFGR_WDE			BIT32(30)
#define MCFGR_AXIPIPE(val)		SHIFT_U32(val, 4)
#define BM_MCFGR_AXIPIPE		SHIFT_U32(0xF, 4)

/* Job Ring x MID */
#define JRxMIDR_SIZE			0x8
#define JR0MIDR_MS			0x0010
#define JR0MIDR_LS			0x0014
#define JRxMIDR_MS(idx)			(JR0MIDR_MS + (idx) * JRxMIDR_SIZE)
#define JRxMIDR_LS(idx)			(JR0MIDR_LS + (idx) * JRxMIDR_SIZE)

#define JRxMIDR_MS_LMID			BIT32(31)
#define JRxMIDR_MS_LAMTD		BIT32(17)
#define JRxMIDR_MS_TZ			BIT32(15)
#define JRxMIDR_MS_AMTD			BIT32(16)
#define JRxMIDR_MS_JROWN_NS		BIT32(3)
#define JRxMIDR_MS_JROWN_MID(val)	SHIFT_U32((val) & 0x7, 0)

#define JRxMIDR_LS_NONSEQ_NS		BIT32(19)
#define JRxMIDR_LS_NONSEQ_MID(val)	SHIFT_U32((val) & 0x7, 16)
#define JRxMIDR_LS_SEQ_NS		BIT32(3)
#define JRxMIDR_LS_SEQ_MID(val)		SHIFT_U32((val) & 0x7, 0)

/* Security Configuration */
#define SCFGR 0x000C

#endif /* __CTRL_REGS_H__ */

