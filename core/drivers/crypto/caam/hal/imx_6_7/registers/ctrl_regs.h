/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2017-2019 NXP
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
#define JRxMIDR_MS_AMTD			BIT32(16)
#if !defined(CFG_MX7ULP)
#define JRxMIDR_MS_JROWN_NS		BIT32(3)
#define JRxMIDR_MS_JROWN_MID(val)	SHIFT_U32((val) & 0x7, 0)

#define JRxMIDR_LS_NONSEQ_NS		BIT32(19)
#define JRxMIDR_LS_NONSEQ_MID(val)	SHIFT_U32((val) & 0x7, 16)
#define JRxMIDR_LS_SEQ_NS		BIT32(3)
#define JRxMIDR_LS_SEQ_MID(val)		SHIFT_U32((val) & 0x7, 0)
#else
#define JRxMIDR_MS_JROWN_NS		BIT32(4)
#define JRxMIDR_MS_JROWN_MID(val)	SHIFT_U32((val) & 0xF, 0)

#define JRxMIDR_LS_NONSEQ_NS		BIT32(20)
#define JRxMIDR_LS_NONSEQ_MID(val)	SHIFT_U32((val) & 0xF, 16)
#define JRxMIDR_LS_SEQ_NS		BIT32(4)
#define JRxMIDR_LS_SEQ_MID(val)		SHIFT_U32((val) & 0xF, 0)
#endif

/* Security Configuration */
#define SCFGR				0x000C
#define BS_SCFGR_MPCURVE		28
#define BM_SCFGR_MPCURVE		SHIFT_U32(0xF, BS_SCFGR_MPCURVE)
#define BM_SCFGR_MPMRL			BIT32(26)

/* Manufacturing Protection Message */
#define MPMR				0x0380
#define MPMR_NB_REG			0x20

#endif /* __CTRL_REGS_H__ */
