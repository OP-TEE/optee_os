/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2020 NXP
 */
#ifndef __CTRL_REGS_H__
#define __CTRL_REGS_H__

/* Global includes */
#include <util.h>

/* Job Ring x MID */
#define JRxDID_SIZE    0x8
#define JR0DID_MS      0x0010
#define JR0DID_LS      0x0014
#define JRxDID_MS(idx) (JR0DID_MS + (idx) * (JRxDID_SIZE))
#define JRxDID_LS(idx) (JR0DID_LS + (idx) * (JRxDID_SIZE))

#define JRxDID_MS_LDID		 BIT32(31)
#define JRxDID_MS_PRIM_ICID(val) SHIFT_U32((val) & (0x3FF), 19)
#define JRxDID_MS_LAMTD		 BIT32(17)
#define JRxDID_MS_AMTD		 BIT32(16)
#define JRxDID_MS_TZ_OWN	 BIT32(15)
#define JRxDID_MS_PRIM_TZ	 BIT32(4)
#define JRxDID_MS_PRIM_DID(val)	 SHIFT_U32((val) & (0xF), 0)

/* Security Configuration */
#define SCFGR		 0x000C
#define BS_SCFGR_MPCURVE 28
#define BM_SCFGR_MPCURVE SHIFT_U32(0xF, BS_SCFGR_MPCURVE)
#define BM_SCFGR_MPMRL	 BIT32(26)

/* Secure Memory Virtual Base Address */
#define JRX_SMVBAR(idx) (0x0184 + (idx) * (8))

/* Manufacturing Protection Message */
#define MPMR	    0x0380
#define MPMR_NB_REG 0x20

#endif /* __CTRL_REGS_H__ */
