/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2019 NXP
 */
#ifndef __SM_REGS_H__
#define __SM_REGS_H__

#include <util.h>

/* Access Permission */
#define SM_SMAPR(prtn)			(0x0A04 + (prtn) * 16)
#define SM_SMAPR_GRP1(perm)		SHIFT_U32((perm) & 0xF, 0)
#define SM_SMAPR_GRP2(perm)		SHIFT_U32((perm) & 0xF, 4)
#define SM_SMAPR_CSP			BIT32(15)
#define SM_SMAPR_SMAP_LCK		BIT32(13)
#define SM_SMAPR_SMAG_LCK		BIT32(12)

/* Access Group */
#define SM_SMAG2(prtn)			(0x0A08 + (prtn) * 16)
#define SM_SMAG1(prtn)			(0x0A0C + (prtn) * 16)

/* Command */
#define SM_SMCR				0x0BE4
#define SM_SMCR_PAGE(page)		SHIFT_U32((page) & UINT16_MAX, 16)
#define SM_SMCR_PRTN(prtn)		SHIFT_U32((prtn) & 0xF, 8)
#define SM_SMCR_CMD(cmd)		SHIFT_U32((cmd) & 0xF, 0)
#define SM_SMCR_PAGE_ALLOC		0x1
#define SM_SMCR_PAGE_DEALLOC		0x2
#define SM_SMCR_PARTITION_DEALLOC	0x3
#define SM_SMCR_PAGE_INQ		0x5

/* Command Status */
#define SM_SMCSR			0x0BEC
#define SM_SMCSR_CERR(val)		(((val) >> 14) & 0x3)
#define SM_SMCSR_CERR_NO_ERROR		0x0
#define SM_SMCSR_CERR_NOT_COMPLETED	0x1
#define SM_SMCSR_AERR(val)		(((val) >> 12) & 0x3)
#define SM_SMCSR_AERR_NO_ERROR		0x0
#define SM_SMCSR_PO(val)		(((val) >> 6) & 0x3)
#define SM_SMCSR_PO_AVAILABLE		0x0
#define SM_SMCSR_PO_UNKNOWN		0x1
#define SM_SMCSR_PO_OWNED_BY_OTHER	0x2
#define SM_SMCSR_PO_OWNED		0x3
#define SM_SMCSR_PRTN(val)		((val) & 0x3)

/* Partition Owners */
#define SM_SMPO				0x0FBC
#define SM_SMPO_PART(prtn)		((prtn) * 2)
#define SM_SMPO_OWNER(val, prtn)	(((val) >> SM_SMPO_PART(prtn)) & 0x3)
#define SMPO_PO_AVAIL			0x0
#define SMPO_PO_OWNED			0x3

#endif /* __SM_REGS_H__ */
