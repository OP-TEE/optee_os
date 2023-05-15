/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2017-2020 NXP
 *
 * Brief   Version Registers.
 */
#ifndef __VERSION_REGS_H__
#define __VERSION_REGS_H__

#include <util.h>

/* Compile Time Parameters */
#define CTPR_MS                         0x0FA8
#define BM_CTPR_MS_RNG_I                SHIFT_U32(0x7, 8)
#define GET_CTPR_MS_RNG_I(val)          (((val) & BM_CTPR_MS_RNG_I) >> 8)

#define CTPR_LS				0x0FAC
#define BM_CTPR_LS_SPLIT_KEY		BIT(14)
#define GET_CTPR_LS_SPLIT_KEY(val)	(((val) & BM_CTPR_LS_SPLIT_KEY) >> 14)

/* Secure Memory Version ID */
#define SMVID_MS			0x0FD8
#define BM_SMVID_MS_MAX_NPAG		SHIFT_U32(0x3FF, 16)
#define GET_SMVID_MS_MAX_NPAG(val)	(((val) & BM_SMVID_MS_MAX_NPAG) >> 16)
#define BM_SMVID_MS_NPRT		SHIFT_U32(0xF, 12)
#define GET_SMVID_MS_NPRT(val)		(((val) & BM_SMVID_MS_NPRT) >> 12)

#define SMVID_LS			0x0FDC
#define BM_SMVID_LS_PSIZ		SHIFT_U32(0x7, 16)
#define GET_SMVID_LS_PSIZ(val)		(((val) & BM_SMVID_LS_PSIZ) >> 16)

/* CHA Cluster Block Version ID */
#define CCBVID                          0x0FE4
#define BM_CCBVID_CAAM_ERA              SHIFT_U32(0xFF, 24)
#define GET_CCBVID_CAAM_ERA(val)        (((val) & BM_CCBVID_CAAM_ERA) >> 24)

/* CHA Version ID */
#define CHAVID_LS                       0x0FEC
#define BM_CHAVID_LS_RNGVID             SHIFT_U32(0xF, 16)
#define GET_CHAVID_LS_RNGVID(val)       (((val) & BM_CHAVID_LS_RNGVID) >> 16)
#define BM_CHAVID_LS_MDVID		SHIFT_U32(0xF, 12)

#define CHAVID_LS_MDVID_LP256           SHIFT_U32(0, 12)

/* CHA Number */
#define CHANUM_MS                       0x0FF0
#define BM_CHANUM_MS_JRNUM              SHIFT_U32(0xF, 28)
#define GET_CHANUM_MS_JRNUM(val)        (((val) & BM_CHANUM_MS_JRNUM) >> 28)

#define CHANUM_LS                       0x0FF4
#define BM_CHANUM_LS_PKNUM              SHIFT_U32(0xF, 28)
#define GET_CHANUM_LS_PKNUM(val)	(((val) & BM_CHANUM_LS_PKNUM) >> 28)
#define BM_CHANUM_LS_MDNUM              SHIFT_U32(0xF, 12)
#define GET_CHANUM_LS_MDNUM(val)	(((val) & BM_CHANUM_LS_MDNUM) >> 12)

/* PKHA Version for Era > 10 */
#define PKHA_VERSION			0x0E8C
#define BM_PKHA_VERSION_PKNUM		0xFF
#define GET_PKHA_VERSION_PKNUM(val)	((val) & BM_PKHA_VERSION_PKNUM)

/* MDHA Version for Era > 10 */
#define MDHA_VERSION			0xE94
#define BM_MDHA_VERSION_MDNUM		0xFF
#define GET_MDHA_VERSION_MDNUM(val)	((val) & BM_MDHA_VERSION_MDNUM)
#define BM_MDHA_VERSION_MDVID		SHIFT_U32(0xFF, 24)

#define MDHA_VERSION_MDVID_LP256	SHIFT_U32(0, 24)

/* RNG Version for Era > 10 */
#define RNG_VERSION			0x0EF8
#define BM_RNG_VERSION_VID	        SHIFT_U32(0xFF, 24)
#define GET_RNG_VERSION_VID(val)	((val) & BM_RNG_VERSION_VID)

/* JR Version for Era > 10 */
#define JR_VERSION			0x0EF8
#define BM_JR_VERSION_JRNUM		0xFF
#define GET_JR_VERSION_JRNUM(val)	((val) & BM_JR_VERSION_JRNUM)

#endif /* __VERSION_REGS_H__ */

