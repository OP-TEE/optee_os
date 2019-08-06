/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2017-2019 NXP
 *
 * Brief   Version Registers.
 */
#ifndef __VERSION_REGS_H__
#define __VERSION_REGS_H__

#include <util.h>

/* CAAM Version ID */
#define CAAMVID_MS                      0x0BF8
#define BM_CAAMVID_MS_MAJ_REV           SHIFT_U32(0xFF, 8)
#define GET_CAAMVID_MS_MAJ_REV(val)     (((val) & BM_CAAMVID_MS_MAJ_REV) >> 8)

/* Compile Time Parameters */
#define CTPR_MS                         0x0FA8
#define BM_CTPR_MS_RNG_I                SHIFT_U32(0x7, 8)
#define GET_CTPR_MS_RNG_I(val)          (((val) & BM_CTPR_MS_RNG_I) >> 8)

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
#define BM_CHANUM_LS_MDNUM              SHIFT_U32(0xF, 12)
#define GET_CHANUM_LS_MDNUM(val)	(((val) & BM_CHANUM_LS_MDNUM) >> 12)

#endif /* __VERSION_REGS_H__ */

