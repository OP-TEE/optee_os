/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2018-2019 NXP
 *
 * Brief   CAAM Job Ring Status definition header.
 */
#ifndef __JR_STATUS_H__
#define __JR_STATUS_H__

/* Source */
#define BM_JRSTA_SRC SHIFT_U32(0xF, 28)

#define JRSTA_SRC_GET(status) ((status) & BM_JRSTA_SRC)
#define JRSTA_SRC(src)        SHIFT_U32(JRSTA_SRC_##src, 28)

#define JRSTA_SRC_NONE          0x0
#define JRSTA_SRC_CCB           0x2
#define JRSTA_SRC_JMP_HALT_USER 0x3
#define JRSTA_SRC_DECO          0x4
#define JRSTA_SRC_JR            0x6
#define JRSTA_SRC_JMP_HALT_COND 0x7

#define JRSTA_CCB_GET_ERR(status) ((status) & SHIFT_U32(0xFF, 0))
#define JRSTA_CCB_CHAID_RNG       SHIFT_U32(0x5, 4)
#define JRSTA_CCB_ERRID_HW        SHIFT_U32(0xB, 0)
#define JRSTA_DECO_ERRID_FORMAT   SHIFT_U32(0x88, 0)

#endif /* __CAAM_JR_STATUS_H__ */
