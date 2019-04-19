/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2018-2019 NXP
 *
 * @file    caam_jr.h
 *
 * @brief   CAAM Job Rings module header.
 */
#ifndef __JR_STATUS_H__
#define __JR_STATUS_H__

/* Source */
#define BM_JRSTA_SRC			SHIFT_U32(0xF, 28)

#define JRSTA_SRC_GET(status)	(status & BM_JRSTA_SRC)
#define JRSTA_SRC(src)			SHIFT_U32(JRSTA_SRC_##src, 28)

#define JRSTA_SRC_NONE			0x0
#define JRSTA_SRC_CCB			0x2
#define JRSTA_SRC_JMP_HALT_USER	0x3
#define JRSTA_SRC_DECO			0x4
#define JRSTA_SRC_JR			0x6
#define JRSTA_SRC_JMP_HALT_COND	0x7

#define JRSTA_CCB_GET_ERR(status)	(status & SHIFT_U32(0xFF, 0))
#define JRSTA_CCB_CHAID_RNG			SHIFT_U32(0x5, 4)
#define JRSTA_CCB_ERRID_HW			SHIFT_U32(0xB, 0)
#define JRSTA_DECO_ERRID_FORMAT		SHIFT_U32(0x88, 0)

/* Return the Halt User status else 0 if not a Jump Halt User */
#define JRSTA_GET_HALT_USER(status) \
		((JRSTA_SRC_GET(status) == JRSTA_SRC(JMP_HALT_USER)) ? \
			(status & 0xFF) : 0)

#endif /* __JR_STATUS_H__ */

