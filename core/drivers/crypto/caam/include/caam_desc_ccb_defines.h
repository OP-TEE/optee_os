/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2018-2021 NXP
 *
 * Brief   Define the CCB Registers to use in the CAAM descriptor
 */
#ifndef __CAAM_DESC_CCB_DEFINES_H__
#define __CAAM_DESC_CCB_DEFINES_H__

/* CCB CHA Control Register */
#define CCTRL_ULOAD_PKHA_B  BIT32(27)
#define CCTRL_ULOAD_PKHA_A  BIT32(26)

/* CCB Clear Written Register */
#define CLR_WR_IFIFO_NFIFO BIT32(31)
#define CLR_WR_RST_C2_CHA  BIT32(28)
#define CLR_WR_RST_C2_DSZ  BIT32(18)

/* CCB NFIFO */
#define NFIFO_CLASS(cla)       SHIFT_U32(NFIFO_CLASS_##cla & 0x3, 30)
#define NFIFO_CLASS_DECO       0x0
#define NFIFO_CLASS_C1         0x1
#define NFIFO_CLASS_BOTH       0x3

#define NFIFO_LC2	       BIT32(29)
#define NFIFO_LC1              BIT32(28)
#define NFIFO_FC1              BIT32(26)

#define NFIFO_STYPE(src)       SHIFT_U32(NFIFO_STYPE_##src & 0x3, 24)
#define NFIFO_STYPE_IFIFO      0x0
#define NFIFO_STYPE_PAD        0x2

#define NFIFO_DTYPE(data)      SHIFT_U32(NFIFO_DTYPE_##data & 0xF, 20)
#define NFIFO_DTYPE_MSG        0xF
#define NFIFO_DTYPE_PKHA_N     0x8
#define NFIFO_DTYPE_PKHA_A     0xC

#define NFIFO_PTYPE(pad)       SHIFT_U32(NFIFO_PTYPE_##pad & 0x7, 16)
#define NFIFO_PTYPE_ZERO       0x0
#define NFIFO_PTYPE_RND        0x3

#define NFIFO_DATA_LENGTH(len) SHIFT_U32((len) & 0xFFF, 0)
#define NFIFO_PAD_LENGTH(len)  SHIFT_U32((len) & 0x7F, 0)

/*
 * CCB NFIFO Entry to pad data with pad type
 */
#define NFIFO_PAD(cla, options, data, pad, len)                                \
	(NFIFO_CLASS(cla) | (options) | NFIFO_STYPE(PAD) | NFIFO_DTYPE(data) | \
	 NFIFO_PTYPE(pad) | NFIFO_PAD_LENGTH(len))

/*
 * CCB NFIFO Entry to move data from src to data
 */
#define NFIFO_NOPAD(cla, options, src, data, len)                              \
	(NFIFO_CLASS(cla) | (options) | NFIFO_STYPE(src) | NFIFO_DTYPE(data) | \
	 NFIFO_PTYPE(ZERO) | NFIFO_DATA_LENGTH(len))

#endif /* __CAAM_DESC_CCB_DEFINES_H__ */
