/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2024 HiSilicon Limited.
 */
#ifndef _HPRE_MAIN_H
#define _HPRE_MAIN_H

#include <initcall.h>
#include "hisi_qm.h"

#define HPRE_BAR_BASE		0x150000000
#define HPRE_BAR_SIZE		0x400000
#define HPRE_SQE_SIZE		64
#define HPRE_SQE_LOG2_SIZE	6
#define HPRE_SQE_SM2_KSEL_SHIFT	1
#define HPRE_SQE_BD_RSV2_SHIFT	7
#define HPRE_HW_TASK_INIT	0x1
#define HPRE_HW_TASK_DONE	0x3
#define TASK_LENGTH(len)	((len) / 8 - 1)
#define BITS_TO_BYTES(len)	(((len) + 7) / 8)
#define BYTES_TO_BITS(len)	((len) * 8)

#define HPRE_ETYPE_SHIFT	5
#define HPRE_ETYPE_MASK		0x7ff
#define HPRE_ETYPE1_SHIFT	16
#define HPRE_ETYPE1_MASK	0x3fff
#define HPRE_DONE_SHIFT		30
#define HPRE_DONE_MASK		0x3
#define HPRE_TASK_ETYPE(w0)	(((w0) >> HPRE_ETYPE_SHIFT) & HPRE_ETYPE_MASK)
#define HPRE_TASK_ETYPE1(w0)	(((w0) >> HPRE_ETYPE1_SHIFT) & HPRE_ETYPE1_MASK)
#define HPRE_TASK_DONE(w0)	(((w0) >> HPRE_DONE_SHIFT) & HPRE_DONE_MASK)

struct hisi_qp *hpre_create_qp(uint8_t sq_type);
enum hisi_drv_status hpre_bin_from_crypto_bin(uint8_t *dst, const uint8_t *src,
					      uint32_t bsize, uint32_t dsize);
enum hisi_drv_status hpre_bin_to_crypto_bin(uint8_t *dst, const uint8_t *src,
					    uint32_t bsize, uint32_t dsize);

#endif
