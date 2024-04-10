/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2024 HiSilicon Limited.
 */
#ifndef _HPRE_MAIN_H
#define _HPRE_MAIN_H

#include <hisi_qm.h>

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

struct hpre_sqe {
	/*
	 * alg : 5
	 * etype : 11
	 * etype1 : 14
	 * done : 2
	 */
	uint32_t w0;

	uint8_t task_len1;
	uint8_t task_len2;
	uint8_t mrttest_num;
	/*
	 * uwkey_enb : 1
	 * sm2_ksel : 1
	 * sva_bypass : 1
	 * sva_status : 4
	 * bd_rsv2 : 1
	 */
	uint8_t ext1;

	uint64_t key;
	uint64_t in;
	uint64_t out;
	uint64_t tag;

	uint16_t sm2enc_klen;
	/*
	 * uwkey_sel : 4
	 * uwkey_wrap_num : 3
	 * rsvd2 : 9
	 */
	uint16_t ext2;

	uint64_t kek_key;
	uint32_t rsv[3];
};

enum hpre_alg_type {
	HPRE_ALG_NC_NCRT = 0x0,
	HPRE_ALG_NC_CRT = 0x1,
	HPRE_ALG_KG_STD = 0x2,
	HPRE_ALG_KG_CRT = 0x3,
	HPRE_ALG_DH_G2 = 0x4,
	HPRE_ALG_DH = 0x5,
	HPRE_ALG_ECDH_MULTIPLY = 0xD,
	HPRE_ALG_ECDSA_SIGN = 0xE,
	HPRE_ALG_ECDSA_VERF = 0xF,
	HPRE_ALG_X_DH_MULTIPLY = 0x10,
	HPRE_ALG_SM2_KEY_GEN = 0x11,
	HPRE_ALG_SM2_SIGN = 0x12,
	HPRE_ALG_SM2_VERF = 0x13,
	HPRE_ALG_SM2_ENC = 0x14,
	HPRE_ALG_SM2_DEC = 0x15
};

uint32_t hpre_init(void);
struct hisi_qp *hpre_create_qp(uint8_t sq_type);
enum hisi_drv_status hpre_bin_from_crypto_bin(uint8_t *dst, const uint8_t *src,
					      uint32_t bsize, uint32_t dsize);
enum hisi_drv_status hpre_bin_to_crypto_bin(uint8_t *dst, const uint8_t *src,
					    uint32_t bsize, uint32_t dsize);

#endif
