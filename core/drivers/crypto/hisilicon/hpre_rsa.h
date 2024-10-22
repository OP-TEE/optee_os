/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2024, HiSilicon Technologies Co., Ltd.
 */

#ifndef __HPRE_RSA_H__
#define __HPRE_RSA_H__

#include <stdint.h>
#include <tee_api_types.h>
#include <types_ext.h>

#define PKCS_V1_5_MSG_MIN_LEN			11
#define PKCS_V1_5_PS_MIN_LEN			8
#define PKCS_V1_5_PS_POS			2
#define PKCS_V1_5_FIXED_LEN			3
#define PKCS_V1_5_PS_DATA			0x5a
#define OAEP_MAX_HASH_LEN			64
#define OAEP_MAX_DB_LEN				512
#define PRIME_QUALITY_FLAG			1024
#define HPRE_RSA_CRT_TOTAL_BUF_SIZE(kbytes)	((kbytes) * 6)
#define HPRE_RSA_CRT_KEY_BUF_SIZE(kbytes)	((kbytes) >> 10)
#define HPRE_RSA_NCRT_TOTAL_BUF_SIZE(kbytes)	((kbytes) * 4)

enum pkcs_v1_5_pad_type {
	SIGN_PAD = 1,
	ENCRYPT_PAD = 2
};

/*
 * When the mode is encrypt, the size of the buffer is
 * HPRE_RSA_NCRT_TOTAL_BUF_SIZE(kbytes) for both crt and ncrt;
 * when the mode is decrypt, the size of the buffer is
 * HPRE_RSA_CRT_TOTAL_BUF_SIZE(kbytes) for crt and
 * HPRE_RSA_NCRT_TOTAL_BUF_SIZE(kbytes) for ncrt.
 */
struct hpre_rsa_msg {
	uint8_t *pubkey;
	paddr_t pubkey_dma;
	uint8_t *prikey;
	paddr_t prikey_dma;
	uint8_t *in;
	paddr_t in_dma;
	uint8_t *out;
	paddr_t out_dma;
	uint32_t alg_type;
	uint32_t key_bytes;
	bool is_private;    /* True if private key */
};

#endif
