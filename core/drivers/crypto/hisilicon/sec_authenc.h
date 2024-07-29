/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2022-2024 HiSilicon Limited. */

#ifndef __SEC_AUTHENC_H__
#define __SEC_AUTHENC_H__

#include <stdbool.h>
#include <stdint.h>

#include "hisi_qm.h"

#define SEC_MAX_AEAD_LENGTH		16777199
#define SEC_MIN_AEAD_LENGTH		4
#define SEC_TAG_ERR			0x2
#define SEC_MIN_GCM_TAG_LEN		8
#define SEC_MIN_CCM_TAG_LEN		4
#define SEC_MAX_TAG_LEN			16
#define SEC_CIPHER_THEN_DIGEST		0
#define SEC_DIGEST_THEN_CIPHER		1

#define MAX_GCM_AAD_SIZE		65535
#define MAX_CCM_AAD_SIZE		65279
#define GCM_IV_SIZE			12
#define MAX_CCM_NONCE_SIZE		12
#define MIN_CCM_NONCE_SIZE		7
#define TAG_ALIGN			2
#define MAX_KEY_SIZE			32
#define MAX_IV_SIZE			16
#define NONCE_OFFSET			1
#define IV_LAST_BYTE1			15
#define IV_LAST_BYTE2			14
#define IV_LAST_BYTE3			13
#define IV_CTR_INIT			1
#define IV_CL_CAL_NUM			14
#define IV_CM_CAL_NUM			2
#define IV_CL_MASK			0x7
#define IV_FLAGS_OFFSET			0x6
#define IV_CM_OFFSET			0x3
#define IV_LAST_BYTE_MASK		0xFF
#define IV_BYTE_OFFSET			0x8
#define AAD_NOT_NULL			1

struct authenc_ctx {
	struct hisi_qp *qp;
	bool encrypt;
	uint8_t civ[MAX_IV_SIZE];
	uint8_t aiv[MAX_IV_SIZE];
	uint8_t key[MAX_KEY_SIZE];
	uint8_t tag[SEC_MAX_TAG_LEN];
	struct drvcrypt_buf aad;
	struct drvcrypt_buf src;
	struct drvcrypt_buf dst;

	uint8_t algo;
	uint8_t mode;
	uint32_t result;
	bool is_hw_supported;
	struct crypto_authenc_ctx *ae_soft_ctx;
	size_t src_offset;
	size_t payload_len;
	size_t key_len;
	size_t civ_len;
	size_t tag_len;
	uint8_t c_key_len;

	/* aead dma */
	paddr_t key_dma;
	paddr_t civ_dma;
	paddr_t aiv_dma;
	paddr_t src_dma;
	paddr_t dst_dma;
	paddr_t tag_dma;
};
#endif /* __SEC_AUTHENC_H__ */
