/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2022-2024 HiSilicon Limited. */
#ifndef __SEC_HASH_H__
#define __SEC_HASH_H__

#include <stdint.h>
#include <tee_api_types.h>

#define WORD_ALIGNMENT_MASK		0x3
#define HASH_MODE_OFFSET		28
#define WCRYPTO_DIGEST_HMAC		3
#define WCRYPTO_DIGEST_NORMAL		5
#define MAX_AUTH_LENGTH			16776704
#define HASH_MAC_LEN128			16
#define HASH_MAC_LEN160			20
#define HASH_MAC_LEN224			28
#define HASH_MAC_LEN256			32
#define HASH_MAC_LEN384			48
#define HASH_MAC_LEN512			64
#define SEC_DIGEST_MAX_KEY_SIZE		128
#define SEC_DIGEST_MAX_MAC_SIZE		64
#define SEC_DIGEST_MAX_IV_SIZE		64
#define SMALL_BUF_SIZE			0x1000

struct hashctx {
	uint8_t key[SEC_DIGEST_MAX_KEY_SIZE];
	uint8_t iv[SEC_DIGEST_MAX_IV_SIZE];
	uint8_t out[SEC_DIGEST_MAX_MAC_SIZE];
	bool has_next;
	uint8_t mode;
	uint32_t algo;
	uint32_t scene;
	struct hisi_qp *qp;
	uint8_t *in;
	uint64_t in_dma;
	size_t buf_len;
	size_t in_len;
	uint64_t out_dma;
	size_t mac_len;
	uint64_t key_dma;
	size_t key_len;
	uint64_t iv_dma;
	size_t iv_len;
	uint64_t long_data_len;
};

/*
 * Format the hash context to keep the reference to the
 * operation driver
 */
struct crypto_hash {
	struct crypto_hash_ctx hash_ctx; /* Crypto Hash API context */
	struct hashctx *ctx; /* Hash Context */
};

/*
 * Format the hmac context to keep the reference to the
 * operation driver
 */
struct crypto_hmac {
	struct crypto_mac_ctx hmac_op; /* Crypto Hash API context */
	struct hashctx *ctx; /* Hash Context */
};

enum A_ALG {
	A_ALG_SHA1     = 0x0,
	A_ALG_SHA256   = 0x1,
	A_ALG_MD5      = 0x2,
	A_ALG_SHA224   = 0x3,
	A_ALG_SHA384   = 0x4,
	A_ALG_SHA512   = 0x5,
	A_ALG_SHA512_224 = 0x6,
	A_ALG_SHA512_256 = 0x7,
	A_ALG_HMAC_SHA1   = 0x10,
	A_ALG_HMAC_SHA256 = 0x11,
	A_ALG_HMAC_MD5      = 0x12,
	A_ALG_HMAC_SHA224 = 0x13,
	A_ALG_HMAC_SHA384 = 0x14,
	A_ALG_HMAC_SHA512 = 0x15,
	A_ALG_HMAC_SHA512_224 = 0x16,
	A_ALG_HMAC_SHA512_256 = 0x17,
	A_ALG_AES_XCBC_MAC_96  = 0x20,
	A_ALG_AES_XCBC_PRF_128 = 0x20,
	A_ALG_AES_CMAC = 0x21,
	A_ALG_AES_GMAC = 0x22,
	A_ALG_SM3       = 0x25,
	A_ALG_HMAC_SM3 = 0x26,
	A_ALG_MAX
};

enum {
	AI_GEN_INNER        = 0x0,
	AI_GEN_IVIN_ADDR    = 0x1,
	AI_GEN_CAL_IV_ADDR  = 0x2,
	AI_GEN_TRNG         = 0x3,
};

enum {
	AUTHPAD_PAD,
	AUTHPAD_NOPAD,
};

TEE_Result hisi_sec_hash_ctx_init(struct hashctx *hash_ctx, uint32_t algo);
TEE_Result hisi_sec_digest_ctx_init(struct hashctx *hash_ctx,
				    const uint8_t *key, size_t len);
TEE_Result hisi_sec_digest_do_update(struct hashctx *hashctx,
				     const uint8_t *data, size_t len);
TEE_Result hisi_sec_digest_do_final(struct hashctx *hashctx, uint8_t *digest,
				    size_t len);
void hisi_sec_digest_ctx_free(struct hashctx *hash_ctx);
void hisi_sec_digest_copy_state(struct hashctx *out_hash_ctx,
				struct hashctx *in_hash_ctx);

#endif
