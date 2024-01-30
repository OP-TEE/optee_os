// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021, STMicroelectronics - All Rights Reserved
 */

#include <assert.h>
#include <crypto/crypto.h>
#include <crypto/crypto_impl.h>
#include <crypto/internal_aes-gcm.h>
#include <drvcrypt.h>
#include <drvcrypt_authenc.h>
#include <initcall.h>
#include <stdlib.h>
#include <string.h>
#include <string_ext.h>
#include <tee_api_types.h>
#include <utee_defines.h>
#include <util.h>

#include "common.h"
#include "stm32_cryp.h"

#define MAX_TAG_SIZE			16U

struct stm32_ae_ctx {
	struct crypto_authenc_ctx a_ctx;
	struct stm32_cryp_context cryp;
	enum stm32_cryp_algo_mode algo;
	uint8_t tag_mask[MAX_TAG_SIZE];
};

static void xor_vec(uint8_t *r, uint8_t *a, uint8_t *b, size_t len)
{
	size_t i = 0;

	for (i = 0; i < len; i++)
		r[i] = a[i] ^ b[i];
}

static struct stm32_ae_ctx *to_stm32_ae_ctx(struct crypto_authenc_ctx *ctx)
{
	assert(ctx);

	return container_of(ctx, struct stm32_ae_ctx, a_ctx);
}

static TEE_Result stm32_ae_gcm_generate_iv(struct stm32_ae_ctx *c,
					   uint32_t *iv,
					   struct drvcrypt_authenc_init *dinit)
{
	TEE_Result res = TEE_SUCCESS;
	uint8_t tag1[MAX_TAG_SIZE] = { 0 };
	uint8_t tag2[MAX_TAG_SIZE] = { 0 };
	uint32_t j0[MAX_TAG_SIZE / sizeof(uint32_t)] = { 0 };
	uint8_t dummy_iv[MAX_TAG_SIZE] = { 0 };
	struct stm32_cryp_context ctx = { };
	uint8_t *data_out = NULL;

	if (dinit->nonce.length == 12) {
		memcpy(iv, dinit->nonce.data, dinit->nonce.length);
		iv[3] = TEE_U32_TO_BIG_ENDIAN(2);
		return TEE_SUCCESS;
	}

	/* Calculate GHASH(dinit->nonce.data) */
	dummy_iv[15] = 2;

	res = stm32_cryp_init(&ctx, true, STM32_CRYP_MODE_AES_GCM,
			      dinit->key.data, dinit->key.length,
			      dummy_iv, sizeof(dummy_iv));
	if (res)
		return res;

	res = stm32_cryp_final(&ctx, tag1, sizeof(tag1));
	if (res)
		return res;

	memset(&ctx, 0, sizeof(ctx));
	res = stm32_cryp_init(&ctx, true, STM32_CRYP_MODE_AES_GCM,
			      dinit->key.data, dinit->key.length,
			      dummy_iv, sizeof(dummy_iv));
	if (res)
		return res;

	data_out = malloc(dinit->nonce.length);
	if (!data_out)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = stm32_cryp_update_load(&ctx, dinit->nonce.data, data_out,
				     dinit->nonce.length);
	free(data_out);

	if (res)
		return res;

	res = stm32_cryp_final(&ctx, tag2, sizeof(tag2));
	if (res)
		return res;

	xor_vec((uint8_t *)j0, tag1, tag2, sizeof(tag1));

	memcpy(iv, j0, sizeof(j0));
	iv[3] = TEE_U32_TO_BIG_ENDIAN(TEE_U32_FROM_BIG_ENDIAN(iv[3]) + 1);

	/* Compute first mask=AES_ECB(J0_real) into tag1 */
	memset(&ctx, 0, sizeof(ctx));
	res = stm32_cryp_init(&ctx, false, STM32_CRYP_MODE_AES_ECB,
			      dinit->key.data, dinit->key.length,
			      NULL, 0);
	if (res)
		return res;

	res = stm32_cryp_update(&ctx, true, (uint8_t *)j0, tag1,
				sizeof(tag1));
	if (res)
		return res;

	/* Compute second mask=AES_ECB(J0_used_by_HW) into tag2 */
	memset(&ctx, 0, sizeof(ctx));
	j0[3] = TEE_U32_TO_BIG_ENDIAN(1);
	res = stm32_cryp_init(&ctx, false, STM32_CRYP_MODE_AES_ECB,
			      dinit->key.data, dinit->key.length,
			      NULL, 0);
	if (res)
		return res;

	res = stm32_cryp_update(&ctx, true, (uint8_t *)j0, tag2,
				sizeof(tag2));
	if (res)
		return res;

	/*
	 * Save the mask we will apply in {enc,dec}_final() to the
	 * (wrongly) computed tag to get the expected one.
	 */
	xor_vec(c->tag_mask, tag1, tag2, sizeof(c->tag_mask));

	return TEE_SUCCESS;
}

static void stm32_ae_ccm_generate_b0(uint8_t *b0,
				     struct drvcrypt_authenc_init *dinit)
{
	size_t m = dinit->tag_len;
	size_t l = 15 - dinit->nonce.length;
	size_t payload_len = dinit->payload_len;
	size_t i = 15;

	/* The tag_len should be 4, 6, 8, 10, 12, 14 or 16 */
	assert(m >= 4 && m <= 16 && (m % 2) == 0);

	memset(b0, 0, TEE_AES_BLOCK_SIZE);
	/* Flags: (Adata << 6) | (M' << 3) | L' */
	b0[0] = ((dinit->aad_len ? 1 : 0) << 6) |
		(((m - 2) / 2) << 3) |
		(l - 1);

	/* Nonce */
	memcpy(b0 + 1, dinit->nonce.data, dinit->nonce.length);

	/* Payload length */
	for (i = 15; i >= 15 - l + 1; i--, payload_len >>= 8)
		b0[i] = payload_len & 0xFF;
}

static TEE_Result stm32_ae_ccm_push_b1(struct stm32_ae_ctx *c,
				       struct drvcrypt_authenc_init *dinit)
{
	uint8_t b1[TEE_AES_BLOCK_SIZE] = { 0 };
	size_t len = 0;

	if (dinit->aad_len == 0)
		return TEE_SUCCESS;

	if (dinit->aad_len < 0x100) {
		b1[1] = dinit->aad_len;
		len = 2;
	} else if (dinit->aad_len < 0xFF00) {
		b1[0] = dinit->aad_len / 0x100;
		b1[1] = dinit->aad_len % 0x100;
		len = 2;
	} else if  (dinit->aad_len <= UINT32_MAX) {
		b1[0] = 0xFF;
		b1[1] = 0xFE;
		b1[2] = dinit->aad_len & GENMASK_32(7, 0);
		b1[3] = (dinit->aad_len & GENMASK_32(15, 8)) >> 8;
		b1[4] = (dinit->aad_len & GENMASK_32(23, 16)) >> 16;
		b1[5] = (dinit->aad_len & GENMASK_32(31, 24)) >> 24;
		len = 6;
	} else {
		b1[0] = 0xFF;
		b1[1] = 0xFF;
		b1[2] = dinit->aad_len & GENMASK_64(7, 0);
		b1[3] = (dinit->aad_len & GENMASK_64(15, 8)) >> 8;
		b1[4] = (dinit->aad_len & GENMASK_64(23, 16)) >> 16;
		b1[5] = (dinit->aad_len & GENMASK_64(31, 24)) >> 24;
		b1[6] = (dinit->aad_len & GENMASK_64(39, 32)) >> 32;
		b1[7] = (dinit->aad_len & GENMASK_64(47, 40)) >> 40;
		b1[8] = (dinit->aad_len & GENMASK_64(55, 48)) >> 48;
		b1[9] = (dinit->aad_len & GENMASK_64(63, 56)) >> 56;
		len = 10;
	}

	return stm32_cryp_update_assodata(&c->cryp, b1, len);
}

static TEE_Result stm32_ae_initialize(struct drvcrypt_authenc_init *dinit)
{
	TEE_Result res = TEE_SUCCESS;
	uint32_t iv[4] = { 0 };
	struct stm32_ae_ctx *c = to_stm32_ae_ctx(dinit->ctx);

	if (c->algo == STM32_CRYP_MODE_AES_GCM) {
		res = stm32_ae_gcm_generate_iv(c, iv, dinit);
		if (res)
			return res;
	} else if (c->algo == STM32_CRYP_MODE_AES_CCM) {
		stm32_ae_ccm_generate_b0((uint8_t *)iv, dinit);
	}

	res = stm32_cryp_init(&c->cryp, !dinit->encrypt, c->algo,
			      dinit->key.data, dinit->key.length, iv,
			      sizeof(iv));
	if (res)
		return res;

	if (c->algo == STM32_CRYP_MODE_AES_CCM)
		return stm32_ae_ccm_push_b1(c, dinit);

	return TEE_SUCCESS;
}

static TEE_Result
stm32_ae_update_aad(struct drvcrypt_authenc_update_aad *dupdate)
{
	struct stm32_ae_ctx *c = to_stm32_ae_ctx(dupdate->ctx);

	return stm32_cryp_update_assodata(&c->cryp, dupdate->aad.data,
					  dupdate->aad.length);
}

static TEE_Result
stm32_ae_update_payload(struct drvcrypt_authenc_update_payload *dupdate)
{
	struct stm32_ae_ctx *c = to_stm32_ae_ctx(dupdate->ctx);
	size_t len = MIN(dupdate->src.length, dupdate->dst.length);

	return stm32_cryp_update_load(&c->cryp, dupdate->src.data,
				      dupdate->dst.data, len);
}

static TEE_Result stm32_ae_encdec_final(struct stm32_ae_ctx *c, uint8_t *tag,
					size_t tag_size)
{
	TEE_Result res = TEE_SUCCESS;
	uint8_t t[MAX_TAG_SIZE] = { 0 };

	res = stm32_cryp_final(&c->cryp, t, sizeof(t));
	if (res)
		return res;

	xor_vec(tag, t, c->tag_mask, tag_size);

	return TEE_SUCCESS;
}

static TEE_Result stm32_ae_enc_final(struct drvcrypt_authenc_final *dfinal)
{
	TEE_Result res = TEE_SUCCESS;
	struct stm32_ae_ctx *c = to_stm32_ae_ctx(dfinal->ctx);
	size_t len = MIN(dfinal->src.length, dfinal->dst.length);

	res = stm32_cryp_update_load(&c->cryp, dfinal->src.data,
				     dfinal->dst.data, len);
	if (res)
		return res;

	return stm32_ae_encdec_final(c, dfinal->tag.data, dfinal->tag.length);
}

static TEE_Result stm32_ae_dec_final(struct drvcrypt_authenc_final *dfinal)
{
	TEE_Result res = TEE_SUCCESS;
	struct stm32_ae_ctx *c = to_stm32_ae_ctx(dfinal->ctx);
	size_t len = MIN(dfinal->src.length, dfinal->dst.length);
	unsigned char tag_buf[MAX_TAG_SIZE] = { 0 };

	res = stm32_cryp_update_load(&c->cryp, dfinal->src.data,
				     dfinal->dst.data, len);
	if (res)
		return res;

	res = stm32_ae_encdec_final(c, tag_buf, sizeof(tag_buf));
	if (res)
		return res;

	if (consttime_memcmp(tag_buf, dfinal->tag.data, dfinal->tag.length))
		return TEE_ERROR_MAC_INVALID;

	return TEE_SUCCESS;
}

static void stm32_ae_final(void *ctx __unused)
{
}

static void stm32_ae_free(void *ctx)
{
	struct stm32_ae_ctx *c = to_stm32_ae_ctx(ctx);

	free(c);
}

static void stm32_ae_copy_state(void *dst_ctx, void *src_ctx)
{
	struct stm32_ae_ctx *src = to_stm32_ae_ctx(src_ctx);
	struct stm32_ae_ctx *dst = to_stm32_ae_ctx(dst_ctx);

	memcpy(dst, src, sizeof(*dst));
}

static TEE_Result alloc_ctx(void **ctx, enum stm32_cryp_algo_mode algo)
{
	struct stm32_ae_ctx *c = calloc(1, sizeof(*c));

	if (!c)
		return TEE_ERROR_OUT_OF_MEMORY;

	c->algo = algo;
	*ctx = &c->a_ctx;

	return TEE_SUCCESS;
}

/*
 * Allocate the SW authenc data context
 *
 * @ctx   [out] Caller context variable
 * @algo  Algorithm ID of the context
 */
static TEE_Result stm32_ae_allocate(void **ctx, uint32_t algo)
{
	/* Convert TEE_ALGO id to CRYP id */
	switch (algo) {
	case TEE_ALG_AES_CCM:
		return alloc_ctx(ctx, STM32_CRYP_MODE_AES_CCM);
	case TEE_ALG_AES_GCM:
		return alloc_ctx(ctx, STM32_CRYP_MODE_AES_GCM);
	default:
		return TEE_ERROR_NOT_IMPLEMENTED;
	}
}

/*
 * Registration of the Authenc Driver
 */
static struct drvcrypt_authenc driver_authenc = {
	.alloc_ctx = stm32_ae_allocate,
	.free_ctx = stm32_ae_free,
	.init = stm32_ae_initialize,
	.update_aad = stm32_ae_update_aad,
	.update_payload = stm32_ae_update_payload,
	.enc_final = stm32_ae_enc_final,
	.dec_final = stm32_ae_dec_final,
	.final = stm32_ae_final,
	.copy_state = stm32_ae_copy_state,
};

TEE_Result stm32_register_authenc(void)
{
	return drvcrypt_register_authenc(&driver_authenc);
}
