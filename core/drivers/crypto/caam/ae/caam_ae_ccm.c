// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2024 NXP
 *
 * Implementation of Cipher CCM functions
 */
#include <caam_common.h>
#include <caam_utils_mem.h>
#include <caam_utils_status.h>
#include <drvcrypt_math.h>
#include <string.h>
#include <string_ext.h>
#include <utee_defines.h>

#include "local.h"

/* Length of AAD buffer size, as in SP800-38C */
#define AAD_SIZE_LEN 2

/* Nonce length */
#define AES_CCM_MAX_NONCE_LEN 15

/* Tag length */
#define AES_CCM_MIN_TAG_LEN 4
#define AES_CCM_MAX_TAG_LEN 16

/* Adata Flag */
#define BM_B0_ADATA_PRESENCE BIT32(6)

/* B0 Tag length */
#define BS_B0_TAG_LENGTH 3
#define BM_B0_TAG_LENGTH SHIFT_U32(0x7, BS_B0_TAG_LENGTH)
#define B0_TAG_LENGTH(x) \
	(SHIFT_U32(((x) - 2) / 2, BS_B0_TAG_LENGTH) & BM_B0_TAG_LENGTH)

/* B0 Payload size length */
#define BS_B0_Q_LENGTH 0
#define BM_B0_Q_LENGTH SHIFT_U32(0x7, BS_B0_Q_LENGTH)
#define B0_Q_LENGTH(x) (SHIFT_U32((x) - 1, BS_B0_Q_LENGTH) & BM_B0_Q_LENGTH)

/*
 * Initialize AES CCM operation context
 *
 * @caam_ctx AE Cipher context
 * @dinit    Data initialization object
 */
static TEE_Result caam_ae_ccm_init_ctx(struct caam_ae_ctx *caam_ctx,
				       struct drvcrypt_authenc_init *dinit)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	enum caam_status retstatus = CAAM_FAILURE;
	struct caambuf aad = { };
	uint8_t *b0 = NULL;
	uint8_t *ctr0 = NULL;
	size_t q = 0;
	size_t payload_len = 0;
	size_t i = 0;

	assert(caam_ctx && dinit);

	if (dinit->nonce.length > AES_CCM_MAX_NONCE_LEN)
		return TEE_ERROR_BAD_PARAMETERS;

	/* The tag_len should be 4, 6, 8, 10, 12, 14 or 16 */
	if (caam_ctx->tag_length < 4 || caam_ctx->tag_length > 16 ||
	    caam_ctx->tag_length % 2 != 0)
		return TEE_ERROR_BAD_PARAMETERS;

	payload_len = caam_ctx->payload_length;

	/*
	 * Before AE operations CAAM ctx register
	 * must be filled with B0 and Ctr0.
	 */
	b0 = caam_ctx->initial_ctx.data;
	ctr0 = caam_ctx->initial_ctx.data + TEE_AES_BLOCK_SIZE;

	/*
	 * Set B0 initial value
	 * B0 initial value (specification SP 800-38C) contains flags,
	 * data length (Whole operation length in case of init update final)
	 * and nonce
	 */
	memset(b0, 0, TEE_AES_BLOCK_SIZE);

	/* Available length for the data size length field */
	q = AES_CCM_MAX_NONCE_LEN - dinit->nonce.length;

	/* Flags value in b0[0] */
	b0[0] = B0_TAG_LENGTH(caam_ctx->tag_length) | B0_Q_LENGTH(q);
	if (caam_ctx->aad_length)
		b0[0] |= BM_B0_ADATA_PRESENCE;

	/* Nonce value in b0[1..AES_CCM_MAX_NONCE_LEN] */
	memcpy(&b0[1], dinit->nonce.data, dinit->nonce.length);

	/*
	 * Payload length as defined in SP800-38C,
	 * A.2.1 Formatting of the Control Information and the Nonce
	 * Payload length (i.e. Q) is store in big-endian fashion.
	 */
	for (i = AES_CCM_MAX_NONCE_LEN; i >= dinit->nonce.length + 1; i--) {
		b0[i] = payload_len & 0xFF;
		payload_len >>= 8;
	}

	/* Add AAD size to Adata */
	if (caam_ctx->aad_length > 0) {
		if (caam_ctx->aad_length >= AAD_LENGTH_OVERFLOW)
			return TEE_ERROR_NOT_SUPPORTED;

		retstatus = caam_calloc_align_buf(&aad, AAD_SIZE_LEN);
		if (retstatus)
			return caam_status_to_tee_result(retstatus);

		aad.data[0] = (caam_ctx->aad_length & GENMASK_32(15, 8)) >> 8;
		aad.data[1] = caam_ctx->aad_length & GENMASK_32(7, 0);
		retstatus = caam_cpy_block_src(&caam_ctx->buf_aad, &aad, 0);
		if (retstatus) {
			ret = caam_status_to_tee_result(retstatus);
			goto out;
		}
	}

	/*
	 * Set CTR0 initial value
	 * Ctr0 initial value (specification SP 800-38C) contains flags
	 * and nonce
	 */
	memset(ctr0, 0, TEE_AES_BLOCK_SIZE);

	/* Flags value in ctr0[0] */
	ctr0[0] = B0_Q_LENGTH(q);

	/* Nonce value in ctr0[1..AES_CCM_MAX_NONCE_LEN] */
	memcpy(&ctr0[1], &b0[1], dinit->nonce.length);

	ret = TEE_SUCCESS;
out:
	caam_free_buf(&aad);
	return ret;
}

TEE_Result caam_ae_initialize_ccm(struct drvcrypt_authenc_init *dinit)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	enum caam_status retstatus = CAAM_FAILURE;
	struct caam_ae_ctx *caam_ctx = NULL;

	if (!dinit || !dinit->ctx)
		return TEE_ERROR_BAD_PARAMETERS;

	caam_ctx = dinit->ctx;

	if (caam_ctx->tag_length < AES_CCM_MIN_TAG_LEN ||
	    caam_ctx->tag_length > AES_CCM_MAX_TAG_LEN)
		return TEE_ERROR_NOT_SUPPORTED;

	/* Allocate initial B0 and CTR0 input */
	retstatus = caam_alloc_align_buf(&caam_ctx->initial_ctx,
					 caam_ctx->alg->size_ctx);
	if (retstatus)
		return caam_status_to_tee_result(retstatus);

	/* Initialize the AAD buffer */
	caam_ctx->buf_aad.max = dinit->aad_len + AAD_SIZE_LEN;

	ret = caam_ae_ccm_init_ctx(caam_ctx, dinit);
	if (ret)
		goto err;

	return TEE_SUCCESS;
err:
	caam_free_buf(&caam_ctx->initial_ctx);

	return ret;
}

TEE_Result caam_ae_final_ccm(struct drvcrypt_authenc_final *dfinal)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	struct caam_ae_ctx *caam_ctx = NULL;
	uint8_t *encrypted_tag = NULL;
	struct drvcrypt_mod_op mod_op = { };

	if (!dfinal || !dfinal->ctx)
		return TEE_ERROR_BAD_PARAMETERS;

	caam_ctx = dfinal->ctx;

	ret = caam_ae_do_update(caam_ctx, &dfinal->src, &dfinal->dst, true);
	if (ret)
		return ret;

	if (caam_ctx->tag_length) {
		if (dfinal->tag.length < caam_ctx->tag_length)
			return TEE_ERROR_BAD_PARAMETERS;

		if (caam_ctx->encrypt) {
			encrypted_tag = caam_ctx->ctx.data +
					(2 * AES_CCM_MAX_TAG_LEN);

			memcpy(dfinal->tag.data, encrypted_tag,
			       caam_ctx->tag_length);
			dfinal->tag.length = caam_ctx->tag_length;
		} else {
			encrypted_tag = caam_ctx->ctx.data;

			mod_op.n.length = caam_ctx->tag_length;
			mod_op.a.data = encrypted_tag;
			mod_op.a.length = caam_ctx->tag_length;
			mod_op.b.data = encrypted_tag +
					2 * AES_CCM_MAX_TAG_LEN;
			mod_op.b.length = caam_ctx->tag_length;
			mod_op.result.data = encrypted_tag;
			mod_op.result.length = caam_ctx->tag_length;

			ret = drvcrypt_xor_mod_n(&mod_op);
			if (ret)
				return ret;

			if (consttime_memcmp(dfinal->tag.data, encrypted_tag,
					     caam_ctx->tag_length))
				return TEE_ERROR_MAC_INVALID;
		}
	}

	return TEE_SUCCESS;
}
