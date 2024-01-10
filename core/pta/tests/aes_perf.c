// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020, Linaro Limited
 */

#include <compiler.h>
#include <crypto/crypto.h>
#include <pta_invoke_tests.h>
#include <tee_api_defines.h>
#include <tee_api_types.h>
#include <trace.h>
#include <types_ext.h>
#include <utee_defines.h>

#include "misc.h"

/*
 * These keys and iv are copied from optee_test/ta/aes_perf/ta_aes_perf.c,
 * not because their actual values are important, rather that there's no
 * reason to use different values.
 */

static const uint8_t aes_key[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
};

static const uint8_t aes_key2[] = {
	0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
	0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
	0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F
};

static uint8_t aes_iv[] = {
	0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
	0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF
};

static void free_ctx(void **ctx, uint32_t algo)
{
	if (algo == TEE_ALG_AES_GCM)
		crypto_authenc_free_ctx(*ctx);
	else
		crypto_cipher_free_ctx(*ctx);

	*ctx = NULL;
}

static TEE_Result init_ctx(void **ctx, uint32_t algo, TEE_OperationMode mode,
			   size_t key_size_bits, size_t payload_len)
{
	TEE_Result res = TEE_SUCCESS;
	const uint8_t *key2 = NULL;
	const uint8_t *iv = NULL;
	size_t key2_len = 0;
	size_t key_len = 0;
	size_t iv_len = 0;

	if (key_size_bits % 8)
		return TEE_ERROR_BAD_PARAMETERS;
	key_len = key_size_bits / 8;
	if (key_len > sizeof(aes_key))
		return TEE_ERROR_BAD_PARAMETERS;

	/* Alloc ctx */
	switch (algo) {
	case TEE_ALG_AES_XTS:
		key2_len = key_len;
		key2 = aes_key2;
		fallthrough;
	case TEE_ALG_AES_ECB_NOPAD:
	case TEE_ALG_AES_CBC_NOPAD:
	case TEE_ALG_AES_CTR:
		res = crypto_cipher_alloc_ctx(ctx, algo);
		break;
	case TEE_ALG_AES_GCM:
		res = crypto_authenc_alloc_ctx(ctx, algo);
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
	if (res)
		return res;

	/* Init ctx */
	switch (algo) {
	case TEE_ALG_AES_CBC_NOPAD:
	case TEE_ALG_AES_CTR:
	case TEE_ALG_AES_XTS:
		iv = aes_iv;
		iv_len = sizeof(aes_iv);
		fallthrough;
	case TEE_ALG_AES_ECB_NOPAD:
		res = crypto_cipher_init(*ctx, mode, aes_key, key_len, key2,
					 key2_len, iv, iv_len);
		break;
	case TEE_ALG_AES_GCM:
		res = crypto_authenc_init(*ctx, mode, aes_key, key_len, aes_iv,
					  sizeof(aes_iv), TEE_AES_BLOCK_SIZE,
					  0, payload_len);
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (res)
		free_ctx(ctx, algo);

	return res;
}

static TEE_Result update_ae(void *ctx, TEE_OperationMode mode,
			    const void *src, size_t len, void *dst)
{
	size_t dlen = len;

	return crypto_authenc_update_payload(ctx, mode, src, len, dst, &dlen);
}

static TEE_Result update_cipher(void *ctx, TEE_OperationMode mode,
				const void *src, size_t len, void *dst)
{
	return crypto_cipher_update(ctx, mode, false, src, len, dst);
}

static TEE_Result do_update(void *ctx, uint32_t algo, TEE_OperationMode mode,
			    unsigned int rep_count, unsigned int unit_size,
			    const uint8_t *in, size_t sz, uint8_t *out)
{
	TEE_Result (*update_func)(void *ctx, TEE_OperationMode mode,
				  const void *src, size_t len,
				  void *dst) = NULL;
	TEE_Result res = TEE_SUCCESS;
	unsigned int n = 0;
	unsigned int m = 0;

	if (algo == TEE_ALG_AES_GCM)
		update_func = update_ae;
	else
		update_func = update_cipher;

	for (n = 0; n < rep_count; n++) {
		for (m = 0; m < sz / unit_size; m++) {
			res = update_func(ctx, mode, in + m * unit_size,
					  unit_size, out + m * unit_size);
			if (res)
				return res;
		}
		if (sz % unit_size)
			res = update_func(ctx, mode, in + m * unit_size,
					  sz % unit_size, out + m * unit_size);
	}

	return res;
}

TEE_Result core_aes_perf_tests(uint32_t param_types,
			       TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_MEMREF_INOUT,
						   TEE_PARAM_TYPE_MEMREF_INOUT);
	TEE_Result res = TEE_SUCCESS;
	TEE_OperationMode mode = 0;
	unsigned int rep_count = 0;
	unsigned int unit_size = 0;
	size_t key_size_bits = 0;
	uint32_t algo = 0;
	void *ctx = NULL;

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	switch (params[0].value.b) {
	case PTA_INVOKE_TESTS_AES_ECB:
		algo = TEE_ALG_AES_ECB_NOPAD;
		break;
	case PTA_INVOKE_TESTS_AES_CBC:
		algo = TEE_ALG_AES_CBC_NOPAD;
		break;
	case PTA_INVOKE_TESTS_AES_CTR:
		algo = TEE_ALG_AES_CTR;
		break;
	case PTA_INVOKE_TESTS_AES_XTS:
		algo = TEE_ALG_AES_XTS;
		break;
	case PTA_INVOKE_TESTS_AES_GCM:
		algo = TEE_ALG_AES_GCM;
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (params[0].value.a >> 16)
		mode = TEE_MODE_DECRYPT;
	else
		mode = TEE_MODE_ENCRYPT;

	key_size_bits = params[0].value.a & 0xffff;

	rep_count = params[1].value.a;
	unit_size = params[1].value.b;

	if (params[2].memref.size > params[3].memref.size)
		return TEE_ERROR_BAD_PARAMETERS;

	res = init_ctx(&ctx, algo, mode, key_size_bits, params[2].memref.size);
	if (res)
		return res;

	res = do_update(ctx, algo, mode, rep_count, unit_size,
			params[2].memref.buffer, params[2].memref.size,
			params[3].memref.buffer);

	free_ctx(&ctx, algo);
	return res;
}
