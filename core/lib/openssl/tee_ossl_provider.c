/*
 * Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 *
 * The HMAC and AES-CMAC code below is adapted from OpenSSL. The following
 * notice applies.
 *
 *
 * ====================================================================
 * Copyright (c) 2010 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */

#include <tee/tee_cryp_provider.h>
#include <tee/tee_cryp_utl.h>
#include <kernel/tee_ta_manager_unpg.h>
#include <kernel/tee_core_trace.h>
#include <kernel/util.h>
#include <compiler.h>
#include <utee_defines.h>
#include <openssl/bn.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/dh.h>
#include <openssl/evp.h>

static TEE_Result tee_ossl_init(void)
{
	EVP_add_digest(EVP_md5());
	EVP_add_digest(EVP_sha1());
	EVP_add_digest(EVP_sha224());
	EVP_add_digest(EVP_sha256());
	EVP_add_digest(EVP_sha384());
	EVP_add_digest(EVP_sha512());

	EVP_add_cipher(EVP_aes_128_cbc());
	EVP_add_cipher(EVP_aes_128_ccm());
	EVP_add_cipher(EVP_aes_128_ctr());
	EVP_add_cipher(EVP_aes_128_ecb());
	EVP_add_cipher(EVP_aes_128_gcm());
	EVP_add_cipher(EVP_aes_128_xts());
	EVP_add_cipher(EVP_aes_192_cbc());
	EVP_add_cipher(EVP_aes_192_ccm());
	EVP_add_cipher(EVP_aes_192_ctr());
	EVP_add_cipher(EVP_aes_192_ecb());
	EVP_add_cipher(EVP_aes_192_gcm());
	EVP_add_cipher(EVP_aes_256_cbc());
	EVP_add_cipher(EVP_aes_256_ccm());
	EVP_add_cipher(EVP_aes_256_ctr());
	EVP_add_cipher(EVP_aes_256_ecb());
	EVP_add_cipher(EVP_aes_256_gcm());
	EVP_add_cipher(EVP_aes_256_xts());
	EVP_add_cipher(EVP_des_cbc());
	EVP_add_cipher(EVP_des_ecb());
	EVP_add_cipher(EVP_des_ede3_cbc());
	EVP_add_cipher(EVP_des_ede3_ecb());
	EVP_add_cipher(EVP_des_ede_cbc());
	EVP_add_cipher(EVP_des_ede_ecb());

	return TEE_SUCCESS;
}


/******************************************************************************
 * Message digest functions
 ******************************************************************************/

static int hash_supported(uint32_t algo)
{
	switch (algo) {
	case TEE_ALG_MD5:
	case TEE_ALG_SHA1:
	case TEE_ALG_SHA224:
	case TEE_ALG_SHA256:
	case TEE_ALG_SHA384:
	case TEE_ALG_SHA512:
		return 1;
	default:
		return 0;
	}
}

static size_t hash_get_blocksize(uint32_t algo)
{
	switch (algo) {
	case TEE_ALG_MD5:
	case TEE_ALG_SHA1:
	case TEE_ALG_SHA224:
	case TEE_ALG_SHA256:
		return 64;
	case TEE_ALG_SHA384:
	case TEE_ALG_SHA512:
		return 128;
	default:
		return 0;
	}
}

static TEE_Result hash_get_ctx_size(uint32_t algo, size_t *size)
{
	if (!hash_supported(algo))
		return TEE_ERROR_NOT_SUPPORTED;

	*size = sizeof(EVP_MD_CTX);

	return TEE_SUCCESS;
}

static TEE_Result hash_init(void *ctx, uint32_t algo)
{
	int st;
	const struct env_md_st *md;

	switch (algo) {
	case TEE_ALG_MD5:
		md = EVP_md5();
		break;
	case TEE_ALG_SHA1:
		md = EVP_sha1();
		break;
	case TEE_ALG_SHA224:
		md = EVP_sha224();
		break;
	case TEE_ALG_SHA256:
		md = EVP_sha256();
		break;
	case TEE_ALG_SHA384:
		md = EVP_sha384();
		break;
	case TEE_ALG_SHA512:
		md = EVP_sha512();
		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	st = EVP_DigestInit(ctx, md);
	if (st != 1)
		return TEE_ERROR_BAD_STATE;

	return TEE_SUCCESS;
}

static TEE_Result hash_update(void *ctx, uint32_t algo, const uint8_t *data,
			      size_t len)
{
	int st;

	if (!hash_supported(algo))
		return TEE_ERROR_NOT_SUPPORTED;

	st = EVP_DigestUpdate(ctx, data, len);

	return (st == 1) ? TEE_SUCCESS : TEE_ERROR_BAD_STATE;
}

static TEE_Result hash_final(void *ctx, uint32_t algo, uint8_t *digest,
			     size_t len)
{
	int st;
	size_t hash_size;
	uint8_t buf[64], *out;

	if (!hash_supported(algo))
		return TEE_ERROR_NOT_SUPPORTED;
	if (tee_hash_get_digest_size(algo, &hash_size) != TEE_SUCCESS)
		return TEE_ERROR_NOT_SUPPORTED;

	if ((len == 0) || (hash_size < len) || (hash_size > sizeof(buf)))
		return TEE_ERROR_BAD_PARAMETERS;

	out = (hash_size > len) ? buf : digest;

	st = EVP_DigestFinal(ctx, out, NULL);
	if (st != 1)
		return TEE_ERROR_BAD_STATE;

	if (hash_size > len)
		memcpy(digest, out, len);

	return TEE_SUCCESS;
}


/******************************************************************************
 * Symmetric ciphers
 ******************************************************************************/

struct aes_cts_ctx {
	EVP_CIPHER_CTX ecb;
	EVP_CIPHER_CTX cbc;
};

static int cipher_supported(uint32_t algo)
{
	switch (algo) {
	case TEE_ALG_AES_ECB_NOPAD:
	case TEE_ALG_AES_CBC_NOPAD:
	case TEE_ALG_AES_CTR:
	case TEE_ALG_AES_CTS:
	case TEE_ALG_DES_ECB_NOPAD:
	case TEE_ALG_DES_CBC_NOPAD:
	case TEE_ALG_DES3_ECB_NOPAD:
	case TEE_ALG_DES3_CBC_NOPAD:
	case TEE_ALG_AES_XTS:
		return 1;
	default:
		return 0;
	}
}

static TEE_Result cipher_get_ctx_size(uint32_t algo, size_t *size)
{
	switch (algo) {
	case TEE_ALG_AES_ECB_NOPAD:
	case TEE_ALG_AES_CBC_NOPAD:
	case TEE_ALG_AES_CTR:
	case TEE_ALG_DES_ECB_NOPAD:
	case TEE_ALG_DES_CBC_NOPAD:
	case TEE_ALG_DES3_ECB_NOPAD:
	case TEE_ALG_DES3_CBC_NOPAD:
	case TEE_ALG_AES_XTS:
		*size = sizeof(EVP_CIPHER_CTX);
		break;
	case TEE_ALG_AES_CTS:
		*size = sizeof(struct aes_cts_ctx);
		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
}

static TEE_Result cipher_init(void *ctx, uint32_t algo, TEE_OperationMode mode,
			      const uint8_t *key1, size_t key1_len,
			      const uint8_t *key2, size_t key2_len,
			      const uint8_t *iv, size_t iv_len)
{
	int st;
	TEE_Result tres;
	struct aes_cts_ctx *acts;
	const struct evp_cipher_st *cipher;
	uint8_t *key = (uint8_t *)key1;

	switch (algo) {
	case TEE_ALG_AES_ECB_NOPAD:
		if (key1_len == 16)
			cipher = EVP_aes_128_ecb();
		else if (key1_len == 24)
			cipher = EVP_aes_192_ecb();
		else if (key1_len == 32)
			cipher = EVP_aes_256_ecb();
		else
			return TEE_ERROR_NOT_SUPPORTED;
		break;
	case TEE_ALG_AES_CBC_NOPAD:
		if (key1_len == 16)
			cipher = EVP_aes_128_cbc();
		else if (key1_len == 24)
			cipher = EVP_aes_192_cbc();
		else if (key1_len == 32)
			cipher = EVP_aes_256_cbc();
		else
			return TEE_ERROR_NOT_SUPPORTED;
		break;
	case TEE_ALG_AES_CTR:
		if (key1_len == 16)
			cipher = EVP_aes_128_ctr();
		else if (key1_len == 24)
			cipher = EVP_aes_192_ctr();
		else if (key1_len == 32)
			cipher = EVP_aes_256_ctr();
		else
			return TEE_ERROR_NOT_SUPPORTED;
		break;
	case TEE_ALG_AES_CTS:
		acts = ctx;
		tres = cipher_init(&acts->ecb, TEE_ALG_AES_ECB_NOPAD, mode,
				   key1, key1_len, key2, key2_len, iv, iv_len);
		if (tres != TEE_SUCCESS)
			return tres;
		tres = cipher_init(&acts->cbc, TEE_ALG_AES_CBC_NOPAD, mode,
				   key1, key1_len, key2, key2_len, iv, iv_len);
		if (tres != TEE_SUCCESS)
			return tres;
		return TEE_SUCCESS;
	case TEE_ALG_DES_ECB_NOPAD:
		cipher = EVP_des_ecb();
		break;
	case TEE_ALG_DES_CBC_NOPAD:
		cipher = EVP_des_cbc();
		break;
	case TEE_ALG_DES3_ECB_NOPAD:
		if (key1_len == 16) {
			/* 2-DES */
			cipher = EVP_des_ede_ecb();
		} else if (key1_len == 24) {
			/* 3-DES */
			cipher = EVP_des_ede3_ecb();
		} else {
			return TEE_ERROR_NOT_SUPPORTED;
		}
		break;
	case TEE_ALG_DES3_CBC_NOPAD:
		if (key1_len == 16) {
			/* 2-DES */
			cipher = EVP_des_ede_cbc();
		} else if (key1_len == 24) {
			/* 3-DES */
			cipher = EVP_des_ede3_cbc();
		} else {
			return TEE_ERROR_NOT_SUPPORTED;
		}
		break;
	case TEE_ALG_AES_XTS:
		if (key1_len == 16)
			cipher = EVP_aes_128_xts();
		else if (key1_len == 32)
			cipher = EVP_aes_256_xts();
		else
			return TEE_ERROR_NOT_SUPPORTED;
		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	if (algo == TEE_ALG_AES_XTS) {
		key = malloc(key1_len + key2_len);
		if (!key)
			return TEE_ERROR_OUT_OF_MEMORY;
		memcpy(key, key1, key1_len);
		memcpy(key + key1_len, key2, key2_len);
	}

	if (mode == TEE_MODE_ENCRYPT)
		st = EVP_EncryptInit(ctx, cipher, key, iv);
	else
		st = EVP_DecryptInit(ctx, cipher, key, iv);

	if (algo == TEE_ALG_AES_XTS)
		free(key);

	if (st != 1)
		return TEE_ERROR_BAD_STATE;

	st = EVP_CIPHER_CTX_set_padding(ctx, 0);
	if (st != 1)
		return TEE_ERROR_BAD_STATE;

	return TEE_SUCCESS;
}

static TEE_Result cipher_update(void *ctx, uint32_t algo,
				TEE_OperationMode mode,
				bool last_block, const uint8_t *data,
				size_t len, uint8_t *dst)
{
	struct aes_cts_ctx *acts;
	int st;
	int outl = 0;

	if (!cipher_supported(algo))
		return TEE_ERROR_NOT_SUPPORTED;

	if (algo == TEE_ALG_AES_CTS) {
		acts = ctx;
		return tee_aes_cbc_cts_update(&acts->cbc, &acts->ecb, mode,
					      last_block, data, len, dst);
	}

	if (mode == TEE_MODE_ENCRYPT) {
		st = EVP_EncryptUpdate(ctx, dst, &outl, data, len);
		if (st != 1)
			return TEE_ERROR_BAD_STATE;
		if (last_block) {
			st = EVP_EncryptFinal(ctx, dst + outl, &outl);
			if (st != 1)
				return TEE_ERROR_BAD_STATE;
		}
	} else {
		st = EVP_DecryptUpdate(ctx, dst, &outl, data, len);
		if (st != 1)
			return TEE_ERROR_BAD_STATE;
		if (last_block) {
			st = EVP_DecryptFinal(ctx, dst + outl, &outl);
			if (st != 1)
				return TEE_ERROR_BAD_STATE;
		}
	}
	if (st != 1)
		return TEE_ERROR_BAD_STATE;

	return TEE_SUCCESS;
}

static void cipher_final(void *ctx, uint32_t algo __unused)
{
	(void)EVP_CIPHER_CTX_cleanup(ctx);
}

/*****************************************************************************
 * Message Authentication Code functions
 *****************************************************************************/

/*
 * The hmac_* functions below are heavily inspired from OpenSSL's HMAC_*
 * functions. We don't use the OpenSSL ones because they bring in too many
 * dependencies due to the EVP* stuff.
 */
#define HMAC_MAX_BLOCKSIZE 128  /* Largest block size is SHA512 */

#define HASH_CTX_MAX_SIZE sizeof(EVP_MD_CTX)

struct hmac_ctx {
	uint8_t key[HMAC_MAX_BLOCKSIZE];
	size_t keylen;
	uint8_t ctx[HASH_CTX_MAX_SIZE];
	uint8_t i_ctx[HASH_CTX_MAX_SIZE];
	uint8_t o_ctx[HASH_CTX_MAX_SIZE];
};

static int32_t hmac_get_base_algo(int32_t algo)
{
	switch (algo) {
	case TEE_ALG_HMAC_MD5:
		return TEE_ALG_MD5;
	case TEE_ALG_HMAC_SHA1:
		return TEE_ALG_SHA1;
	case TEE_ALG_HMAC_SHA224:
		return TEE_ALG_SHA224;
	case TEE_ALG_HMAC_SHA256:
		return TEE_ALG_SHA256;
	case TEE_ALG_HMAC_SHA384:
		return TEE_ALG_SHA384;
	case TEE_ALG_HMAC_SHA512:
		return TEE_ALG_SHA512;
	default:
		return 0;
	}
}

static TEE_Result hmac_init(void *ctx, int32_t algo, const uint8_t *key,
			    size_t keylen)
{
	TEE_Result res;
	struct hmac_ctx *h_ctx;
	uint32_t h_alg;
	size_t blocksize, i;
	uint8_t pad[HMAC_MAX_BLOCKSIZE];

	h_ctx = ctx;
	memset(h_ctx, 0, sizeof(*h_ctx));

	h_alg = hmac_get_base_algo(algo);
	blocksize = hash_get_blocksize(h_alg);
	if (blocksize == 0) {
		res = TEE_ERROR_BAD_STATE;
		goto err;
	}

	if (keylen > blocksize) {
		/* Key shall be shortened by hashing */
		res = hash_init(h_ctx->ctx, h_alg);
		if (res != TEE_SUCCESS)
			goto err;
		res = hash_update(h_ctx->ctx, h_alg, key, keylen);
		if (res != TEE_SUCCESS)
			goto err;
		res = hash_final(h_ctx->ctx, h_alg, h_ctx->key,
				 sizeof(h_ctx->key));
		if (res != TEE_SUCCESS)
			goto err;
		res = tee_hash_get_digest_size(algo, &h_ctx->keylen);
		if (res != TEE_SUCCESS)
			goto err;
	}
	if (keylen < blocksize) {
		/* Key shall be zero-padded (already done by above memset) */
		memcpy(h_ctx->key, key, keylen);
		h_ctx->keylen = keylen;
	}

	for (i = 0; i < HMAC_MAX_BLOCKSIZE; i++)
		pad[i] = 0x36 ^ h_ctx->key[i];
	res = hash_init(h_ctx->i_ctx, h_alg);
	if (res != TEE_SUCCESS)
		goto err;
	res = hash_update(h_ctx->i_ctx, h_alg, pad, blocksize);
	if (res != TEE_SUCCESS)
		goto err;

	for (i = 0; i < HMAC_MAX_BLOCKSIZE; i++)
		pad[i] = 0x5c ^ h_ctx->key[i];
	res = hash_init(h_ctx->o_ctx, h_alg);
	if (res != TEE_SUCCESS)
		goto err;
	res = hash_update(h_ctx->o_ctx, h_alg, pad, blocksize);
	if (res != TEE_SUCCESS)
		goto err;

	/*
	 * This assumes that hash contexts are self-contained
	 * (which is the case for OpenSSL's MD5_CTX/SHA_CTX etc.)
	 */
	memcpy(h_ctx->ctx, h_ctx->i_ctx, sizeof(h_ctx->ctx));
	res = TEE_SUCCESS;

err:
	return res;
}

static TEE_Result hmac_update(void *ctx, uint32_t algo, const uint8_t *data,
			      size_t len)
{
	struct hmac_ctx *hctx = ctx;

	return hash_update(hctx->ctx, hmac_get_base_algo(algo), data, len);
}

static TEE_Result hmac_final(void *ctx, uint32_t algo, const uint8_t *data,
			     size_t data_len, uint8_t *digest,
			     size_t digest_len)
{
	TEE_Result res;
	uint32_t h_alg;
	struct hmac_ctx *h_ctx;
	size_t h_size;
	uint8_t buf[HMAC_MAX_BLOCKSIZE];

	if (data && data_len) {
		res = hmac_update(ctx, algo, data, data_len);
		if (res != TEE_SUCCESS)
			goto err;
	}
	h_ctx = ctx;
	h_alg = hmac_get_base_algo(algo);
	res = tee_hash_get_digest_size(algo, &h_size);
	if (res != TEE_SUCCESS)
		goto err;
	if (h_size > sizeof(buf)) {
		res = TEE_ERROR_BAD_STATE;
		goto err;
	}
	res = hash_final(h_ctx->ctx, h_alg, buf, h_size);
	if (res != TEE_SUCCESS)
		goto err;
	memcpy(h_ctx->ctx, h_ctx->o_ctx, sizeof(h_ctx->ctx));
	res = hash_update(h_ctx->ctx, h_alg, buf, h_size);
	if (res != TEE_SUCCESS)
		goto err;
	res = hash_final(h_ctx->ctx, h_alg, digest, digest_len);
err:
	return res;
}

/*
 * AES/DES/DES3 CBC-MAC code is based on the tee_ltc_provider.c implementation.
 * This code could be slightly refactored and moved to tee_svc_cryp.c. The only
 * difficulty is to deal with the size of the CBC contexts which are not
 * statically known at compile time in tee_svc_cryp.c.
 */

#define CBCMAC_MAX_BLOCK_LEN 16
struct cbc_mac_ctx {
	EVP_CIPHER_CTX cipher_ctx;
	uint8_t block[CBCMAC_MAX_BLOCK_LEN];
	uint8_t digest[CBCMAC_MAX_BLOCK_LEN];
	size_t current_block_len, block_len;
	int is_computed;
};

static uint32_t cbc_mac_get_base_algo(uint32_t algo)
{
	switch (algo) {
	case TEE_ALG_AES_CBC_MAC_NOPAD:
	case TEE_ALG_AES_CBC_MAC_PKCS5:
		return TEE_ALG_AES_CBC_NOPAD;
	case TEE_ALG_DES_CBC_MAC_NOPAD:
	case TEE_ALG_DES_CBC_MAC_PKCS5:
		return TEE_ALG_DES_CBC_NOPAD;
	case TEE_ALG_DES3_CBC_MAC_NOPAD:
	case TEE_ALG_DES3_CBC_MAC_PKCS5:
		return TEE_ALG_DES3_CBC_NOPAD;
	default:
		break;
	}
	return 0;
}

static TEE_Result cbc_mac_init(void *ctx, uint32_t algo, const uint8_t *key,
			       size_t len)
{
	TEE_Result res;
	uint32_t c_alg;
	struct cbc_mac_ctx *cbc_mac;
	uint8_t iv[CBCMAC_MAX_BLOCK_LEN];

	cbc_mac = ctx;
	memset(cbc_mac, 0, sizeof(*cbc_mac));
	c_alg = cbc_mac_get_base_algo(algo);
	res = tee_cipher_get_block_size(c_alg, &cbc_mac->block_len);
	if (res != TEE_SUCCESS)
		goto err;
	if (cbc_mac->block_len > CBCMAC_MAX_BLOCK_LEN) {
		res = TEE_ERROR_BAD_STATE;
		goto err;
	}
	memset(iv, 0, cbc_mac->block_len);
	res = cipher_init(&cbc_mac->cipher_ctx, c_alg, TEE_MODE_ENCRYPT, key,
			  len, NULL, 0, iv, cbc_mac->block_len);
err:
	return res;
}

static TEE_Result cbc_mac_update(void *ctx, uint32_t algo, const uint8_t *data,
				 size_t len)
{
	TEE_Result res;
	uint32_t c_alg;
	struct cbc_mac_ctx *cbc;
	size_t pad_len;

	cbc = ctx;
	c_alg = cbc_mac_get_base_algo(algo);

	if ((cbc->current_block_len > 0) &&
	    (len + cbc->current_block_len >= cbc->block_len)) {
		pad_len = cbc->block_len - cbc->current_block_len;
		memcpy(cbc->block + cbc->current_block_len,
		       data, pad_len);
		data += pad_len;
		len -= pad_len;
		res = cipher_update(&cbc->cipher_ctx, c_alg, TEE_MODE_ENCRYPT,
				    0, cbc->block, cbc->block_len,
				    cbc->digest);
		if (res != TEE_SUCCESS)
			return TEE_ERROR_BAD_STATE;
		cbc->is_computed = 1;
	}

	while (len >= cbc->block_len) {
		res = cipher_update(&cbc->cipher_ctx, c_alg, TEE_MODE_ENCRYPT,
				    0, data, cbc->block_len, cbc->digest);
		if (res != TEE_SUCCESS)
			return TEE_ERROR_BAD_STATE;
		cbc->is_computed = 1;
		data += cbc->block_len;
		len -= cbc->block_len;
	}

	if (len > 0)
		memcpy(cbc->block, data, len);

	cbc->current_block_len = len;

	res = TEE_SUCCESS;
	return res;
}

static TEE_Result cbc_mac_final(void *ctx, uint32_t algo, const uint8_t *data,
				size_t data_len, uint8_t *digest,
				size_t digest_len)
{
	struct cbc_mac_ctx *cbc;
	size_t pad_len;

	cbc = ctx;
	if (cbc_mac_update(ctx, algo, data, data_len) != TEE_SUCCESS)
		return TEE_ERROR_BAD_STATE;

	switch (algo) {
	case TEE_ALG_AES_CBC_MAC_PKCS5:
	case TEE_ALG_DES_CBC_MAC_PKCS5:
	case TEE_ALG_DES3_CBC_MAC_PKCS5:
		/*
		 * Add PKCS5 padding. The value of each added byte is the
		 * number of bytes that are added, i.e., append '0x01' when 1
		 * byte is needed, '0x02 0x02' when two bytes are needed, etc.
		 */
		pad_len = cbc->block_len - cbc->current_block_len;
		memset(cbc->block+cbc->current_block_len, pad_len, pad_len);
		cbc->current_block_len = 0;
		if (cbc_mac_update(ctx, algo, cbc->block, cbc->block_len)
				!= TEE_SUCCESS)
			return TEE_ERROR_BAD_STATE;
		break;
	default:
		/* No padding is required */
		break;
	}

	if ((!cbc->is_computed) || (cbc->current_block_len != 0))
		return TEE_ERROR_BAD_STATE;

	memcpy(digest, cbc->digest, MIN(digest_len, cbc->block_len));
	cipher_final(&cbc->cipher_ctx, algo);

	return TEE_SUCCESS;
}

/*
 * cmac_*: AES-CMAC, adapted from OpenSSL's CMAC_* implementation
 */
struct cmac_aes_cbc_ctx {
	EVP_CIPHER_CTX cipher_ctx;
	uint8_t k1[AES_BLOCK_SIZE], k2[AES_BLOCK_SIZE];
	uint8_t tbl[AES_BLOCK_SIZE];
	uint8_t last_block[AES_BLOCK_SIZE];
	ssize_t nlast_block;
};

/* Make temporary keys k1 and k2 */
static void cmac_make_kn(uint8_t *k1, uint8_t *l, size_t bl)
{
	size_t i;
	/* Shift block to left, including carry */
	for (i = 0; i < bl; i++) {
		k1[i] = l[i] << 1;
		if (i < bl - 1 && l[i + 1] & 0x80)
			k1[i] |= 1;
	}
	/* If MSB set fixup with R */
	if (l[0] & 0x80)
		k1[bl - 1] ^= bl == 16 ? 0x87 : 0x1b;
}

static TEE_Result cmac_aes_cbc_init(void *ctx, const uint8_t *key,
				    size_t keylen)
{
	TEE_Result res;
	struct cmac_aes_cbc_ctx *c_ctx;
	static uint8_t zero_iv[AES_BLOCK_SIZE];
	const size_t bl = AES_BLOCK_SIZE;


	c_ctx = ctx;
	memset(c_ctx, 0, sizeof(*c_ctx));
	res = cipher_init(&c_ctx->cipher_ctx, TEE_ALG_AES_CBC_NOPAD,
			  TEE_MODE_ENCRYPT, key, keylen, NULL, 0, zero_iv,
			  sizeof(zero_iv));
	if (res != TEE_SUCCESS)
		goto err;
	res = cipher_update(&c_ctx->cipher_ctx, TEE_ALG_AES_CBC_NOPAD,
			    TEE_MODE_ENCRYPT, false, zero_iv, sizeof(zero_iv),
			    c_ctx->tbl);
	if (res != TEE_SUCCESS)
		goto err;
	cmac_make_kn(c_ctx->k1, c_ctx->tbl, bl);
	cmac_make_kn(c_ctx->k2, c_ctx->k1, bl);
	memset(c_ctx->tbl, 0, bl);
	/* Reset context again, ready for first data block */
	res = cipher_init(&c_ctx->cipher_ctx, TEE_ALG_AES_CBC_NOPAD,
			  TEE_MODE_ENCRYPT, key, keylen, NULL, 0, zero_iv,
			  sizeof(zero_iv));
	if (res != TEE_SUCCESS)
		goto err;
	c_ctx->nlast_block = 0;
err:
	return res;
}

static TEE_Result cmac_aes_cbc_update(void *ctx, const uint8_t *in,
				      size_t dlen)
{
	TEE_Result res;
	struct cmac_aes_cbc_ctx *c_ctx = ctx;
	const size_t bl = AES_BLOCK_SIZE;
	const uint8_t *data = in;

	if (c_ctx->nlast_block == -1)
		return TEE_ERROR_BAD_STATE;
	if (dlen == 0)
		return TEE_SUCCESS;
	/* Copy into partial block if we need to */
	if (c_ctx->nlast_block > 0) {
		size_t nleft;

		nleft = bl - c_ctx->nlast_block;
		if (dlen < nleft)
			nleft = dlen;
		memcpy(c_ctx->last_block + c_ctx->nlast_block, data, nleft);
		dlen -= nleft;
		c_ctx->nlast_block += nleft;
		/* If no more to process return */
		if (dlen == 0)
			return TEE_SUCCESS;
		data += nleft;
		/* Else not final block so encrypt it */
		res = cipher_update(&c_ctx->cipher_ctx, TEE_ALG_AES_CBC_NOPAD,
				    TEE_MODE_ENCRYPT, false, c_ctx->last_block,
				    bl, c_ctx->tbl);
		if (res != TEE_SUCCESS)
			return res;
	}
	/* Encrypt all but one of the complete blocks left */
	while (dlen > bl) {
		res = cipher_update(&c_ctx->cipher_ctx, TEE_ALG_AES_CBC_NOPAD,
				    TEE_MODE_ENCRYPT, false, data,
				    bl, c_ctx->tbl);
		if (res != TEE_SUCCESS)
			return res;
		dlen -= bl;
		data += bl;
	}
	/* Copy any data left to last block buffer */
	memcpy(c_ctx->last_block, data, dlen);
	c_ctx->nlast_block = dlen;

	return TEE_SUCCESS;
}

static TEE_Result cmac_aes_cbc_final(void *ctx, const uint8_t *data,
				     size_t data_len, uint8_t *digest,
				     size_t digest_len __unused)
{
	TEE_Result res;
	struct cmac_aes_cbc_ctx *c_ctx = ctx;
	const size_t bl = AES_BLOCK_SIZE;
	size_t i, lb;

	if (data && data_len) {
		res = cmac_aes_cbc_update(ctx, data, data_len);
		if (res != TEE_SUCCESS)
			return res;
	}
	if (c_ctx->nlast_block == -1)
		return TEE_ERROR_BAD_STATE;
	lb = c_ctx->nlast_block;
	/* Is last block complete? */
	if (lb == bl) {
		for (i = 0; i < bl; i++)
			digest[i] = c_ctx->last_block[i] ^ c_ctx->k1[i];
	} else {
		c_ctx->last_block[lb] = 0x80;
		if (bl - lb > 1)
			memset(c_ctx->last_block + lb + 1, 0, bl - lb - 1);
		for (i = 0; i < bl; i++)
			digest[i] = c_ctx->last_block[i] ^ c_ctx->k2[i];
	}
	res = cipher_update(&c_ctx->cipher_ctx, TEE_ALG_AES_CBC_NOPAD,
			    TEE_MODE_ENCRYPT, false, digest, bl, digest);
	if (res != TEE_SUCCESS) {
		memset(digest, 0, bl);
		return res;
	}
	return TEE_SUCCESS;
}

static TEE_Result mac_get_ctx_size(uint32_t algo, size_t *size)
{
	switch (algo) {
	case TEE_ALG_HMAC_MD5:
	case TEE_ALG_HMAC_SHA224:
	case TEE_ALG_HMAC_SHA1:
	case TEE_ALG_HMAC_SHA256:
	case TEE_ALG_HMAC_SHA384:
	case TEE_ALG_HMAC_SHA512:
		*size = sizeof(struct hmac_ctx);
		break;
	case TEE_ALG_AES_CBC_MAC_NOPAD:
	case TEE_ALG_AES_CBC_MAC_PKCS5:
	case TEE_ALG_DES_CBC_MAC_NOPAD:
	case TEE_ALG_DES_CBC_MAC_PKCS5:
	case TEE_ALG_DES3_CBC_MAC_NOPAD:
	case TEE_ALG_DES3_CBC_MAC_PKCS5:
		*size = sizeof(struct cbc_mac_ctx);
		break;
	case TEE_ALG_AES_CMAC:
		*size = sizeof(struct cmac_aes_cbc_ctx);
		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
}

static TEE_Result mac_init(void *ctx, uint32_t algo, const uint8_t *key,
			   size_t len)
{
	switch (algo) {
	case TEE_ALG_HMAC_MD5:
	case TEE_ALG_HMAC_SHA224:
	case TEE_ALG_HMAC_SHA1:
	case TEE_ALG_HMAC_SHA256:
	case TEE_ALG_HMAC_SHA384:
	case TEE_ALG_HMAC_SHA512:
		return hmac_init(ctx, algo, key, len);
	case TEE_ALG_AES_CBC_MAC_NOPAD:
	case TEE_ALG_AES_CBC_MAC_PKCS5:
	case TEE_ALG_DES_CBC_MAC_NOPAD:
	case TEE_ALG_DES_CBC_MAC_PKCS5:
	case TEE_ALG_DES3_CBC_MAC_NOPAD:
	case TEE_ALG_DES3_CBC_MAC_PKCS5:
		return cbc_mac_init(ctx, algo, key, len);
	case TEE_ALG_AES_CMAC:
		return cmac_aes_cbc_init(ctx, key, len);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

static TEE_Result mac_update(void *ctx, uint32_t algo, const uint8_t *data,
			     size_t len)
{
	switch (algo) {
	case TEE_ALG_HMAC_MD5:
	case TEE_ALG_HMAC_SHA224:
	case TEE_ALG_HMAC_SHA1:
	case TEE_ALG_HMAC_SHA256:
	case TEE_ALG_HMAC_SHA384:
	case TEE_ALG_HMAC_SHA512:
		return hmac_update(ctx, algo, data, len);
	case TEE_ALG_AES_CBC_MAC_NOPAD:
	case TEE_ALG_AES_CBC_MAC_PKCS5:
	case TEE_ALG_DES_CBC_MAC_NOPAD:
	case TEE_ALG_DES_CBC_MAC_PKCS5:
	case TEE_ALG_DES3_CBC_MAC_NOPAD:
	case TEE_ALG_DES3_CBC_MAC_PKCS5:
		return cbc_mac_update(ctx, algo, data, len);
	case TEE_ALG_AES_CMAC:
		return cmac_aes_cbc_update(ctx, data, len);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

static TEE_Result mac_final(void *ctx, uint32_t algo, const uint8_t *data,
			    size_t data_len, uint8_t *digest,
			    size_t digest_len)
{
	switch (algo) {
	case TEE_ALG_HMAC_MD5:
	case TEE_ALG_HMAC_SHA224:
	case TEE_ALG_HMAC_SHA1:
	case TEE_ALG_HMAC_SHA256:
	case TEE_ALG_HMAC_SHA384:
	case TEE_ALG_HMAC_SHA512:
		return hmac_final(ctx, algo, data, data_len, digest,
				  digest_len);
	case TEE_ALG_AES_CBC_MAC_NOPAD:
	case TEE_ALG_AES_CBC_MAC_PKCS5:
	case TEE_ALG_DES_CBC_MAC_NOPAD:
	case TEE_ALG_DES_CBC_MAC_PKCS5:
	case TEE_ALG_DES3_CBC_MAC_NOPAD:
	case TEE_ALG_DES3_CBC_MAC_PKCS5:
		return cbc_mac_final(ctx, algo, data, data_len, digest,
				     digest_len);
	case TEE_ALG_AES_CMAC:
		return cmac_aes_cbc_final(ctx, data, data_len, digest,
					  digest_len);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

/******************************************************************************
 * Big numbers
 ******************************************************************************/

static size_t num_bytes(struct bignum *a)
{
	return BN_num_bytes((const struct bignum_st *)a);
}

static void bn2bin(const struct bignum *from, uint8_t *to)
{
	BN_bn2bin((const struct bignum_st *)from, to);
}

static TEE_Result bin2bn(const uint8_t *from, size_t fromsize,
			 struct bignum *to)
{
	if (BN_bin2bn(from, fromsize, (struct bignum_st *)to))
		return TEE_SUCCESS;
	/*
	 * The only error situation is when struct bignum_st storage cannot be
	 * expanded.
	 */
	return TEE_ERROR_OUT_OF_MEMORY;
}

static void bn_copy(struct bignum *to, const struct bignum *from)
{
	BN_copy((struct bignum_st *)to, (const struct bignum_st *)from);
}

static struct bignum *bn_allocate(size_t size_bits __unused)
{
	return (struct bignum *)BN_new();
}

static void bn_free(struct bignum *s)
{
	BN_free((struct bignum_st *)s);
}


static TEE_Result alloc_rsa_keypair(struct rsa_keypair *s,
				    size_t key_size_bits __unused)
{
	memset(s, 0, sizeof(*s));
	s->e = (struct bignum *)BN_new();
	if (!s->e)
		return TEE_ERROR_OUT_OF_MEMORY;
	s->d = (struct bignum *)BN_new();
	if (!s->d)
		goto err;
	s->n = (struct bignum *)BN_new();
	if (!s->n)
		goto err;
	s->p = (struct bignum *)BN_new();
	if (!s->p)
		goto err;
	BN_set_word((struct bignum_st *)s->p, 0);
	s->q = (struct bignum *)BN_new();
	if (!s->q)
		goto err;
	s->qp = (struct bignum *)BN_new();
	if (!s->qp)
		goto err;
	s->dp = (struct bignum *)BN_new();
	if (!s->dp)
		goto err;
	s->dq = (struct bignum *)BN_new();
	if (!s->dq)
		goto err;
	return TEE_SUCCESS;
err:
	free(s->e);
	free(s->d);
	free(s->n);
	free(s->p);
	free(s->q);
	free(s->qp);
	free(s->dp);
	return TEE_ERROR_OUT_OF_MEMORY;
}

static TEE_Result alloc_rsa_public_key(struct rsa_public_key *s,
				       size_t key_size_bits __unused)
{
	memset(s, 0, sizeof(*s));
	s->e = (struct bignum *)BN_new();
	if (!s->e)
		return TEE_ERROR_OUT_OF_MEMORY;
	s->n = (struct bignum *)BN_new();
	if (!s->n)
		goto err;
	return TEE_SUCCESS;
err:
	free(s->e);
	return TEE_ERROR_OUT_OF_MEMORY;
}

static TEE_Result alloc_dsa_keypair(struct dsa_keypair *s,
				    size_t key_size_bits __unused)
{
	memset(s, 0, sizeof(*s));
	s->g = (struct bignum *)BN_new();
	if (!s->g)
		return TEE_ERROR_OUT_OF_MEMORY;
	s->p = (struct bignum *)BN_new();
	if (!s->p)
		goto err;
	s->q = (struct bignum *)BN_new();
	if (!s->q)
		goto err;
	s->y = (struct bignum *)BN_new();
	if (!s->y)
		goto err;
	s->x = (struct bignum *)BN_new();
	if (!s->x)
		goto err;
	return TEE_SUCCESS;
err:
	free(s->g);
	free(s->p);
	free(s->q);
	free(s->y);
	return TEE_ERROR_OUT_OF_MEMORY;
}

static TEE_Result alloc_dsa_public_key(struct dsa_public_key *s,
				       size_t key_size_bits __unused)
{
	memset(s, 0, sizeof(*s));
	s->g = (struct bignum *)BN_new();
	if (!s->g)
		return TEE_ERROR_OUT_OF_MEMORY;
	s->p = (struct bignum *)BN_new();
	if (!s->p)
		goto err;
	s->q = (struct bignum *)BN_new();
	if (!s->q)
		goto err;
	s->y = (struct bignum *)BN_new();
	if (!s->y)
		goto err;
	return TEE_SUCCESS;
err:
	free(s->g);
	free(s->p);
	free(s->q);
	return TEE_ERROR_OUT_OF_MEMORY;
}

static TEE_Result alloc_dh_keypair(struct dh_keypair *s,
				   size_t key_size_bits __unused)
{
	memset(s, 0, sizeof(*s));
	s->g = (struct bignum *)BN_new();
	if (!s->g)
		return TEE_ERROR_OUT_OF_MEMORY;
	s->p = (struct bignum *)BN_new();
	if (!s->p)
		goto err;
	s->x = (struct bignum *)BN_new();
	if (!s->x)
		goto err;
	s->y = (struct bignum *)BN_new();
	if (!s->y)
		goto err;
	s->q = (struct bignum *)BN_new();
	if (!s->q)
		goto err;
	return TEE_SUCCESS;
err:
	free(s->g);
	free(s->p);
	free(s->x);
	free(s->y);
	return TEE_ERROR_OUT_OF_MEMORY;
}

static TEE_Result gen_rsa_key(struct rsa_keypair *key, size_t key_size)
{
	TEE_Result res = TEE_ERROR_OUT_OF_MEMORY;
	RSA *tmp_key;
	struct bignum_st *e, *c;
	int st;

	tmp_key = RSA_new();
	if (!tmp_key)
		return TEE_ERROR_OUT_OF_MEMORY;
	e = BN_new();
	if (!e)
		goto err;
	st = BN_set_word(e, 65537);
	if (st != 1)
		goto err;
	st = RSA_generate_key_ex(tmp_key, key_size, e, NULL);
	if (st != 1) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto err;
	}
	if ((size_t)BN_num_bits(tmp_key->n) != key_size) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto err;
	}
	c = BN_copy((struct bignum_st *)key->e, tmp_key->e);
	if (!c)
		goto err;
	c = BN_copy((struct bignum_st *)key->d, tmp_key->d);
	if (!c)
		goto err;
	c = BN_copy((struct bignum_st *)key->n, tmp_key->n);
	if (!c)
		goto err;
	c = BN_copy((struct bignum_st *)key->p, tmp_key->p);
	if (!c)
		goto err;
	c = BN_copy((struct bignum_st *)key->q, tmp_key->q);
	if (!c)
		goto err;
	c = BN_copy((struct bignum_st *)key->qp, tmp_key->iqmp);
	if (!c)
		goto err;
	c = BN_copy((struct bignum_st *)key->dp, tmp_key->dmp1);
	if (!c)
		goto err;
	c = BN_copy((struct bignum_st *)key->dq, tmp_key->dmq1);
	if (!c)
		goto err;
	RSA_free(tmp_key);

	return TEE_SUCCESS;
err:
	RSA_free(tmp_key);
	BN_free(e);
	return res;
}

static TEE_Result gen_dsa_key(struct dsa_keypair *key,
			      size_t key_size)
{
	TEE_Result res = TEE_ERROR_OUT_OF_MEMORY;
	DSA *tmp_key;
	struct bignum_st *c;
	int st;

	tmp_key = DSA_new();
	if (!tmp_key)
		return TEE_ERROR_OUT_OF_MEMORY;
	st = DSA_generate_parameters_ex(tmp_key, key_size,  NULL, 0, NULL,
					NULL, NULL);
	if (st != 1) {
		res = TEE_ERROR_BAD_STATE;
		goto err;
	}
	st = DSA_generate_key(tmp_key);
	if (st != 1) {
		res = TEE_ERROR_BAD_STATE;
		goto err;
	}
	c = BN_copy((struct bignum_st *)key->g, tmp_key->g);
	if (!c)
		goto err;
	c = BN_copy((struct bignum_st *)key->p, tmp_key->p);
	if (!c)
		goto err;
	c = BN_copy((struct bignum_st *)key->q, tmp_key->q);
	if (!c)
		goto err;
	c = BN_copy((struct bignum_st *)key->y, tmp_key->pub_key);
	if (!c)
		goto err;
	c = BN_copy((struct bignum_st *)key->x, tmp_key->priv_key);
	if (!c)
		goto err;
	DSA_free(tmp_key);

	return TEE_SUCCESS;
err:
	DSA_free(tmp_key);
	return res;
}

static DH *make_dh_keypair(struct dh_keypair *key, int copy_priv)
{
	DH *dh = NULL;
	struct bignum_st *n;

	dh = DH_new();
	if (!dh)
		return NULL;
	dh->p = BN_new();
	dh->g = BN_new();
	if (!dh->p || !dh->g)
		goto err;
	n = BN_copy(dh->p, (struct bignum_st *)key->p);
	if (!n)
		goto err;
	n = BN_copy(dh->g, (struct bignum_st *)key->g);
	if (!n)
		goto err;
	if (copy_priv && key->x) {
		dh->priv_key = BN_new();
		if (!dh->priv_key)
			goto err;
		n = BN_copy(dh->priv_key, (struct bignum_st *)key->x);
	}
	return dh;
err:
	DH_free(dh);
	return NULL;
}

static TEE_Result gen_dh_key(struct dh_keypair *key, struct bignum *q,
			     size_t xbits)
{
	TEE_Result res = TEE_ERROR_OUT_OF_MEMORY;
	DH *dh;
	struct bignum_st *n;
	int st;

	dh = make_dh_keypair(key, 0);
	if (!dh)
		goto out;
	if (q) {
		dh->q = BN_new();
		if (!dh->q)
			goto out;
		n = BN_copy(dh->q, (struct bignum_st *)q);
		if (!n)
			goto out;
	}
	if (xbits)
		dh->length = xbits;
	st = DH_generate_key(dh);
	if (st != 1) {
		res = TEE_ERROR_BAD_STATE;
		goto out;
	}
	n = BN_copy((struct bignum_st *)key->y, dh->pub_key);
	if (!n)
		goto out;
	n = BN_copy((struct bignum_st *)key->x, dh->priv_key);
	if (!n)
		goto out;
	res = TEE_SUCCESS;
out:
	DH_free(dh);
	return res;
}

static TEE_Result do_dh_shared_secret(struct dh_keypair *private_key,
				      struct bignum *public_key,
				      struct bignum *secret)
{
	TEE_Result res = TEE_ERROR_OUT_OF_MEMORY;
	DH *dh;
	struct bignum_st *n;
	int sz;
	unsigned char *buf = NULL;

	dh = make_dh_keypair(private_key, 1);
	if (!dh)
		goto out;
	sz = DH_size(dh);
	buf = malloc(sz);
	if (!buf)
		goto out;
	sz = DH_compute_key(buf, (struct bignum_st *)public_key, dh);
	if (sz < 0) {
		res = TEE_ERROR_BAD_STATE;
		goto out;
	}
	n = BN_bin2bn(buf, sz, (struct bignum_st *)secret);
	if (!n)
		goto out;
	res = TEE_SUCCESS;
out:
	DH_free(dh);
	free(buf);
	return res;
}

static RSA *make_rsa_keypair(struct rsa_keypair *key)
{
	RSA *rsa;

	rsa = RSA_new();
	if (!rsa)
		return NULL;
	RSA_blinding_off(rsa); /* FIXME */
	rsa->e = BN_new();
	rsa->d = BN_new();
	rsa->n = BN_new();
	if (!rsa->e || !rsa->d || !rsa->n)
		goto err;
	if (!BN_copy(rsa->e, (struct bignum_st *)key->e))
		goto err;
	if (!BN_copy(rsa->d, (struct bignum_st *)key->d))
		goto err;
	if (!BN_copy(rsa->n, (struct bignum_st *)key->n))
		goto err;
	if (key->p && num_bytes(key->p)) {
		rsa->p = BN_new();
		rsa->q = BN_new();
		rsa->iqmp = BN_new();
		rsa->dmp1 = BN_new();
		rsa->dmq1 = BN_new();
		if (!rsa->p || !rsa->q || !rsa->iqmp || !rsa->dmp1 ||
		    !rsa->dmq1)
			goto err;
		if (!BN_copy(rsa->p, (struct bignum_st *)key->p))
			goto err;
		if (!BN_copy(rsa->q, (struct bignum_st *)key->q))
			goto err;
		if (!BN_copy(rsa->iqmp, (struct bignum_st *)key->qp))
			goto err;
		if (!BN_copy(rsa->dmp1, (struct bignum_st *)key->dp))
			goto err;
		if (!BN_copy(rsa->dmq1, (struct bignum_st *)key->dq))
			goto err;
	}
	return rsa;
err:
	RSA_free(rsa);
	return NULL;

}

static RSA *make_rsa_public_key(struct rsa_public_key *key)
{
	RSA *rsa;

	rsa = RSA_new();
	if (!rsa)
		return NULL;
	RSA_blinding_off(rsa); /* FIXME */
	rsa->e = BN_new();
	rsa->n = BN_new();
	if (!rsa->e || !rsa->n)
		goto err;
	if (!BN_copy(rsa->e, (struct bignum_st *)key->e))
		goto err;
	if (!BN_copy(rsa->n, (struct bignum_st *)key->n))
		goto err;
	return rsa;
err:
	RSA_free(rsa);
	return NULL;

}

static TEE_Result rsa_public_encrypt(int flen, const unsigned char *from,
				     unsigned char *to, RSA *rsa, int padding,
				     int *tolen)
{
	/*
	 * Wrapper around RSA_public_encrypt, which requires that
	 * flen == RSA_size(rsa). Here we just require flen <= RSA_size(rsa).
	 * Input buffer is padded with zeros if needed.
	 */
	TEE_Result ret;
	const unsigned char *in = from;
	unsigned char *out = to;
	unsigned char *inbuf = NULL, *outbuf = NULL;
	int outsz, insz = flen, reqsz = RSA_size(rsa);
	bool alloced = 0;

	if (insz < reqsz) {
		inbuf = calloc(1, reqsz);
		outbuf = calloc(1, reqsz);
		alloced = 1;
		if (!inbuf || !outbuf) {
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto out;
		}
		memcpy(inbuf + reqsz - flen, from, flen);
		in = inbuf;
		insz = reqsz;
		out = outbuf;
	}
	outsz = RSA_public_encrypt(insz, in, out, rsa, padding);
	if (outsz < 0) {
		ret = TEE_ERROR_BAD_STATE;
		goto out;
	}
	if (*tolen < outsz) {
		*tolen = outsz;
		ret = TEE_ERROR_SHORT_BUFFER;
		goto out;
	}
	*tolen = outsz;
	if (alloced)
		memcpy(to, out, outsz);
	ret = TEE_SUCCESS;
out:
	if (alloced) {
		free(inbuf);
		free(outbuf);
	}
	return ret;
}
static TEE_Result rsanopad_encrypt(struct rsa_public_key *key,
				   const uint8_t *src, size_t src_len,
				   uint8_t *dst, size_t *dst_len)
{
	RSA *rsa;
	const unsigned char *in = src;
	unsigned char *out = dst;
	int maxinsz, outsz = *dst_len, insz, leftinsz;
	int leftoutsz, done = 0;
	TEE_Result ret;

	rsa = make_rsa_public_key(key);
	if (!rsa) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	maxinsz = RSA_size(rsa);
	leftinsz = src_len;
	leftoutsz = *dst_len;
	do {
		insz = MIN(leftinsz, maxinsz);
		outsz = leftoutsz;
		ret = rsa_public_encrypt(insz, in, out, rsa, RSA_NO_PADDING,
					 &outsz);
		if (ret != TEE_SUCCESS)
			goto out;
		if (outsz > leftoutsz) {
			ret = TEE_ERROR_SHORT_BUFFER;
			goto out;
		}
		in += insz;
		out += outsz;
		leftinsz -= insz;
		leftoutsz -= outsz;
		done += outsz;
	} while (leftinsz > 0);
	*dst_len = done;
	ret = TEE_SUCCESS;
out:
	RSA_free(rsa);
	return ret;
}
static TEE_Result rsanopad_decrypt(struct rsa_keypair *key,
				   const uint8_t *src, size_t src_len,
				   uint8_t *dst, size_t *dst_len)
{
	RSA *rsa;
	TEE_Result ret;
	unsigned char *buf = NULL;
	int maxsz, outsz, offset;

	rsa = make_rsa_keypair(key);
	if (!rsa) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	/*
	 * Decrypt to temporary buffer since output size is unknown (but less
	 * than maxsz)
	 */
	maxsz = RSA_size(rsa);
	buf = calloc(1, maxsz);
	if (!buf) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	outsz = RSA_private_decrypt(src_len, src, buf, rsa, RSA_NO_PADDING);

	/* Remove the zero-padding (leave one zero if buff is all zeroes) */
	offset = 0;
	while ((offset < outsz - 1) && (buf[offset] == 0))
		offset++;

	if (*dst_len < (size_t)(outsz - offset)) {
		*dst_len = outsz - offset;
		ret = TEE_ERROR_SHORT_BUFFER;
		goto out;
	}

	*dst_len = outsz - offset;
	memcpy(dst, (char *)buf + offset, *dst_len);
	ret = TEE_SUCCESS;
out:
	RSA_free(rsa);
	free(buf);
	return ret;
}

static TEE_Result rsaes_encrypt(uint32_t algo, struct rsa_public_key *key,
					const uint8_t *label, size_t label_len,
					const uint8_t *src, size_t src_len,
					uint8_t *dst, size_t *dst_len)
{
	TEE_Result ret = TEE_SUCCESS;
	unsigned char *buf = NULL;
	int st;
	size_t bufsz;

	bufsz = num_bytes(key->n);
	buf = calloc(1, bufsz);
	if (!buf) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	if (algo == TEE_ALG_RSAES_PKCS1_V1_5) {
		st = RSA_padding_add_PKCS1_type_2(buf, bufsz, src, src_len);
	} else {
		st = RSA_padding_add_PKCS1_OAEP(buf, bufsz, src, src_len,
						label, label_len);
	}
	if (st < 0) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}
	ret = rsanopad_encrypt(key, buf, bufsz, dst, dst_len);
out:
	free(buf);
	return ret;
}

static TEE_Result rsaes_decrypt(uint32_t algo, struct rsa_keypair *key,
				    const uint8_t *label, size_t label_len,
				    const uint8_t *src, size_t src_len,
				    uint8_t *dst, size_t *dst_len)
{
	TEE_Result ret = TEE_SUCCESS;
	unsigned char *buf = NULL;
	int st;
	size_t rsa_len, bufsz;

	rsa_len = num_bytes(key->n);
	bufsz = rsa_len;
	buf = malloc(bufsz);
	if (!buf) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	ret = rsanopad_decrypt(key, src, src_len, buf, &bufsz);
	if (ret != TEE_SUCCESS)
		goto out;
	if (algo == TEE_ALG_RSAES_PKCS1_V1_5) {
		st = RSA_padding_check_PKCS1_type_2(dst, *dst_len, buf, bufsz,
						    rsa_len);
	} else {
		st = RSA_padding_check_PKCS1_OAEP(dst, *dst_len, buf, bufsz,
						  rsa_len, label, label_len);
	}
	if (st < 0) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}
	if (*dst_len < (size_t)st) {
		*dst_len = st;
		ret = TEE_ERROR_SHORT_BUFFER;
		goto out;
	}
	*dst_len = st;
out:
	free(buf);
	return ret;
}

static int digest_type(uint32_t algo)
{
	switch (algo) {
	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
		return NID_md5;
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
	case TEE_ALG_DSA_SHA1:
		return NID_sha1;
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
		return NID_sha224;
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
		return NID_sha256;
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
		return NID_sha384;
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
		return NID_sha512;
	default:
		return -1;
	}

}

static TEE_Result rsassa_pkcs1_v1_5_sign(uint32_t algo,
					 struct rsa_keypair *key,
					 const uint8_t *msg, size_t msg_len,
					 uint8_t *sig, size_t *sig_len)
{
	int st, type;
	TEE_Result ret = TEE_ERROR_BAD_STATE;
	RSA *rsa = NULL;

	type = digest_type(algo);
	if (type < 0)
		return TEE_ERROR_NOT_IMPLEMENTED;
	rsa = make_rsa_keypair(key);
	if (!rsa) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	st = RSA_sign(type, msg, msg_len, sig, sig_len, rsa);
	if (st != 1)
		goto out;
	ret = TEE_SUCCESS;
out:
	RSA_free(rsa);
	return ret;
}

static TEE_Result rsassa_pkcs1_v1_5_verify(uint32_t algo,
					   struct rsa_public_key *key,
					   const uint8_t *msg,
					   size_t msg_len, const uint8_t *sig,
					   size_t sig_len)
{
	int st, type;
	TEE_Result ret = TEE_ERROR_BAD_STATE;
	RSA *rsa = NULL;

	type = digest_type(algo);
	if (type < 0)
		return TEE_ERROR_NOT_IMPLEMENTED;

	rsa = make_rsa_public_key(key);
	if (!rsa) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	st = RSA_verify(type, msg, msg_len, sig, sig_len, rsa);
	if (st != 1) {
		ret = TEE_ERROR_SIGNATURE_INVALID;
		goto out;
	}
	ret = TEE_SUCCESS;
out:
	RSA_free(rsa);
	return ret;
}

static const EVP_MD *evp_md(uint32_t algo)
{
	switch (algo) {
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1:
		return EVP_sha1();
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224:
		return EVP_sha224();
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
		return EVP_sha256();
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384:
		return EVP_sha384();
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512:
		return EVP_sha512();
	default:
		return NULL;
	}
}

static TEE_Result rsassa_pkcs1_pss_mgf1_sign(uint32_t algo, uint32_t salt_len,
					     struct rsa_keypair *key,
					     const uint8_t *msg,
					     size_t msg_len,
					     uint8_t *sig, size_t *sig_len)
{
	int st, padded_sz;
	TEE_Result ret = TEE_ERROR_BAD_STATE;
	RSA *rsa = NULL;
	const EVP_MD *md;
	unsigned char *padded = NULL;

	md = evp_md(algo);
	if (!md)
		goto out;
	if (msg_len != (size_t)EVP_MD_size(md)) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}
	rsa = make_rsa_keypair(key);
	if (!rsa) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	if (*sig_len < (size_t)RSA_size(rsa)) {
		ret = TEE_ERROR_SHORT_BUFFER;
		goto out;
	}
	padded_sz = RSA_size(rsa);
	padded = malloc(padded_sz);
	if (!padded)
		goto out;
	st = RSA_padding_add_PKCS1_PSS_mgf1(rsa, padded, msg, md, NULL,
					    salt_len);
	if (st != 1)
		goto out;
	st = RSA_private_encrypt(padded_sz, padded, sig, rsa, RSA_NO_PADDING);
	if (st < 0)
		goto out;
	*sig_len = st;
	ret = TEE_SUCCESS;
out:
	RSA_free(rsa);
	free(padded);
	return ret;
}

static TEE_Result rsassa_pkcs1_pss_mgf1_verify(uint32_t algo,
					       uint32_t salt_len,
					       struct rsa_public_key *key,
					       const uint8_t *msg,
					       size_t msg_len __unused,
					       const uint8_t *sig,
					       size_t sig_len)
{
	int st;
	TEE_Result ret = TEE_ERROR_BAD_STATE;
	RSA *rsa = NULL;
	const EVP_MD *md;
	unsigned char *buf = NULL;

	md = evp_md(algo);
	if (!md)
		goto out;
	if (msg_len != (size_t)EVP_MD_size(md)) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}
	rsa = make_rsa_public_key(key);
	if (!rsa) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	if (sig_len != (size_t)RSA_size(rsa)) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}
	buf = malloc(RSA_size(rsa));
	if (!buf)
		goto out;
	st = RSA_public_decrypt(sig_len, sig, buf, rsa, RSA_NO_PADDING);
	if (st <= 0) {
		ret = TEE_ERROR_SIGNATURE_INVALID;
		goto out;
	}
	if ((size_t)st != sig_len) {
		ret = TEE_ERROR_SIGNATURE_INVALID;
		goto out;
	}
	st = RSA_verify_PKCS1_PSS_mgf1(rsa, msg, md, NULL, buf, salt_len);
	if (st != 1) {
		ret = TEE_ERROR_SIGNATURE_INVALID;
		goto out;
	}
	ret = TEE_SUCCESS;
out:
	RSA_free(rsa);
	free(buf);
	return ret;
}

static TEE_Result rsassa_sign(uint32_t algo, struct rsa_keypair *key,
			      int salt_len, const uint8_t *msg,
			      size_t msg_len, uint8_t *sig,
			      size_t *sig_len)
{
	TEE_Result res;
	size_t hash_size, mod_size;

	(void)salt_len;
	res = tee_hash_get_digest_size(TEE_DIGEST_HASH_TO_ALGO(algo),
				       &hash_size);
	if (res != TEE_SUCCESS)
		return res;
	if (msg_len != hash_size)
		return TEE_ERROR_BAD_PARAMETERS;

	mod_size = num_bytes(key->n);
	if (*sig_len < mod_size) {
		*sig_len = mod_size;
		return TEE_ERROR_SHORT_BUFFER;
	}
	*sig_len = mod_size;

	switch (algo) {
	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
		return rsassa_pkcs1_v1_5_sign(algo, key, msg, msg_len, sig,
					      sig_len);
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512:
		return rsassa_pkcs1_pss_mgf1_sign(algo, salt_len, key, msg,
						  msg_len, sig, sig_len);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_ERROR_NOT_IMPLEMENTED;
}

static TEE_Result rsassa_verify(uint32_t algo, struct rsa_public_key *key,
				int salt_len, const uint8_t *msg,
				size_t msg_len, const uint8_t *sig,
				size_t sig_len)
{
	switch (algo) {
	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
		return rsassa_pkcs1_v1_5_verify(algo, key, msg, msg_len, sig,
						sig_len);
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512:
		return rsassa_pkcs1_pss_mgf1_verify(algo, salt_len, key, msg,
						    msg_len, sig, sig_len);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_ERROR_NOT_IMPLEMENTED;
}

static DSA *make_dsa_public_key(struct dsa_public_key *key)
{
	DSA *dsa;

	dsa = DSA_new();
	if (!dsa)
		return NULL;
	dsa->g = BN_new();
	dsa->p = BN_new();
	dsa->q = BN_new();
	dsa->pub_key = BN_new();
	if (!dsa->g || !dsa->p || !dsa->q || !dsa->pub_key)
		goto err;
	if (!BN_copy(dsa->g, (struct bignum_st *)key->g))
		goto err;
	if (!BN_copy(dsa->p, (struct bignum_st *)key->p))
		goto err;
	if (!BN_copy(dsa->q, (struct bignum_st *)key->q))
		goto err;
	if (!BN_copy(dsa->pub_key, (struct bignum_st *)key->y))
		goto err;
	return dsa;
err:
	DSA_free(dsa);
	return NULL;

}

static DSA *make_dsa_keypair(struct dsa_keypair *key)
{
	DSA *dsa;

	dsa = DSA_new();
	if (!dsa)
		return NULL;
	dsa->g = BN_new();
	dsa->p = BN_new();
	dsa->q = BN_new();
	dsa->pub_key = BN_new();
	dsa->priv_key = BN_new();
	if (!dsa->g || !dsa->p || !dsa->q || !dsa->pub_key || !dsa->priv_key)
		goto err;
	if (!BN_copy(dsa->g, (struct bignum_st *)key->g))
		goto err;
	if (!BN_copy(dsa->p, (struct bignum_st *)key->p))
		goto err;
	if (!BN_copy(dsa->q, (struct bignum_st *)key->q))
		goto err;
	if (!BN_copy(dsa->pub_key, (struct bignum_st *)key->y))
		goto err;
	if (!BN_copy(dsa->priv_key, (struct bignum_st *)key->x))
		goto err;
	return dsa;
err:
	DSA_free(dsa);
	return NULL;

}

static TEE_Result dsa_sign(uint32_t algo, struct dsa_keypair *key,
			   const uint8_t *msg, size_t msg_len, uint8_t *sig,
			   size_t *sig_len)
{
	TEE_Result ret;
	DSA *dsa = NULL;
	DSA_SIG *dsig = NULL;
	size_t hashsz, outsz;

	ret = tee_hash_get_digest_size(algo, &hashsz);
	if (ret != TEE_SUCCESS)
		goto out;
	if (msg_len != hashsz) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}
	dsa = make_dsa_keypair(key);
	if (!dsa) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	outsz = 2 * BN_num_bytes(dsa->q);
	if (*sig_len < outsz) {
		*sig_len = outsz;
		ret = TEE_ERROR_SHORT_BUFFER;
		goto out;
	}
	*sig_len = outsz;
	dsig = DSA_do_sign(msg, msg_len, dsa);
	if (!dsig) {
		ret = TEE_ERROR_BAD_STATE;
		goto out;
	}
	BN_bn2bin(dsig->r, sig);
	BN_bn2bin(dsig->s, sig + outsz/2);
	ret = TEE_SUCCESS;
out:
	DSA_SIG_free(dsig);
	DSA_free(dsa);
	return ret;
}

static TEE_Result dsa_verify(uint32_t algo __unused,
			     struct dsa_public_key *key,
			     const uint8_t *msg, size_t msg_len,
			     const uint8_t *sig, size_t sig_len)
{
	int st;
	TEE_Result ret = TEE_ERROR_OUT_OF_MEMORY;
	DSA *dsa = NULL;
	DSA_SIG *dsig = NULL;

	dsa = make_dsa_public_key(key);
	if (!dsa)
		goto out;
	dsig = DSA_SIG_new();
	if (!dsig)
		goto out;
	dsig->r = BN_bin2bn(sig, sig_len/2, NULL);
	if (!dsig->r)
		goto out;
	dsig->s = BN_bin2bn(sig + sig_len/2, sig_len/2, NULL);
	if (!dsig->s)
		goto out;
	st = DSA_do_verify(msg, msg_len, dsig, dsa);
	if (st != 1) {
		ret = TEE_ERROR_SIGNATURE_INVALID;
		goto out;
	}
	ret = TEE_SUCCESS;
out:
	DSA_SIG_free(dsig);
	DSA_free(dsa);
	return ret;
}

/******************************************************************************
 * Authenticated encryption
 ******************************************************************************/

/*
 * In CCM mode, EVP_EncryptUpdate() or EVP_DecryptUpdate() may be called only
 * once for AAD data, and once for the payload (plain text or cipher text).
 * Hence, we have to re-assemble data in our own buffers.
 * GCM does not suffer from this limitation.
 */
struct aes_ccm_ctx {
	EVP_CIPHER_CTX ctx;
	unsigned char *aad;
	size_t aad_len;
	size_t aad_count;
	unsigned char *dst_buf;
	unsigned char *payload;
	size_t payload_len;
	size_t payload_count;
	unsigned char *nonce;
	unsigned char *key;
	size_t key_len;
};

static TEE_Result authenc_get_ctx_size(uint32_t algo, size_t *size)
{
	switch (algo) {
	case TEE_ALG_AES_CCM:
		*size = sizeof(struct aes_ccm_ctx);
		break;
	case TEE_ALG_AES_GCM:
		*size = sizeof(EVP_CIPHER_CTX);
		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
	return TEE_SUCCESS;
}

static TEE_Result aes_ccm_init(void *ctx, TEE_OperationMode mode,
			       const uint8_t *key, size_t key_len,
			       const uint8_t *nonce, size_t nonce_len,
			       size_t tag_len, size_t aad_len,
			       size_t payload_len)
{
	const EVP_CIPHER *cipher;
	struct aes_ccm_ctx *cctx = ctx;
	int st, len;

	switch (key_len) {
	case 16:
		cipher = EVP_aes_128_ccm();
		break;
	case 24:
		cipher = EVP_aes_192_ccm();
		break;
	case 32:
		cipher = EVP_aes_256_ccm();
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Allocate buffer for AAD data and payload. */
	memset(cctx, 0, sizeof(*cctx));
	cctx->aad = malloc(aad_len);
	if (!cctx->aad)
		return TEE_ERROR_OUT_OF_MEMORY;
	cctx->aad_len = aad_len;
	cctx->aad_count = 0;

	cctx->payload = malloc(payload_len);
	if (!cctx->payload)
		return TEE_ERROR_OUT_OF_MEMORY;
	cctx->payload_len = payload_len;
	cctx->payload_count = 0;

	if (mode == TEE_MODE_ENCRYPT) {
		/* Set cipher */
		st = EVP_EncryptInit(ctx, cipher, NULL, NULL);
		if (st != 1)
			return TEE_ERROR_BAD_STATE;
		/* Set IV length */
		st = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN,
					 nonce_len, NULL);
		if (st != 1)
			return TEE_ERROR_BAD_STATE;
		/* Set tag length */
		st = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, tag_len,
					 NULL);
		if (st != 1)
			return TEE_ERROR_BAD_STATE;
		/* Set key and nonce */
		st = EVP_EncryptInit(ctx, NULL, key, nonce);
		if (st != 1)
			return TEE_ERROR_BAD_STATE;
		/* Provide plaintext length */
		st = EVP_EncryptUpdate(ctx, NULL, &len, NULL, payload_len);
		if (st != 1)
			return TEE_ERROR_BAD_STATE;
	} else {
		/* Save key and nonce for later use */
		cctx->nonce = malloc(nonce_len);
		if (!cctx->nonce)
			return TEE_ERROR_OUT_OF_MEMORY;
		memcpy(cctx->nonce, nonce, nonce_len);
		cctx->key = malloc(key_len);
		if (!cctx->key)
			return TEE_ERROR_OUT_OF_MEMORY;
		memcpy(cctx->key, key, key_len);
		/* Set cipher */
		st = EVP_DecryptInit(ctx, cipher, NULL, NULL);
		if (st != 1)
			return TEE_ERROR_BAD_STATE;
		/* Set IV length */
		st = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN,
					 nonce_len, NULL);
		if (st != 1)
			return TEE_ERROR_BAD_STATE;
	}
	return TEE_SUCCESS;
}

static TEE_Result aes_gcm_init(void *ctx, TEE_OperationMode mode,
			       const uint8_t *key, size_t key_len,
			       const uint8_t *nonce, size_t nonce_len)
{
	const EVP_CIPHER *cipher;
	struct aes_ccm_ctx *cctx = ctx;
	int st;

	switch (key_len) {
	case 16:
		cipher = EVP_aes_128_gcm();
		break;
	case 24:
		cipher = EVP_aes_192_gcm();
		break;
	case 32:
		cipher = EVP_aes_256_gcm();
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
	/* Set cipher */
	if (mode == TEE_MODE_ENCRYPT)
		st = EVP_EncryptInit(&cctx->ctx, cipher, NULL, NULL);
	else
		st = EVP_DecryptInit(&cctx->ctx, cipher, NULL, NULL);
	if (st != 1)
		return TEE_ERROR_BAD_STATE;
	/* Set IV length */
	st = EVP_CIPHER_CTX_ctrl(&cctx->ctx, EVP_CTRL_GCM_SET_IVLEN, nonce_len,
				 NULL);
	if (st != 1)
		return TEE_ERROR_BAD_STATE;
	/* Set key and nonce */
	if (mode == TEE_MODE_ENCRYPT)
		st = EVP_EncryptInit(&cctx->ctx, NULL, key, nonce);
	else
		st = EVP_DecryptInit(&cctx->ctx, NULL, key, nonce);
	if (st != 1)
		return TEE_ERROR_BAD_STATE;

	return TEE_SUCCESS;
}

static TEE_Result authenc_init(void *ctx, uint32_t algo,
			       TEE_OperationMode mode,
			       const uint8_t *key, size_t key_len,
			       const uint8_t *nonce, size_t nonce_len,
			       size_t tag_len, size_t aad_len,
			       size_t payload_len)
{
	switch (algo) {
	case TEE_ALG_AES_CCM:
		return aes_ccm_init(ctx, mode, key, key_len, nonce, nonce_len,
				    tag_len, aad_len, payload_len);
	case TEE_ALG_AES_GCM:
		return aes_gcm_init(ctx, mode, key, key_len, nonce, nonce_len);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
}

static TEE_Result authenc_update_aad(void *ctx, uint32_t algo,
				     TEE_OperationMode mode,
				     const uint8_t *data, size_t len)
{
	int st, outlen;
	struct aes_ccm_ctx *cctx;

	switch (algo) {
	case TEE_ALG_AES_CCM:
		cctx = ctx;
		if (cctx->aad_count + len > cctx->aad_len)
			return TEE_ERROR_BAD_PARAMETERS;
		memcpy(cctx->aad + cctx->aad_count, data, len);
		cctx->aad_count += len;
		break;
	case TEE_ALG_AES_GCM:
		if (mode == TEE_MODE_ENCRYPT)
			st = EVP_EncryptUpdate(ctx, NULL, &outlen, data, len);
		else
			st = EVP_DecryptUpdate(ctx, NULL, &outlen, data, len);
		if (st != 1)
			return TEE_ERROR_BAD_STATE;
		break;
	default:
		return TEE_ERROR_BAD_STATE;
	}

	return TEE_SUCCESS;
}

static TEE_Result authenc_update_payload(void *ctx, uint32_t algo,
					 TEE_OperationMode mode,
					 const uint8_t *src_data,
					 size_t src_len, uint8_t *dst_data,
					 size_t *dst_len)
{
	int st, outlen;
	struct aes_ccm_ctx *cctx;

	switch (algo) {
	case TEE_ALG_AES_CCM:
		cctx = ctx;
		if (cctx->payload_count + src_len > cctx->payload_len)
			return TEE_ERROR_BAD_PARAMETERS;
		memcpy(cctx->payload + cctx->payload_count, src_data, src_len);
		cctx->payload_count += src_len;
		/* Save start of destination buffer on first call */
		if (!cctx->dst_buf)
			cctx->dst_buf = dst_data;
		*dst_len = 0;
		break;
	case TEE_ALG_AES_GCM:
		outlen = *dst_len;
		if (mode == TEE_MODE_ENCRYPT)
			st = EVP_EncryptUpdate(ctx, dst_data, &outlen,
					       src_data, src_len);
		else
			st = EVP_DecryptUpdate(ctx, dst_data, &outlen,
					       src_data, src_len);
		if (st != 1)
			return TEE_ERROR_BAD_STATE;
		*dst_len = outlen;
		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
	return TEE_SUCCESS;
}

static TEE_Result authenc_enc_final(void *ctx, uint32_t algo,
				    const uint8_t *src_data,
				    size_t src_len, uint8_t *dst_data,
				    size_t *dst_len, uint8_t *dst_tag,
				    size_t *dst_tag_len)
{
	TEE_Result res;
	int st, outlen;
	size_t dlen;
	struct aes_ccm_ctx *cctx;

	switch (algo) {
	case TEE_ALG_AES_CCM:
		cctx = ctx;
		dlen = *dst_len;
		res = authenc_update_payload(ctx, algo, TEE_MODE_ENCRYPT,
					     src_data, src_len, dst_data,
					     &dlen);
		if (res != TEE_SUCCESS)
			return res;
		/* AAD data and payload data complete? */
		if (cctx->aad_count != cctx->aad_len)
			return TEE_ERROR_BAD_STATE;
		if (cctx->payload_count != cctx->payload_len)
			return TEE_ERROR_BAD_STATE;
		/* Provide AAD data */
		st = EVP_EncryptUpdate(&cctx->ctx, NULL, &outlen, cctx->aad,
				       cctx->aad_len);
		if (st != 1)
			return TEE_ERROR_BAD_STATE;
		/* Provide plaintext data */
		st = EVP_EncryptUpdate(&cctx->ctx, cctx->dst_buf, &outlen,
				       cctx->payload, cctx->payload_len);
		if (st != 1)
			return TEE_ERROR_BAD_STATE;
		*dst_len = outlen;
		/* Finalize encryption */
		st = EVP_EncryptFinal(&cctx->ctx, cctx->dst_buf + outlen,
				      &outlen);
		if (st != 1)
			return TEE_ERROR_BAD_STATE;
		/* EVP_EncryptFinal generates no additional data */
		TEE_ASSERT(outlen == 0);
		/* Get the tag */
		st = EVP_CIPHER_CTX_ctrl(&cctx->ctx, EVP_CTRL_CCM_GET_TAG,
					 *dst_tag_len, dst_tag);
		if (st != 1)
			return TEE_ERROR_BAD_STATE;
		break;
	case TEE_ALG_AES_GCM:
		/* Encrypt data */
		st = EVP_EncryptUpdate(ctx, dst_data, &outlen, src_data,
				       src_len);
		if (st != 1)
			return TEE_ERROR_BAD_STATE;
		*dst_len = outlen;
		/* Finalize encryption */
		st = EVP_EncryptFinal(ctx, dst_data + outlen, &outlen);
		if (st != 1)
			return TEE_ERROR_BAD_STATE;
		/* EVP_EncryptFinal generates no additional data */
		TEE_ASSERT(outlen == 0);
		/* Get the tag */
		st = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
					 *dst_tag_len, dst_tag);
		if (st != 1)
			return TEE_ERROR_BAD_STATE;
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
	return TEE_SUCCESS;
}

static TEE_Result authenc_dec_final(void *ctx, uint32_t algo,
				    const uint8_t *src_data, size_t src_len,
				    uint8_t *dst_data, size_t *dst_len,
				    const uint8_t *tag, size_t tag_len)
{
	TEE_Result res;
	int st, outlen;
	size_t dlen;
	struct aes_ccm_ctx *cctx;

	switch (algo) {
	case TEE_ALG_AES_CCM:
		cctx = ctx;
		dlen = *dst_len;
		res = authenc_update_payload(ctx, algo, TEE_MODE_DECRYPT,
					     src_data, src_len, dst_data,
					     &dlen);
		if (res != TEE_SUCCESS)
			return res;
		/* AAD data and payload data complete? */
		if (cctx->aad_count != cctx->aad_len)
			return TEE_ERROR_BAD_STATE;
		if (cctx->payload_count != cctx->payload_len)
			return TEE_ERROR_BAD_STATE;
		/* Provide expected tag */
		st = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, tag_len,
					 (void *)tag);
		if (st != 1)
			return TEE_ERROR_BAD_STATE;
		/* Set key and IV */
		st = EVP_DecryptInit(ctx, NULL, cctx->key, cctx->nonce);
		if (st != 1)
			return TEE_ERROR_BAD_STATE;
		/* Provide total length of encrypted data */
		st = EVP_DecryptUpdate(&cctx->ctx, NULL, &outlen, NULL,
				       cctx->payload_len);
		if (st != 1)
			return TEE_ERROR_BAD_STATE;
		/* Provide AAD data  */
		st = EVP_DecryptUpdate(&cctx->ctx, NULL, &outlen, cctx->aad,
				       cctx->aad_len);
		if (st != 1)
			return TEE_ERROR_BAD_STATE;
		/* Process ciphertext*/
		st = EVP_DecryptUpdate(&cctx->ctx, cctx->dst_buf, &outlen,
				       cctx->payload, cctx->payload_len);
		if (st != 1)
			return TEE_ERROR_BAD_STATE;
		*dst_len = outlen;
		break;
	case TEE_ALG_AES_GCM:
		/* Decrypt data */
		st = EVP_DecryptUpdate(ctx, dst_data, &outlen, src_data,
				       src_len);
		if (st != 1)
			return TEE_ERROR_BAD_STATE;
		*dst_len = outlen;
		/* Provide the tag */
		st = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_len,
					 (void *)tag);
		if (st != 1)
			return TEE_ERROR_BAD_STATE;
		/* Finalize encryption */
		st = EVP_DecryptFinal(ctx, dst_data + *dst_len, &outlen);
		if (st != 1)
			return TEE_ERROR_BAD_STATE;
		/* EVP_EncryptFinal() generates no additional data */
		TEE_ASSERT(outlen == 0);
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
	return TEE_SUCCESS;
}

static void authenc_final(void *ctx, uint32_t algo)
{
	struct aes_ccm_ctx *cctx;

	if (algo == TEE_ALG_AES_CCM) {
		cctx = ctx;
		free(cctx->aad);
		free(cctx->payload);
		free(cctx->nonce);
		EVP_CIPHER_CTX_cleanup(&cctx->ctx);
	} else {
		EVP_CIPHER_CTX_cleanup(ctx);
	}
}

struct crypto_ops crypto_ops = {
	.name = "OpenSSL provider",
	.init = tee_ossl_init,
	.bignum = {
		.allocate = bn_allocate,
		.num_bytes = num_bytes,
		.bn2bin = bn2bin,
		.bin2bn = bin2bn,
		.copy = bn_copy,
		.free = bn_free,
	},
	.hash = {
		.get_ctx_size = hash_get_ctx_size,
		.init = hash_init,
		.update = hash_update,
		.final = hash_final,
	},
	.cipher = {
		.get_ctx_size = cipher_get_ctx_size,
		.init = cipher_init,
		.update = cipher_update,
		.final = cipher_final
	},
	.mac = {
		.get_ctx_size = mac_get_ctx_size,
		.init = mac_init,
		.update = mac_update,
		.final = mac_final
	},
	.acipher = {
		.alloc_dh_keypair = alloc_dh_keypair,
		.alloc_dsa_keypair = alloc_dsa_keypair,
		.alloc_dsa_public_key = alloc_dsa_public_key,
		.alloc_rsa_keypair = alloc_rsa_keypair,
		.alloc_rsa_public_key = alloc_rsa_public_key,
		.dh_shared_secret = do_dh_shared_secret,
		.dsa_sign = dsa_sign,
		.dsa_verify = dsa_verify,
		.gen_dh_key = gen_dh_key,
		.gen_dsa_key = gen_dsa_key,
		.gen_rsa_key = gen_rsa_key,
		.rsaes_decrypt = rsaes_decrypt,
		.rsaes_encrypt = rsaes_encrypt,
		.rsanopad_decrypt = rsanopad_decrypt,
		.rsanopad_encrypt = rsanopad_encrypt,
		.rsassa_sign = rsassa_sign,
		.rsassa_verify = rsassa_verify,
	},
	.authenc = {
		.dec_final = authenc_dec_final,
		.enc_final = authenc_enc_final,
		.final = authenc_final,
		.get_ctx_size = authenc_get_ctx_size,
		.init = authenc_init,
		.update_aad = authenc_update_aad,
		.update_payload = authenc_update_payload,
	},

};
