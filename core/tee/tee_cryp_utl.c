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
 */

#include <stdlib.h>
#include <string.h>
#include <string_ext.h>
#include <utee_defines.h>
#include <tee/tee_cryp_utl.h>
#include <tee/tee_cryp_provider.h>
#include <kernel/tee_time.h>
#include <rng_support.h>
#include <initcall.h>

#if !defined(CFG_WITH_SOFTWARE_PRNG)
TEE_Result get_rng_array(void *buffer, int len)
{
	char *buf_char = buffer;
	int i;


	if (buf_char == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	for (i = 0; i < len; i++)
		buf_char[i] = hw_get_random_byte();

	return TEE_SUCCESS;
}
#endif

TEE_Result tee_hash_get_digest_size(uint32_t algo, size_t *size)
{
	switch (algo) {
	case TEE_ALG_MD5:
	case TEE_ALG_HMAC_MD5:
		*size = TEE_MD5_HASH_SIZE;
		break;
	case TEE_ALG_SHA1:
	case TEE_ALG_HMAC_SHA1:
	case TEE_ALG_DSA_SHA1:
		*size = TEE_SHA1_HASH_SIZE;
		break;
	case TEE_ALG_SHA224:
	case TEE_ALG_HMAC_SHA224:
	case TEE_ALG_DSA_SHA224:
		*size = TEE_SHA224_HASH_SIZE;
		break;
	case TEE_ALG_SHA256:
	case TEE_ALG_HMAC_SHA256:
	case TEE_ALG_DSA_SHA256:
		*size = TEE_SHA256_HASH_SIZE;
		break;
	case TEE_ALG_SHA384:
	case TEE_ALG_HMAC_SHA384:
		*size = TEE_SHA384_HASH_SIZE;
		break;
	case TEE_ALG_SHA512:
	case TEE_ALG_HMAC_SHA512:
		*size = TEE_SHA512_HASH_SIZE;
		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
}

TEE_Result tee_hash_createdigest(uint32_t algo, const uint8_t *data,
				 size_t datalen, uint8_t *digest,
				 size_t digestlen)
{
	TEE_Result res = TEE_ERROR_BAD_STATE;
	void *ctx = NULL;
	size_t ctxsize;

	if (crypto_ops.hash.get_ctx_size == NULL ||
	    crypto_ops.hash.init == NULL ||
	    crypto_ops.hash.update == NULL ||
	    crypto_ops.hash.final == NULL)
		return TEE_ERROR_NOT_IMPLEMENTED;

	if (crypto_ops.hash.get_ctx_size(algo, &ctxsize) != TEE_SUCCESS) {
		res = TEE_ERROR_NOT_SUPPORTED;
		goto out;
	}

	ctx = malloc(ctxsize);
	if (ctx == NULL) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	if (crypto_ops.hash.init(ctx, algo) != TEE_SUCCESS)
		goto out;

	if (datalen != 0) {
		if (crypto_ops.hash.update(ctx, algo, data, datalen)
		    != TEE_SUCCESS)
			goto out;
	}

	if (crypto_ops.hash.final(ctx, algo, digest, digestlen) != TEE_SUCCESS)
		goto out;

	res = TEE_SUCCESS;

out:
	if (ctx)
		free(ctx);

	return res;
}

TEE_Result tee_mac_get_digest_size(uint32_t algo, size_t *size)
{
	switch (algo) {
	case TEE_ALG_HMAC_MD5:
	case TEE_ALG_HMAC_SHA224:
	case TEE_ALG_HMAC_SHA1:
	case TEE_ALG_HMAC_SHA256:
	case TEE_ALG_HMAC_SHA384:
	case TEE_ALG_HMAC_SHA512:
		return tee_hash_get_digest_size(algo, size);
	case TEE_ALG_AES_CBC_MAC_NOPAD:
	case TEE_ALG_AES_CBC_MAC_PKCS5:
	case TEE_ALG_AES_CMAC:
		*size = TEE_AES_BLOCK_SIZE;
		return TEE_SUCCESS;
	case TEE_ALG_DES_CBC_MAC_NOPAD:
	case TEE_ALG_DES_CBC_MAC_PKCS5:
	case TEE_ALG_DES3_CBC_MAC_NOPAD:
	case TEE_ALG_DES3_CBC_MAC_PKCS5:
		*size = TEE_DES_BLOCK_SIZE;
		return TEE_SUCCESS;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

TEE_Result tee_cipher_get_block_size(uint32_t algo, size_t *size)
{
	switch (algo) {
	case TEE_ALG_AES_CBC_MAC_NOPAD:
	case TEE_ALG_AES_CBC_MAC_PKCS5:
	case TEE_ALG_AES_CMAC:
	case TEE_ALG_AES_ECB_NOPAD:
	case TEE_ALG_AES_CBC_NOPAD:
	case TEE_ALG_AES_CTR:
	case TEE_ALG_AES_CTS:
	case TEE_ALG_AES_XTS:
	case TEE_ALG_AES_CCM:
	case TEE_ALG_AES_GCM:
		*size = 16;
		break;

	case TEE_ALG_DES_CBC_MAC_NOPAD:
	case TEE_ALG_DES_CBC_MAC_PKCS5:
	case TEE_ALG_DES_ECB_NOPAD:
	case TEE_ALG_DES_CBC_NOPAD:
	case TEE_ALG_DES3_CBC_MAC_NOPAD:
	case TEE_ALG_DES3_CBC_MAC_PKCS5:
	case TEE_ALG_DES3_ECB_NOPAD:
	case TEE_ALG_DES3_CBC_NOPAD:
		*size = 8;
		break;

	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
}

TEE_Result tee_do_cipher_update(void *ctx, uint32_t algo,
				TEE_OperationMode mode, bool last_block,
				const uint8_t *data, size_t len, uint8_t *dst)
{
	TEE_Result res;
	size_t block_size;

	if (mode != TEE_MODE_ENCRYPT && mode != TEE_MODE_DECRYPT)
		return TEE_ERROR_BAD_PARAMETERS;

	if (crypto_ops.cipher.update == NULL)
		return TEE_ERROR_NOT_IMPLEMENTED;
	/*
	 * Check that the block contains the correct number of data, apart
	 * for the last block in some XTS / CTR / XTS mode
	 */
	res = tee_cipher_get_block_size(algo, &block_size);
	if (res != TEE_SUCCESS)
		return res;
	if ((len % block_size) != 0) {
		if (!last_block && algo != TEE_ALG_AES_CTR)
			return TEE_ERROR_BAD_PARAMETERS;

		switch (algo) {
		case TEE_ALG_AES_ECB_NOPAD:
		case TEE_ALG_DES_ECB_NOPAD:
		case TEE_ALG_DES3_ECB_NOPAD:
		case TEE_ALG_AES_CBC_NOPAD:
		case TEE_ALG_DES_CBC_NOPAD:
		case TEE_ALG_DES3_CBC_NOPAD:
			return TEE_ERROR_BAD_PARAMETERS;

		case TEE_ALG_AES_CTR:
		case TEE_ALG_AES_XTS:
		case TEE_ALG_AES_CTS:
			/*
			 * These modes doesn't require padding for the last
			 * block.
			 *
			 * This isn't entirely true, both XTS and CTS can only
			 * encrypt minimum one block and also they need at least
			 * one complete block in the last update to finish the
			 * encryption. The algorithms are supposed to detect
			 * that, we're only making sure that all data fed up to
			 * that point consists of complete blocks.
			 */
			break;

		default:
			return TEE_ERROR_NOT_SUPPORTED;
		}
	}

	return crypto_ops.cipher.update(ctx, algo, mode, last_block, data, len,
					dst);
}

/*
 * From http://en.wikipedia.org/wiki/Ciphertext_stealing
 * CBC ciphertext stealing encryption using a standard
 * CBC interface:
 *	1. Pad the last partial plaintext block with 0.
 *	2. Encrypt the whole padded plaintext using the
 *	   standard CBC mode.
 *	3. Swap the last two ciphertext blocks.
 *	4. Truncate the ciphertext to the length of the
 *	   original plaintext.
 *
 * CBC ciphertext stealing decryption using a standard
 * CBC interface
 *	1. Dn = Decrypt (K, Cn-1). Decrypt the second to last
 *	   ciphertext block.
 *	2. Cn = Cn || Tail (Dn, B-M). Pad the ciphertext to the
 *	   nearest multiple of the block size using the last
 *	   B-M bits of block cipher decryption of the
 *	   second-to-last ciphertext block.
 *	3. Swap the last two ciphertext blocks.
 *	4. Decrypt the (modified) ciphertext using the standard
 *	   CBC mode.
 *	5. Truncate the plaintext to the length of the original
 *	   ciphertext.
 */
TEE_Result tee_aes_cbc_cts_update(void *cbc_ctx, void *ecb_ctx,
				  TEE_OperationMode mode, bool last_block,
				  const uint8_t *data, size_t len,
				  uint8_t *dst)
{
	TEE_Result res;
	int nb_blocks, len_last_block, block_size = 16;
	uint8_t tmp_block[64], tmp2_block[64];

	if (!last_block)
		return tee_do_cipher_update(cbc_ctx, TEE_ALG_AES_CBC_NOPAD,
					     mode, last_block, data, len, dst);

	/* Compute the last block length and check constraints */
	nb_blocks = ((len + block_size - 1) / block_size);
	if (nb_blocks < 2)
		return TEE_ERROR_BAD_STATE;
	len_last_block = len % block_size;
	if (len_last_block == 0)
		len_last_block = block_size;

	if (mode == TEE_MODE_ENCRYPT) {
		memcpy(tmp_block,
		       data + ((nb_blocks - 1) * block_size),
		       len_last_block);
		memset(tmp_block + len_last_block,
		       0,
		       block_size - len_last_block);

		res = tee_do_cipher_update(cbc_ctx, TEE_ALG_AES_CBC_NOPAD,
					   mode, 0, data,
					   (nb_blocks - 1) * block_size, dst);
		if (res != TEE_SUCCESS)
			return res;

		memcpy(dst + (nb_blocks - 1) * block_size,
		       dst + (nb_blocks - 2) * block_size,
		       len_last_block);

		res = tee_do_cipher_update(cbc_ctx, TEE_ALG_AES_CBC_NOPAD,
					   mode, 0, tmp_block, block_size,
					   dst + (nb_blocks - 2) * block_size);
		if (res != TEE_SUCCESS)
			return res;
	} else {
		/* 1. Decrypt the second to last ciphertext block */
		res = tee_do_cipher_update(ecb_ctx, TEE_ALG_AES_ECB_NOPAD,
					   mode, 0,
					   data + (nb_blocks - 2) * block_size,
					   block_size, tmp2_block);
		if (res != TEE_SUCCESS)
			return res;

		/* 2. Cn = Cn || Tail (Dn, B-M) */
		memcpy(tmp_block, data + ((nb_blocks - 1) * block_size),
		       len_last_block);
		memcpy(tmp_block + len_last_block, tmp2_block + len_last_block,
		       block_size - len_last_block);

		/* 3. Swap the last two ciphertext blocks */
		/* done by passing the correct buffers in step 4. */

		/* 4. Decrypt the (modified) ciphertext */
		if (nb_blocks > 2) {
			res = tee_do_cipher_update(cbc_ctx,
						   TEE_ALG_AES_CBC_NOPAD, mode,
						   0, data,
						   (nb_blocks - 2) *
						   block_size, dst);
			if (res != TEE_SUCCESS)
				return res;
		}

		res = tee_do_cipher_update(cbc_ctx, TEE_ALG_AES_CBC_NOPAD,
					   mode, 0, tmp_block, block_size,
					   dst +
					   ((nb_blocks - 2) * block_size));
		if (res != TEE_SUCCESS)
			return res;

		res = tee_do_cipher_update(cbc_ctx, TEE_ALG_AES_CBC_NOPAD,
					   mode, 0, data +
					   ((nb_blocks - 2) * block_size),
					   block_size, tmp_block);
		if (res != TEE_SUCCESS)
			return res;

		/* 5. Truncate the plaintext */
		memcpy(dst + (nb_blocks - 1) * block_size, tmp_block,
		       len_last_block);
	}
	return TEE_SUCCESS;
}

TEE_Result tee_prng_add_entropy(const uint8_t *in, size_t len)
{
	if (crypto_ops.prng.add_entropy)
		return crypto_ops.prng.add_entropy(in, len);

	return TEE_SUCCESS;
}

/*
 * Override this in your platform code to feed the PRNG platform-specific
 * jitter entropy. This implementation does not efficiently deliver entropy
 * and is here for backwards-compatibility.
 */
__weak void plat_prng_add_jitter_entropy(void)
{
	TEE_Time current;

	if (tee_time_get_sys_time(&current) == TEE_SUCCESS)
		tee_prng_add_entropy((uint8_t *)&current, sizeof(current));
}

__weak void plat_prng_add_jitter_entropy_norpc(void)
{
#ifndef CFG_SECURE_TIME_SOURCE_REE
	plat_prng_add_jitter_entropy();
#endif
}

static TEE_Result tee_cryp_init(void)
{
	if (crypto_ops.init)
		return crypto_ops.init();

	return TEE_SUCCESS;
}

service_init(tee_cryp_init);
