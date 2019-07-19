// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, Linaro Limited
 */

#include <crypto/crypto.h>
#include <initcall.h>
#include <kernel/panic.h>
#include <kernel/tee_time.h>
#include <rng_support.h>
#include <stdlib.h>
#include <string_ext.h>
#include <string.h>
#include <tee/tee_cryp_utl.h>
#include <trace.h>
#include <utee_defines.h>

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
	TEE_Result res;
	void *ctx = NULL;

	res = crypto_hash_alloc_ctx(&ctx, algo);
	if (res)
		return res;

	res = crypto_hash_init(ctx, algo);
	if (res)
		goto out;

	if (datalen != 0) {
		res = crypto_hash_update(ctx, algo, data, datalen);
		if (res)
			goto out;
	}

	res = crypto_hash_final(ctx, algo, digest, digestlen);
out:
	crypto_hash_free_ctx(ctx, algo);

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

	return crypto_cipher_update(ctx, algo, mode, last_block, data, len,
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

/*
 * Override this in your platform code to feed the PRNG platform-specific
 * jitter entropy. This implementation does not efficiently deliver entropy
 * and is here for backwards-compatibility.
 */
__weak void plat_prng_add_jitter_entropy(enum crypto_rng_src sid,
					 unsigned int *pnum)
{
	TEE_Time current;

#ifdef CFG_SECURE_TIME_SOURCE_REE
	if (CRYPTO_RNG_SRC_IS_QUICK(sid))
		return; /* Can't read REE time here */
#endif

	if (tee_time_get_sys_time(&current) == TEE_SUCCESS)
		crypto_rng_add_event(sid, pnum, &current, sizeof(current));
}

__weak void plat_rng_init(void)
{
	TEE_Result res = TEE_SUCCESS;
	TEE_Time t;

#ifndef CFG_SECURE_TIME_SOURCE_REE
	/*
	 * This isn't much of a seed. Ideally we should either get a seed from
	 * a hardware RNG or from a previously saved seed.
	 *
	 * Seeding with hardware RNG is currently up to the platform to
	 * override this function.
	 *
	 * Seeding with a saved seed will require cooperation from normal
	 * world, this is still TODO.
	 */
	res = tee_time_get_sys_time(&t);
#else
	EMSG("Warning: seeding RNG with zeroes");
	memset(&t, 0, sizeof(t));
#endif
	if (!res)
		res = crypto_rng_init(&t, sizeof(t));
	if (res) {
		EMSG("Failed to initialize RNG: %#" PRIx32, res);
		panic();
	}
}

static TEE_Result tee_cryp_init(void)
{
	TEE_Result res = crypto_init();

	/*
	 * If there is a Cryptographic Driver, we need to
	 * call the initialization function here before using
	 * cryptographic operation during the boot
	 * (e.g. HUK generation)
	 */
	if (res == TEE_SUCCESS)
		res = crypto_driver_init();

	if (res) {
		EMSG("Failed to initialize crypto API: %#" PRIx32, res);
		panic();
	}

	plat_rng_init();

	return TEE_SUCCESS;
}
service_init(tee_cryp_init);
