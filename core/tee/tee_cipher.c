/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
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

#include "tee_ltc_wrapper.h"
#include <kernel/tee_common_unpg.h>
#include <tee/tee_cipher.h>

/* From libtomcrypt doc:
 *	Ciphertext stealing is a method of dealing with messages
 *	in CBC mode which are not a multiple of the block
 *	length.  This is accomplished by encrypting the last
 *	ciphertext block in ECB mode, and XOR'ing the output
 *	against the last partial block of plaintext. LibTomCrypt
 *	does not support this mode directly but it is fairly
 *	easy to emulate with a call to the cipher's
 *	ecb encrypt() callback function.
 *	The more sane way to deal with partial blocks is to pad
 *	them with zeroes, and then use CBC normally
 */

/*
 * From Global Platform: CTS = CBC-CS3
 */

struct tee_symmetric_cts {
	symmetric_ECB ecb;
	symmetric_CBC cbc;
};

#define XTS_TWEAK_SIZE 16
struct tee_symmetric_xts {
	symmetric_xts ctx;
	uint8_t tweak[XTS_TWEAK_SIZE];
};

TEE_Result tee_cipher_get_block_size(uint32_t algo, size_t *size)
{
	TEE_Result res;
	int ltc_cipherindex;

	res = tee_algo_to_ltc_cipherindex(algo, &ltc_cipherindex);
	if (res != TEE_SUCCESS)
		return TEE_ERROR_NOT_SUPPORTED;

	*size = cipher_descriptor[ltc_cipherindex].block_length;
	return TEE_SUCCESS;
}

TEE_Result tee_cipher_get_ctx_size(uint32_t algo, size_t *size)
{
	switch (algo) {
	case TEE_ALG_AES_ECB_NOPAD:
		*size = sizeof(symmetric_ECB);
		break;
	case TEE_ALG_AES_CBC_NOPAD:
		*size = sizeof(symmetric_CBC);
		break;
	case TEE_ALG_AES_CTR:
		*size = sizeof(symmetric_CTR);
		break;
	case TEE_ALG_AES_CTS:
		*size = sizeof(struct tee_symmetric_cts);
		break;
	case TEE_ALG_AES_XTS:
		*size = sizeof(struct tee_symmetric_xts);
		break;
	case TEE_ALG_DES_ECB_NOPAD:
		*size = sizeof(symmetric_ECB);
		break;
	case TEE_ALG_DES_CBC_NOPAD:
		*size = sizeof(symmetric_CBC);
		break;
	case TEE_ALG_DES3_ECB_NOPAD:
		*size = sizeof(symmetric_ECB);
		break;
	case TEE_ALG_DES3_CBC_NOPAD:
		*size = sizeof(symmetric_CBC);
		break;

	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
}

TEE_Result tee_cipher_init(void *ctx, uint32_t algo,
			   TEE_OperationMode mode, const uint8_t *key,
			   size_t key_len)
{
	return tee_cipher_init3(ctx, algo, mode, key, key_len, NULL, 0, NULL,
				0);
}

TEE_Result tee_cipher_init2(void *ctx, uint32_t algo,
			    TEE_OperationMode mode, const uint8_t *key,
			    size_t key_len, const uint8_t *iv, size_t iv_len)
{
	return tee_cipher_init3(ctx, algo, mode, key, key_len, NULL, 0, iv,
				iv_len);
}

static void get_des2_key(
	const uint8_t *key, size_t key_len,
	uint8_t *key_intermediate,
	uint8_t **real_key, size_t *real_key_len)
{
	if (key_len == 16) {
		/*
		 * This corresponds to a 2DES key. The 2DES encryption
		 * algorithm is similar to 3DES. Both perform and
		 * encryption step, then a decryption step, followed
		 * by another encryption step (EDE). However 2DES uses
		 * the same key for both of the encryption (E) steps.
		 */
		memcpy(key_intermediate, key, 16);
		memcpy(key_intermediate+16, key, 8);
		*real_key = key_intermediate;
		*real_key_len = 24;
	} else {
		*real_key = (uint8_t *)key;
		*real_key_len = key_len;
	}
}

TEE_Result tee_cipher_init3(void *ctx, uint32_t algo,
			    TEE_OperationMode mode, const uint8_t *key1,
			    size_t key1_len, const uint8_t *key2,
			    size_t key2_len, const uint8_t *iv, size_t iv_len)
{
	TEE_Result res;
	int ltc_res, ltc_cipherindex;
	uint8_t *real_key, key_array[24];
	size_t real_key_len;
	struct tee_symmetric_cts *cts;
	struct tee_symmetric_xts *xts;

	res = tee_algo_to_ltc_cipherindex(algo, &ltc_cipherindex);
	if (res != TEE_SUCCESS)
		return TEE_ERROR_NOT_SUPPORTED;

	switch (algo) {
	case TEE_ALG_AES_ECB_NOPAD:
	case TEE_ALG_DES_ECB_NOPAD:
		ltc_res = ecb_start(
			ltc_cipherindex, key1, key1_len,
			0, (symmetric_ECB *)ctx);
		break;

	case TEE_ALG_DES3_ECB_NOPAD:
		/* either des3 or des2, depending on the size of the key */
		get_des2_key(key1, key1_len, key_array,
			     &real_key, &real_key_len);
		ltc_res = ecb_start(
			ltc_cipherindex, real_key, real_key_len,
			0, (symmetric_ECB *)ctx);
		break;

	case TEE_ALG_AES_CBC_NOPAD:
	case TEE_ALG_DES_CBC_NOPAD:
		if (iv_len !=
		    (size_t)cipher_descriptor[ltc_cipherindex].block_length)
			return TEE_ERROR_BAD_PARAMETERS;
		ltc_res = cbc_start(
			ltc_cipherindex, iv, key1, key1_len,
			0, (symmetric_CBC *)ctx);
		break;

	case TEE_ALG_DES3_CBC_NOPAD:
		/* either des3 or des2, depending on the size of the key */
		get_des2_key(key1, key1_len, key_array,
			     &real_key, &real_key_len);
		if (iv_len !=
		    (size_t)cipher_descriptor[ltc_cipherindex].block_length)
			return TEE_ERROR_BAD_PARAMETERS;
		ltc_res = cbc_start(
			ltc_cipherindex, iv, real_key, real_key_len,
			0, (symmetric_CBC *)ctx);
		break;

	case TEE_ALG_AES_CTR:
		if (iv_len !=
		    (size_t)cipher_descriptor[ltc_cipherindex].block_length)
			return TEE_ERROR_BAD_PARAMETERS;
		ltc_res = ctr_start(
			ltc_cipherindex, iv, key1, key1_len,
			0, CTR_COUNTER_BIG_ENDIAN, (symmetric_CTR *)ctx);
		break;

	case TEE_ALG_AES_CTS:
		cts = (struct tee_symmetric_cts *)ctx;
		res = tee_cipher_init3(
			(void *)(&(cts->ecb)),
			TEE_ALG_AES_ECB_NOPAD, mode,
			key1, key1_len, key2, key2_len, iv, iv_len);
		if (res != TEE_SUCCESS)
			return res;
		res = tee_cipher_init3(
			(void *)(&(cts->cbc)),
			TEE_ALG_AES_CBC_NOPAD, mode,
			key1, key1_len, key2, key2_len, iv, iv_len);
		if (res != TEE_SUCCESS)
			return res;
		ltc_res = CRYPT_OK;
		break;

	case TEE_ALG_AES_XTS:
		xts = ctx;
		if (key1_len != key2_len)
			return TEE_ERROR_BAD_PARAMETERS;
		if (iv) {
			if (iv_len != XTS_TWEAK_SIZE)
				return TEE_ERROR_BAD_PARAMETERS;
			memcpy(xts->tweak, iv, iv_len);
		} else {
			memset(xts->tweak, 0, XTS_TWEAK_SIZE);
		}
		ltc_res = xts_start(
			ltc_cipherindex, key1, key2, key1_len,
			0, &xts->ctx);
		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	if (ltc_res == CRYPT_OK)
		return TEE_SUCCESS;
	else
		return TEE_ERROR_BAD_STATE;
}

TEE_Result tee_cipher_update(void *ctx, uint32_t algo,
			     TEE_OperationMode mode, bool last_block,
			     const uint8_t *data, size_t len, uint8_t *dst)
{
	TEE_Result res;
	int ltc_res = CRYPT_OK;
	size_t block_size;
	uint8_t tmp_block[64], tmp2_block[64];
	int nb_blocks, len_last_block;
	struct tee_symmetric_cts *cts;
	struct tee_symmetric_xts *xts;

	/*
	 * Check that the block contains the correct number of data, apart
	 * for the last block in some XTS / CTR / XTS mode
	 */
	res = tee_cipher_get_block_size(algo, &block_size);
	if (res != TEE_SUCCESS)
		return res;
	if ((len % block_size) != 0) {
		if (!last_block)
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

	switch (algo) {
	case TEE_ALG_AES_ECB_NOPAD:
	case TEE_ALG_DES_ECB_NOPAD:
	case TEE_ALG_DES3_ECB_NOPAD:
		if (mode == TEE_MODE_ENCRYPT)
		    ltc_res = ecb_encrypt(data, dst, len, (symmetric_ECB *)ctx);
		else
		    ltc_res = ecb_decrypt(data, dst, len, (symmetric_ECB *)ctx);
		break;

	case TEE_ALG_AES_CBC_NOPAD:
	case TEE_ALG_DES_CBC_NOPAD:
	case TEE_ALG_DES3_CBC_NOPAD:
		if (mode == TEE_MODE_ENCRYPT)
		    ltc_res = cbc_encrypt(data, dst, len, (symmetric_CBC *)ctx);
		else
		    ltc_res = cbc_decrypt(data, dst, len, (symmetric_CBC *)ctx);
		break;

	case TEE_ALG_AES_CTR:
		if (mode == TEE_MODE_ENCRYPT)
		    ltc_res = ctr_encrypt(data, dst, len, (symmetric_CTR *)ctx);
		else
		    ltc_res = ctr_decrypt(data, dst, len, (symmetric_CTR *)ctx);
		break;

	case TEE_ALG_AES_XTS:
		xts = ctx;
		if (mode == TEE_MODE_ENCRYPT)
			ltc_res = xts_encrypt(
					data, len, dst, xts->tweak, &xts->ctx);
		else
			ltc_res = xts_decrypt(
					data, len, dst, xts->tweak, &xts->ctx);
		break;

	case TEE_ALG_AES_CTS:
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
		cts = (struct tee_symmetric_cts *)ctx;
		if (!last_block)
			return tee_cipher_update(
				&cts->cbc, TEE_ALG_AES_CBC_NOPAD, mode,
				last_block, data, len, dst);

		/* Compute the last block length and check constraints */
		if (block_size > 64)
			return TEE_ERROR_BAD_STATE;
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

			res = tee_cipher_update(
				&cts->cbc, TEE_ALG_AES_CBC_NOPAD, mode, 0,
				data, (nb_blocks - 1) * block_size, dst);
			if (res != TEE_SUCCESS)
				return res;

			memcpy(dst + (nb_blocks - 1) * block_size,
			       dst + (nb_blocks - 2) * block_size,
			       len_last_block);

			res = tee_cipher_update(
				&cts->cbc, TEE_ALG_AES_CBC_NOPAD, mode, 0,
				tmp_block,
				block_size,
				dst + (nb_blocks - 2) * block_size);
			if (res != TEE_SUCCESS)
				return res;
		} else {
			/* 1. Decrypt the second to last ciphertext block */
			res = tee_cipher_update(
				&cts->ecb, TEE_ALG_AES_ECB_NOPAD, mode, 0,
				data + (nb_blocks - 2) * block_size,
				block_size,
				tmp2_block);
			if (res != TEE_SUCCESS)
				return res;

			/* 2. Cn = Cn || Tail (Dn, B-M) */
			memcpy(tmp_block,
			       data + ((nb_blocks - 1) * block_size),
			       len_last_block);
			memcpy(tmp_block + len_last_block,
			       tmp2_block + len_last_block,
			       block_size - len_last_block);

			/* 3. Swap the last two ciphertext blocks */
			/* done by passing the correct buffers in step 4. */

			/* 4. Decrypt the (modified) ciphertext */
			if (nb_blocks > 2) {
				res = tee_cipher_update(
					&cts->cbc, TEE_ALG_AES_CBC_NOPAD,
					mode, 0,
					data,
					(nb_blocks - 2) * block_size,
					dst);
				if (res != TEE_SUCCESS)
					return res;
			}

			res = tee_cipher_update(
				&cts->cbc, TEE_ALG_AES_CBC_NOPAD, mode, 0,
				tmp_block,
				block_size,
				dst + ((nb_blocks - 2) * block_size));
			if (res != TEE_SUCCESS)
				return res;

			res = tee_cipher_update(
				&cts->cbc, TEE_ALG_AES_CBC_NOPAD, mode, 0,
				data + ((nb_blocks - 2) * block_size),
				block_size,
				tmp_block);
			if (res != TEE_SUCCESS)
				return res;

			/* 5. Truncate the plaintext */
			memcpy(dst + (nb_blocks - 1) * block_size,
			       tmp_block,
			       len_last_block);
			break;
		}
		break;

	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	if (ltc_res == CRYPT_OK)
		return TEE_SUCCESS;
	else
		return TEE_ERROR_BAD_STATE;
}

void tee_cipher_final(void *ctx, uint32_t algo)
{
	switch (algo) {
	case TEE_ALG_AES_ECB_NOPAD:
	case TEE_ALG_DES_ECB_NOPAD:
	case TEE_ALG_DES3_ECB_NOPAD:
		ecb_done((symmetric_ECB *)ctx);
		break;

	case TEE_ALG_AES_CBC_NOPAD:
	case TEE_ALG_DES_CBC_NOPAD:
	case TEE_ALG_DES3_CBC_NOPAD:
		cbc_done((symmetric_CBC *)ctx);
		break;

	case TEE_ALG_AES_CTR:
		ctr_done((symmetric_CTR *)ctx);
		break;

	case TEE_ALG_AES_XTS:
		xts_done(&(((struct tee_symmetric_xts *)ctx)->ctx));
		break;

	case TEE_ALG_AES_CTS:
		cbc_done(&(((struct tee_symmetric_cts *)ctx)->cbc));
		ecb_done(&(((struct tee_symmetric_cts *)ctx)->ecb));
		break;

	default:
		/* TEE_ERROR_NOT_SUPPORTED; */
		break;
	}
}
