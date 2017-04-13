/*
 * Copyright (c) 2015, Linaro Limited
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


/*
 * Acronyms:
 *
 * FEK - File Encryption Key
 * SSK - Secure Storage Key
 * TSK - Trusted app Storage Key
 * IV  - Initial vector
 * HUK - Hardware Unique Key
 * RNG - Random Number Generator
 */

#include <initcall.h>
#include <stdlib.h>
#include <string.h>
#include <kernel/panic.h>
#include <kernel/tee_common_otp.h>
#include <kernel/tee_ta_manager.h>
#include <tee/tee_cryp_utl.h>
#include <tee/tee_cryp_provider.h>
#include <tee/tee_fs_key_manager.h>
#include <compiler.h>
#include <trace.h>
#include <util.h>

struct tee_fs_ssk {
	bool is_init;
	uint8_t key[TEE_FS_KM_SSK_SIZE];
};

static struct tee_fs_ssk tee_fs_ssk;
static uint8_t string_for_ssk_gen[] = "ONLY_FOR_tee_fs_ssk";


static TEE_Result do_hmac(void *out_key, size_t out_key_size,
			  const void *in_key, size_t in_key_size,
			  const void *message, size_t message_size)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint8_t *ctx = NULL;
	size_t hash_ctx_size = 0;

	if (!out_key || !in_key || !message)
		return TEE_ERROR_BAD_PARAMETERS;

	res = crypto_ops.mac.get_ctx_size(TEE_FS_KM_HMAC_ALG, &hash_ctx_size);
	if (res != TEE_SUCCESS)
		return res;

	ctx = malloc(hash_ctx_size);
	if (!ctx)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = crypto_ops.mac.init(ctx, TEE_FS_KM_HMAC_ALG, in_key, in_key_size);
	if (res != TEE_SUCCESS)
		goto exit;

	res = crypto_ops.mac.update(ctx, TEE_FS_KM_HMAC_ALG,
			message, message_size);
	if (res != TEE_SUCCESS)
		goto exit;

	res = crypto_ops.mac.final(ctx, TEE_FS_KM_HMAC_ALG, out_key,
				   out_key_size);
	if (res != TEE_SUCCESS)
		goto exit;

	res = TEE_SUCCESS;

exit:
	free(ctx);
	return res;
}

TEE_Result tee_fs_fek_crypt(const TEE_UUID *uuid, TEE_OperationMode mode,
			    const uint8_t *in_key, size_t size,
			    uint8_t *out_key)
{
	TEE_Result res;
	uint8_t *ctx = NULL;
	size_t ctx_size;
	uint8_t tsk[TEE_FS_KM_TSK_SIZE];
	uint8_t dst_key[size];

	if (!in_key || !out_key)
		return TEE_ERROR_BAD_PARAMETERS;

	if (size != TEE_FS_KM_FEK_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	if (tee_fs_ssk.is_init == 0)
		return TEE_ERROR_GENERIC;

	if (uuid) {
		res = do_hmac(tsk, sizeof(tsk), tee_fs_ssk.key,
			      TEE_FS_KM_SSK_SIZE, uuid, sizeof(*uuid));
		if (res != TEE_SUCCESS)
			return res;
	} else {
		/*
		 * Pick something of a different size than TEE_UUID to
		 * guarantee that there's never a conflict.
		 */
		uint8_t dummy[1] = { 0 };

		res = do_hmac(tsk, sizeof(tsk), tee_fs_ssk.key,
			      TEE_FS_KM_SSK_SIZE, dummy, sizeof(dummy));
		if (res != TEE_SUCCESS)
			return res;
	}

	res = crypto_ops.cipher.get_ctx_size(TEE_FS_KM_ENC_FEK_ALG, &ctx_size);
	if (res != TEE_SUCCESS)
		return res;

	ctx = malloc(ctx_size);
	if (!ctx)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = crypto_ops.cipher.init(ctx, TEE_FS_KM_ENC_FEK_ALG, mode, tsk,
				     sizeof(tsk), NULL, 0, NULL, 0);
	if (res != TEE_SUCCESS)
		goto exit;

	res = crypto_ops.cipher.update(ctx, TEE_FS_KM_ENC_FEK_ALG,
			mode, true, in_key, size, dst_key);
	if (res != TEE_SUCCESS)
		goto exit;

	crypto_ops.cipher.final(ctx, TEE_FS_KM_ENC_FEK_ALG);

	memcpy(out_key, dst_key, sizeof(dst_key));

exit:
	free(ctx);

	return res;
}

static TEE_Result generate_fek(uint8_t *key, uint8_t len)
{
	return crypto_ops.prng.read(key, len);
}

static TEE_Result tee_fs_init_key_manager(void)
{
	int res = TEE_SUCCESS;
	struct tee_hw_unique_key huk;
	uint8_t chip_id[TEE_FS_KM_CHIP_ID_LENGTH];
	uint8_t message[sizeof(chip_id) + sizeof(string_for_ssk_gen)];

	/* Secure Storage Key Generation:
	 *
	 *     SSK = HMAC(HUK, message)
	 *     message := concatenate(chip_id, static string)
	 * */
	tee_otp_get_hw_unique_key(&huk);
	tee_otp_get_die_id(chip_id, sizeof(chip_id));

	memcpy(message, chip_id, sizeof(chip_id));
	memcpy(message + sizeof(chip_id), string_for_ssk_gen,
			sizeof(string_for_ssk_gen));

	res = do_hmac(tee_fs_ssk.key, sizeof(tee_fs_ssk.key),
			huk.data, sizeof(huk.data),
			message, sizeof(message));

	if (res == TEE_SUCCESS)
		tee_fs_ssk.is_init = 1;

	return res;
}

TEE_Result tee_fs_generate_fek(const TEE_UUID *uuid, void *buf, size_t buf_size)
{
	TEE_Result res;

	if (buf_size != TEE_FS_KM_FEK_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	res = generate_fek(buf, TEE_FS_KM_FEK_SIZE);
	if (res != TEE_SUCCESS)
		return res;

	return tee_fs_fek_crypt(uuid, TEE_MODE_ENCRYPT, buf,
				TEE_FS_KM_FEK_SIZE, buf);
}

static TEE_Result sha256(uint8_t *out, size_t out_size, const uint8_t *in,
			 size_t in_size)
{
	TEE_Result res;
	uint8_t *ctx = NULL;
	size_t ctx_size;
	uint32_t algo = TEE_ALG_SHA256;

	res = crypto_ops.hash.get_ctx_size(algo, &ctx_size);
	if (res != TEE_SUCCESS)
		return res;

	ctx = malloc(ctx_size);
	if (!ctx)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = crypto_ops.hash.init(ctx, algo);
	if (res != TEE_SUCCESS)
		goto out;

	res = crypto_ops.hash.update(ctx, algo, in, in_size);
	if (res != TEE_SUCCESS)
		goto out;

	res = crypto_ops.hash.final(ctx, algo, out, out_size);

out:
	free(ctx);
	return res;
}

static TEE_Result aes_ecb(uint8_t out[TEE_AES_BLOCK_SIZE],
			  const uint8_t in[TEE_AES_BLOCK_SIZE],
			  const uint8_t *key, size_t key_size)
{
	TEE_Result res;
	uint8_t *ctx = NULL;
	size_t ctx_size;
	uint32_t algo = TEE_ALG_AES_ECB_NOPAD;

	res = crypto_ops.cipher.get_ctx_size(algo, &ctx_size);
	if (res != TEE_SUCCESS)
		return res;

	ctx = malloc(ctx_size);
	if (!ctx)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = crypto_ops.cipher.init(ctx, algo, TEE_MODE_ENCRYPT, key,
				     key_size, NULL, 0, NULL, 0);
	if (res != TEE_SUCCESS)
		goto out;

	res = crypto_ops.cipher.update(ctx, algo, TEE_MODE_ENCRYPT, true, in,
				       TEE_AES_BLOCK_SIZE, out);
	if (res != TEE_SUCCESS)
		goto out;

	crypto_ops.cipher.final(ctx, algo);
	res = TEE_SUCCESS;

out:
	free(ctx);
	return res;
}

static TEE_Result essiv(uint8_t iv[TEE_AES_BLOCK_SIZE],
			const uint8_t fek[TEE_FS_KM_FEK_SIZE],
			uint16_t blk_idx)
{
	TEE_Result res;
	uint8_t sha[TEE_SHA256_HASH_SIZE];
	uint8_t pad_blkid[TEE_AES_BLOCK_SIZE] = { 0, };

	res = sha256(sha, sizeof(sha), fek, TEE_FS_KM_FEK_SIZE);
	if (res != TEE_SUCCESS)
		return res;

	pad_blkid[0] = (blk_idx & 0xFF);
	pad_blkid[1] = (blk_idx & 0xFF00) >> 8;

	return aes_ecb(iv, pad_blkid, sha, 16);
}

/*
 * Encryption/decryption of RPMB FS file data. This is AES CBC with ESSIV.
 */
TEE_Result tee_fs_crypt_block(const TEE_UUID *uuid, uint8_t *out,
			      const uint8_t *in, size_t size,
			      uint16_t blk_idx, const uint8_t *encrypted_fek,
			      TEE_OperationMode mode)
{
	TEE_Result res;
	uint8_t fek[TEE_FS_KM_FEK_SIZE];
	uint8_t iv[TEE_AES_BLOCK_SIZE];
	uint8_t *ctx;
	size_t ctx_size;
	uint32_t algo = TEE_ALG_AES_CBC_NOPAD;

	DMSG("%scrypt block #%u", (mode == TEE_MODE_ENCRYPT) ? "En" : "De",
	     blk_idx);

	/* Decrypt FEK */
	res = tee_fs_fek_crypt(uuid, TEE_MODE_DECRYPT, encrypted_fek,
			       TEE_FS_KM_FEK_SIZE, fek);
	if (res != TEE_SUCCESS)
		return res;

	/* Compute initialization vector for this block */
	res = essiv(iv, fek, blk_idx);

	/* Run AES CBC */
	res = crypto_ops.cipher.get_ctx_size(algo, &ctx_size);
	if (res != TEE_SUCCESS)
		return res;
	ctx = malloc(ctx_size);
	if (!ctx)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = crypto_ops.cipher.init(ctx, algo, mode, fek, sizeof(fek), NULL,
				     0, iv, TEE_AES_BLOCK_SIZE);
	if (res != TEE_SUCCESS)
		goto exit;
	res = crypto_ops.cipher.update(ctx, algo, mode, true, in, size, out);
	if (res != TEE_SUCCESS)
		goto exit;

	crypto_ops.cipher.final(ctx, algo);

exit:
	free(ctx);
	return res;
}

service_init_late(tee_fs_init_key_manager);
