// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015, Linaro Limited
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

#include <assert.h>
#include <compiler.h>
#include <crypto/crypto.h>
#include <initcall.h>
#include <kernel/huk_subkey.h>
#include <kernel/tee_common_otp.h>
#include <kernel/tee_ta_manager.h>
#include <stdlib.h>
#include <string.h>
#include <string_ext.h>
#include <tee/tee_cryp_utl.h>
#include <tee/tee_fs_key_manager.h>
#include <trace.h>
#include <util.h>

struct tee_fs_ssk {
	bool is_init;
	uint8_t key[TEE_FS_KM_SSK_SIZE];
};

static struct tee_fs_ssk tee_fs_ssk;

static TEE_Result do_hmac(void *out_key, size_t out_key_size,
			  const void *in_key, size_t in_key_size,
			  const void *message, size_t message_size)
{
	TEE_Result res;
	void *ctx = NULL;

	if (!out_key || !in_key || !message)
		return TEE_ERROR_BAD_PARAMETERS;

	res = crypto_mac_alloc_ctx(&ctx, TEE_FS_KM_HMAC_ALG);
	if (res != TEE_SUCCESS)
		return res;

	res = crypto_mac_init(ctx, in_key, in_key_size);
	if (res != TEE_SUCCESS)
		goto exit;

	res = crypto_mac_update(ctx, message, message_size);
	if (res != TEE_SUCCESS)
		goto exit;

	res = crypto_mac_final(ctx, out_key, out_key_size);
	if (res != TEE_SUCCESS)
		goto exit;

	res = TEE_SUCCESS;

exit:
	crypto_mac_free_ctx(ctx);
	return res;
}

TEE_Result tee_fs_fek_crypt(const TEE_UUID *uuid, TEE_OperationMode mode,
			    const uint8_t *in_key, size_t size,
			    uint8_t *out_key)
{
	TEE_Result res;
	void *ctx = NULL;
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

	res = crypto_cipher_alloc_ctx(&ctx, TEE_FS_KM_ENC_FEK_ALG);
	if (res != TEE_SUCCESS)
		return res;

	res = crypto_cipher_init(ctx, mode, tsk, sizeof(tsk), NULL, 0, NULL, 0);
	if (res != TEE_SUCCESS)
		goto exit;

	res = crypto_cipher_update(ctx, mode, true, in_key, size, dst_key);
	if (res != TEE_SUCCESS)
		goto exit;

	crypto_cipher_final(ctx);

	memcpy(out_key, dst_key, sizeof(dst_key));

exit:
	crypto_cipher_free_ctx(ctx);
	memzero_explicit(tsk, sizeof(tsk));
	memzero_explicit(dst_key, sizeof(dst_key));

	return res;
}

static TEE_Result generate_fek(uint8_t *key, uint8_t len)
{
	return crypto_rng_read(key, len);
}

static TEE_Result tee_fs_init_key_manager(void)
{
	TEE_Result res = TEE_SUCCESS;

	COMPILE_TIME_ASSERT(TEE_FS_KM_SSK_SIZE <= HUK_SUBKEY_MAX_LEN);

	res = huk_subkey_derive(HUK_SUBKEY_SSK, NULL, 0,
				tee_fs_ssk.key, sizeof(tee_fs_ssk.key));
	if (res == TEE_SUCCESS)
		tee_fs_ssk.is_init = 1;
	else
		memzero_explicit(&tee_fs_ssk, sizeof(tee_fs_ssk));

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
	return tee_hash_createdigest(TEE_ALG_SHA256, in, in_size,
				     out, out_size);
}

static TEE_Result aes_ecb(uint8_t out[TEE_AES_BLOCK_SIZE],
			  const uint8_t in[TEE_AES_BLOCK_SIZE],
			  const uint8_t *key, size_t key_size)
{
	TEE_Result res;
	void *ctx = NULL;

	res = crypto_cipher_alloc_ctx(&ctx, TEE_ALG_AES_ECB_NOPAD);
	if (res != TEE_SUCCESS)
		return res;

	res = crypto_cipher_init(ctx, TEE_MODE_ENCRYPT, key,
				 key_size, NULL, 0, NULL, 0);
	if (res != TEE_SUCCESS)
		goto out;

	res = crypto_cipher_update(ctx, TEE_MODE_ENCRYPT, true, in,
				   TEE_AES_BLOCK_SIZE, out);
	if (res != TEE_SUCCESS)
		goto out;

	crypto_cipher_final(ctx);
	res = TEE_SUCCESS;

out:
	crypto_cipher_free_ctx(ctx);
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

	res = aes_ecb(iv, pad_blkid, sha, 16);

	memzero_explicit(sha, sizeof(sha));
	return res;
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
	void *ctx;

	DMSG("%scrypt block #%u", (mode == TEE_MODE_ENCRYPT) ? "En" : "De",
	     blk_idx);

	/* Decrypt FEK */
	res = tee_fs_fek_crypt(uuid, TEE_MODE_DECRYPT, encrypted_fek,
			       TEE_FS_KM_FEK_SIZE, fek);
	if (res != TEE_SUCCESS)
		goto wipe;

	/* Compute initialization vector for this block */
	res = essiv(iv, fek, blk_idx);
	if (res != TEE_SUCCESS)
		goto wipe;

	/* Run AES CBC */
	res = crypto_cipher_alloc_ctx(&ctx, TEE_ALG_AES_CBC_NOPAD);
	if (res != TEE_SUCCESS)
		goto wipe;

	res = crypto_cipher_init(ctx, mode, fek, sizeof(fek), NULL,
				 0, iv, TEE_AES_BLOCK_SIZE);
	if (res != TEE_SUCCESS)
		goto exit;
	res = crypto_cipher_update(ctx, mode, true, in, size, out);
	if (res != TEE_SUCCESS)
		goto exit;

	crypto_cipher_final(ctx);

exit:
	crypto_cipher_free_ctx(ctx);
wipe:
	memzero_explicit(fek, sizeof(fek));
	memzero_explicit(iv, sizeof(iv));
	return res;
}

service_init_late(tee_fs_init_key_manager);
