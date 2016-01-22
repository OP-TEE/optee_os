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


/* Acronyms:
 *
 * FEK - File Encryption Key
 * SST - Secure Storage
 * SSK - Secure Storage Key
 * IV  - Initial vector
 * HUK - Hardware Unique Key
 * RNG - Random Number Generator
 *
 * */

#include <initcall.h>
#include <stdlib.h>
#include <string.h>
#include <kernel/tee_common_otp.h>
#include <kernel/tee_common_unpg.h>
#include <tee/tee_cryp_utl.h>
#include <tee/tee_cryp_provider.h>
#include <tee/tee_fs_key_manager.h>
#include <compiler.h>
#include <trace.h>

struct tee_fs_ssk {
	bool is_init;
	uint8_t key[TEE_FS_KM_SSK_SIZE];
};

struct aad {
	const uint8_t *encrypted_key;
	const uint8_t *iv;
};

struct km_header {
	struct aad aad;
	uint8_t *tag;
};

static struct tee_fs_ssk tee_fs_ssk;
static uint8_t string_for_ssk_gen[] = "ONLY_FOR_tee_fs_ssk";


static TEE_Result fek_crypt(TEE_OperationMode mode,
		uint8_t *key, int size)
{
	TEE_Result res;
	uint8_t *ctx = NULL;
	size_t ctx_size;
	uint8_t dst_key[TEE_FS_KM_FEK_SIZE];

	if (!key)
		return TEE_ERROR_BAD_PARAMETERS;

	if (size != TEE_FS_KM_FEK_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	if (tee_fs_ssk.is_init == 0)
		return TEE_ERROR_GENERIC;

	res = crypto_ops.cipher.get_ctx_size(TEE_FS_KM_ENC_FEK_ALG, &ctx_size);
	if (res != TEE_SUCCESS)
		return res;

	ctx = malloc(ctx_size);
	if (!ctx)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = crypto_ops.cipher.init(ctx, TEE_FS_KM_ENC_FEK_ALG,
			mode, tee_fs_ssk.key, TEE_FS_KM_SSK_SIZE,
			NULL, 0, NULL, 0);
	if (res != TEE_SUCCESS)
		goto exit;

	res = crypto_ops.cipher.update(ctx, TEE_FS_KM_ENC_FEK_ALG,
			mode, true, key, size, dst_key);
	if (res != TEE_SUCCESS)
		goto exit;

	crypto_ops.cipher.final(ctx, TEE_FS_KM_ENC_FEK_ALG);

	memcpy(key, dst_key, sizeof(dst_key));

exit:
	free(ctx);

	return res;
}

static TEE_Result generate_fek(uint8_t *key, uint8_t len)
{
	return crypto_ops.prng.read(key, len);
}

static TEE_Result generate_iv(uint8_t *iv, uint8_t len)
{
	return crypto_ops.prng.read(iv, len);
}

static TEE_Result generate_ssk(uint8_t *ssk, uint32_t ssk_size,
			uint8_t *huk, uint32_t huk_size,
			uint8_t *message, uint32_t message_size)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint8_t *ctx = NULL;
	size_t hash_ctx_size = 0;

	if (!ssk || !huk || !message)
		return TEE_ERROR_BAD_PARAMETERS;

	res = crypto_ops.mac.get_ctx_size(TEE_FS_KM_HMAC_ALG, &hash_ctx_size);
	if (res != TEE_SUCCESS)
		return res;

	ctx = malloc(hash_ctx_size);
	if (!ctx)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = crypto_ops.mac.init(ctx, TEE_FS_KM_HMAC_ALG, huk, huk_size);
	if (res != TEE_SUCCESS)
		goto exit;

	res = crypto_ops.mac.update(ctx, TEE_FS_KM_HMAC_ALG,
			message, message_size);
	if (res != TEE_SUCCESS)
		goto exit;

	res = crypto_ops.mac.final(ctx, TEE_FS_KM_HMAC_ALG, ssk, ssk_size);
	if (res != TEE_SUCCESS)
		goto exit;

	res = TEE_SUCCESS;

exit:
	free(ctx);
	return res;
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

	res = generate_ssk(tee_fs_ssk.key, sizeof(tee_fs_ssk.key),
			huk.data, sizeof(huk.data),
			message, sizeof(message));

	if (res == TEE_SUCCESS)
		tee_fs_ssk.is_init = 1;

	return res;
}

static TEE_Result do_auth_enc(TEE_OperationMode mode,
		struct km_header *hdr,
		uint8_t *fek, int fek_len,
		const uint8_t *data_in, size_t in_size,
		uint8_t *data_out, size_t *out_size)
{
	TEE_Result res = TEE_SUCCESS;
	uint8_t *ctx = NULL;
	size_t ctx_size;
	size_t tag_len = TEE_FS_KM_MAX_TAG_LEN;

	if ((mode != TEE_MODE_ENCRYPT) && (mode != TEE_MODE_DECRYPT))
		return TEE_ERROR_BAD_PARAMETERS;

	if (*out_size < in_size) {
		EMSG("output buffer(%zd) < input buffer(%zd)",
				*out_size, in_size);
		return TEE_ERROR_SHORT_BUFFER;
	}

	res = crypto_ops.authenc.get_ctx_size(TEE_FS_KM_AUTH_ENC_ALG,
			&ctx_size);
	if (res != TEE_SUCCESS)
		return res;

	ctx = malloc(ctx_size);
	if (!ctx) {
		EMSG("request memory size %zu failed", ctx_size);
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	res = crypto_ops.authenc.init(ctx, TEE_FS_KM_AUTH_ENC_ALG,
			mode, fek, fek_len, hdr->aad.iv,
			TEE_FS_KM_IV_LEN, TEE_FS_KM_MAX_TAG_LEN,
			sizeof(struct aad), in_size);
	if (res != TEE_SUCCESS)
		goto exit;

	res = crypto_ops.authenc.update_aad(ctx, TEE_FS_KM_AUTH_ENC_ALG,
			mode, (uint8_t *)hdr->aad.encrypted_key,
			TEE_FS_KM_FEK_SIZE);
	if (res != TEE_SUCCESS)
		goto exit;

	res = crypto_ops.authenc.update_aad(ctx, TEE_FS_KM_AUTH_ENC_ALG,
			mode, (uint8_t *)hdr->aad.iv,
			TEE_FS_KM_IV_LEN);
	if (res != TEE_SUCCESS)
		goto exit;

	if (mode == TEE_MODE_ENCRYPT) {
		res = crypto_ops.authenc.enc_final(ctx, TEE_FS_KM_AUTH_ENC_ALG,
				data_in, in_size, data_out, out_size,
				hdr->tag, &tag_len);
	} else {
		res = crypto_ops.authenc.dec_final(ctx, TEE_FS_KM_AUTH_ENC_ALG,
				data_in, in_size, data_out, out_size,
				hdr->tag, tag_len);
	}

	if (res != TEE_SUCCESS)
		goto exit;

	crypto_ops.authenc.final(ctx, TEE_FS_KM_AUTH_ENC_ALG);

exit:
	free(ctx);
	return res;
}

size_t tee_fs_get_header_size(enum tee_fs_file_type type)
{
	size_t header_size = 0;

	switch (type) {
	case META_FILE:
		header_size = sizeof(struct meta_header);
		break;
	case BLOCK_FILE:
		header_size = sizeof(struct block_header);
		break;
	default:
		EMSG("Unknown file type, type=%d", type);
		TEE_ASSERT(0);
	}

	return header_size;
}

TEE_Result tee_fs_generate_fek(uint8_t *buf, int buf_size)
{
	TEE_Result res;

	if (buf_size != TEE_FS_KM_FEK_SIZE)
		return TEE_ERROR_SHORT_BUFFER;

	res = generate_fek(buf, TEE_FS_KM_FEK_SIZE);
	if (res != TEE_SUCCESS)
		return res;

	return fek_crypt(TEE_MODE_ENCRYPT, buf,
			TEE_FS_KM_FEK_SIZE);
}

TEE_Result tee_fs_encrypt_file(enum tee_fs_file_type file_type,
		const uint8_t *data_in, size_t data_in_size,
		uint8_t *data_out, size_t *data_out_size,
		const uint8_t *encrypted_fek)
{
	TEE_Result res = TEE_SUCCESS;
	struct km_header hdr;
	uint8_t iv[TEE_FS_KM_IV_LEN];
	uint8_t tag[TEE_FS_KM_MAX_TAG_LEN];
	uint8_t fek[TEE_FS_KM_FEK_SIZE];
	uint8_t *ciphertext;
	size_t cipher_size;
	size_t header_size = tee_fs_get_header_size(file_type);

	/*
	 * Meta File Format: |Header|Chipertext|
	 * Header Format:    |AAD|Tag|
	 * AAD Format:       |Encrypted_FEK|IV|
	 *
	 * Block File Format: |Header|Ciphertext|
	 * Header Format:     |IV|Tag|
	 *
	 * FEK = AES_DECRYPT(SSK, Encrypted_FEK)
	 * Chipertext = AES_GCM_ENCRYPT(FEK, IV, Meta_Info, AAD)
	 */

	if (*data_out_size != (header_size + data_in_size))
		return TEE_ERROR_SHORT_BUFFER;

	res = generate_iv(iv, TEE_FS_KM_IV_LEN);
	if (res != TEE_SUCCESS)
		goto fail;

	memcpy(fek, encrypted_fek, TEE_FS_KM_FEK_SIZE);
	res = fek_crypt(TEE_MODE_DECRYPT, fek, TEE_FS_KM_FEK_SIZE);
	if (res != TEE_SUCCESS)
		goto fail;

	ciphertext = data_out + header_size;
	cipher_size = data_in_size;

	hdr.aad.iv = iv;
	hdr.aad.encrypted_key = encrypted_fek;
	hdr.tag = tag;

	res = do_auth_enc(TEE_MODE_ENCRYPT, &hdr,
			fek, TEE_FS_KM_FEK_SIZE,
			data_in, data_in_size,
			ciphertext, &cipher_size);

	if (res == TEE_SUCCESS) {
		if (file_type == META_FILE) {
			memcpy(data_out, encrypted_fek, TEE_FS_KM_FEK_SIZE);
			data_out += TEE_FS_KM_FEK_SIZE;
		}

		memcpy(data_out, iv, TEE_FS_KM_IV_LEN);
		data_out += TEE_FS_KM_IV_LEN;
		memcpy(data_out, tag, TEE_FS_KM_MAX_TAG_LEN);

		*data_out_size = header_size + cipher_size;
	}

fail:
	return res;
}

TEE_Result tee_fs_decrypt_file(enum tee_fs_file_type file_type,
		const uint8_t *data_in, size_t data_in_size,
		uint8_t *plaintext, size_t *plaintext_size,
		uint8_t *encrypted_fek)
{
	TEE_Result res = TEE_SUCCESS;
	struct km_header km_hdr;
	size_t file_hdr_size = tee_fs_get_header_size(file_type);
	const uint8_t *cipher = data_in + file_hdr_size;
	int cipher_size = data_in_size - file_hdr_size;
	uint8_t fek[TEE_FS_KM_FEK_SIZE];

	if (file_type == META_FILE) {
		struct meta_header *hdr = (struct meta_header *)data_in;

		km_hdr.aad.encrypted_key = hdr->encrypted_key;
		km_hdr.aad.iv = hdr->common.iv;
		km_hdr.tag = hdr->common.tag;

		/* return encrypted FEK to tee_fs which is used for block
		 * encryption/decryption */
		memcpy(encrypted_fek, hdr->encrypted_key, TEE_FS_KM_FEK_SIZE);
	} else {
		struct block_header *hdr = (struct block_header *)data_in;

		km_hdr.aad.encrypted_key = encrypted_fek;
		km_hdr.aad.iv = hdr->common.iv;
		km_hdr.tag = hdr->common.tag;
	}

	memcpy(fek, km_hdr.aad.encrypted_key, TEE_FS_KM_FEK_SIZE);
	res = fek_crypt(TEE_MODE_DECRYPT, fek, TEE_FS_KM_FEK_SIZE);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to decrypt FEK, res=0x%x", res);
		return res;
	}

	return do_auth_enc(TEE_MODE_DECRYPT, &km_hdr, fek, TEE_FS_KM_FEK_SIZE,
			cipher, cipher_size, plaintext, plaintext_size);
}

static void u16_to_big_endian(uint16_t u16, uint8_t *bytes)
{
	*bytes = (uint8_t) (u16 >> 8);
	*(bytes + 1) = (uint8_t) u16;
}

/*
 * AES CTR mode encryption/decryption used for block encryption of RPMB FS
 * files.
 */
TEE_Result tee_fs_crypt_block(uint8_t *out, const uint8_t *in, size_t size,
			      uint16_t blk_idx, uint8_t *encrypted_fek,
			      uint8_t *nonce, TEE_OperationMode mode)
{
	TEE_Result res;
	uint8_t fek[TEE_FS_KM_FEK_SIZE];
	uint8_t iv[TEE_AES_BLOCK_SIZE];
	uint8_t *ctx;
	size_t ctx_size;

	DMSG("%scrypt block #%u", (mode == TEE_MODE_ENCRYPT) ? "En" : "De",
	     blk_idx);

	memcpy(fek, encrypted_fek, TEE_FS_KM_FEK_SIZE);
	res = fek_crypt(TEE_MODE_DECRYPT, fek, TEE_FS_KM_FEK_SIZE);
	if (res != TEE_SUCCESS)
		return res;

	res = crypto_ops.cipher.get_ctx_size(TEE_ALG_AES_CTR, &ctx_size);
	if (res != TEE_SUCCESS)
		return res;
	ctx = malloc(ctx_size);
	if (!ctx)
		return TEE_ERROR_OUT_OF_MEMORY;

	memcpy(iv, nonce, 14);
	u16_to_big_endian(blk_idx, iv + 14);

	res = crypto_ops.cipher.init(ctx, TEE_ALG_AES_CTR, mode, fek,
				     sizeof(fek), NULL, 0, iv,
				     TEE_AES_BLOCK_SIZE);
	if (res != TEE_SUCCESS)
		goto exit;
	res = crypto_ops.cipher.update(ctx, TEE_ALG_AES_CTR, mode, true,
				       in, size, out);
	crypto_ops.cipher.final(ctx, TEE_ALG_AES_CTR);


exit:
	free(ctx);
	return res;
}

service_init(tee_fs_init_key_manager);

