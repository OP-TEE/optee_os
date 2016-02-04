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

struct auth_enc_info {
	uint8_t *key;
	size_t key_len;
	uint8_t *iv;
	size_t iv_len;
	uint8_t *tag;
	size_t tag_len;
	uint8_t *aad;
	size_t aad_len;
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

static TEE_Result generate_random_number(uint8_t *buf, uint8_t len)
{
	return crypto_ops.prng.read(buf, len);
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

static TEE_Result init_key_manager(void)
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
		struct auth_enc_info *info,
		const uint8_t *in, uint32_t in_size,
		uint8_t *out, size_t *out_size)
{
	TEE_Result res = TEE_SUCCESS;
	uint8_t *ctx = NULL;
	size_t ctx_size;

	if ((mode != TEE_MODE_ENCRYPT) && (mode != TEE_MODE_DECRYPT))
		return TEE_ERROR_BAD_PARAMETERS;

	if (*out_size < in_size) {
		EMSG("output buffer(%zu) < input buffer(%u)",
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
			mode, info->key, info->key_len,
			info->iv, info->iv_len,
			info->tag_len, info->aad_len,
			in_size);
	if (res != TEE_SUCCESS)
		goto exit;

	res = crypto_ops.authenc.update_aad(ctx, TEE_FS_KM_AUTH_ENC_ALG,
			mode, info->aad, info->aad_len);
	if (res != TEE_SUCCESS)
		goto exit;

	if (mode == TEE_MODE_ENCRYPT) {
		res = crypto_ops.authenc.enc_final(ctx, TEE_FS_KM_AUTH_ENC_ALG,
				in, in_size,
				out, out_size,
				info->tag, &info->tag_len);
	} else {
		res = crypto_ops.authenc.dec_final(ctx, TEE_FS_KM_AUTH_ENC_ALG,
				in, in_size, out, out_size,
				info->tag, info->tag_len);
	}

	if (res != TEE_SUCCESS)
		goto exit;

	crypto_ops.authenc.final(ctx, TEE_FS_KM_AUTH_ENC_ALG);

exit:
	free(ctx);
	return res;
}

static uint32_t get_cipher_header_size(enum tee_file_data_type data_type)
{
	uint32_t size = 0;

	switch (data_type) {
	case FILE_HEADER:
		size = sizeof(struct fh_cipher_header);
		break;
	case DATA_BLOCK:
		size = sizeof(struct block_cipher_header);
		break;
	default:
		EMSG("Unknown data type, type=%d", data_type);
		TEE_ASSERT(0);
	}

	return size;
}

static TEE_Result generate_fek(uint8_t *buf, int buf_size)
{
	TEE_Result res;

	if (buf_size != TEE_FS_KM_FEK_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	res = generate_random_number(buf, TEE_FS_KM_FEK_SIZE);
	if (res != TEE_SUCCESS)
		return res;

	return fek_crypt(TEE_MODE_ENCRYPT, buf,
			TEE_FS_KM_FEK_SIZE);
}

static TEE_Result get_encrypted_fek(const uint8_t *in, uint32_t in_size,
		uint8_t *out, uint32_t *out_size)
{
	TEE_Result tee_res = TEE_SUCCESS;
	struct fh_cipher_header *hdr = (struct fh_cipher_header *)in;
	uint32_t cipher_header_size = get_cipher_header_size(FILE_HEADER);

	if (in_size < cipher_header_size) {
		tee_res = TEE_ERROR_SHORT_BUFFER;
		goto exit;
	}

	if (*out_size < TEE_FS_KM_FEK_SIZE) {
		tee_res = TEE_FS_KM_FEK_SIZE;
		goto exit;
	}

	memcpy(out, hdr->encrypted_fek, TEE_FS_KM_FEK_SIZE);
	*out_size = TEE_FS_KM_FEK_SIZE;

exit:
	return tee_res;
}

static inline void prepare_cipher_header(enum tee_file_data_type data_type,
		struct auth_enc_info *auth_enc_info,
		const uint8_t *encrypted_fek, uint32_t encrypted_fek_len,
		uint8_t *in)
{
	if (data_type == FILE_HEADER) {
		struct fh_cipher_header *hdr =
				(struct fh_cipher_header *)in;

		memcpy(hdr->encrypted_fek, encrypted_fek, encrypted_fek_len);
		memcpy(hdr->iv, auth_enc_info->iv, auth_enc_info->iv_len);
		memcpy(hdr->tag, auth_enc_info->tag, auth_enc_info->tag_len);
	} else if (data_type == DATA_BLOCK) {
		struct block_cipher_header *hdr =
				(struct block_cipher_header *)in;

		memcpy(hdr->iv, auth_enc_info->iv, auth_enc_info->iv_len);
		memcpy(hdr->tag, auth_enc_info->tag, auth_enc_info->tag_len);
	} else {
		EMSG("Unknown data type, type=%d", data_type);
		TEE_ASSERT(0);
	}
}

static TEE_Result do_encryption(enum tee_file_data_type data_type,
		const uint8_t *encrypted_fek,
		uint8_t *aad, uint32_t aad_len,
		uint8_t *in, uint32_t in_size,
		uint8_t *out, size_t *out_size)
{
	TEE_Result res = TEE_SUCCESS;
	struct auth_enc_info auth_enc_info;
	uint8_t iv[TEE_FS_KM_IV_LEN];
	uint8_t tag[TEE_FS_KM_MAX_TAG_LEN];
	uint8_t fek[TEE_FS_KM_FEK_SIZE];
	uint8_t *cipher_header = out;
	uint32_t cipher_header_size = get_cipher_header_size(data_type);
	uint8_t *cipher_text = out + cipher_header_size;
	size_t cipher_text_size = in_size;

	/*
	 * In buffer  := |Meta data or Block TEE data|
	 * Out buffer := |<Cipher Header>|<Cipher Text>|
	 *
	 * FEK = AES_DECRYPT(SSK, Encrypted_FEK)
	 * cipher text = AES_GCM_ENCRYPT(FEK, IV, AAD, In buffer)
	 */
	if (*out_size != (cipher_header_size + in_size))
		return TEE_ERROR_SHORT_BUFFER;

	res = generate_random_number(iv, TEE_FS_KM_IV_LEN);
	if (res != TEE_SUCCESS)
		goto fail;

	memcpy(fek, encrypted_fek, TEE_FS_KM_FEK_SIZE);
	res = fek_crypt(TEE_MODE_DECRYPT, fek, TEE_FS_KM_FEK_SIZE);
	if (res != TEE_SUCCESS)
		goto fail;

	auth_enc_info.key = fek;
	auth_enc_info.key_len = sizeof(fek);
	auth_enc_info.iv = iv;
	auth_enc_info.iv_len = sizeof(iv);
	auth_enc_info.tag = tag;
	auth_enc_info.tag_len = sizeof(tag);
	auth_enc_info.aad = aad;
	auth_enc_info.aad_len = aad_len;

	res = do_auth_enc(TEE_MODE_ENCRYPT,
			&auth_enc_info,
			in, in_size,
			cipher_text, &cipher_text_size);

	if (res == TEE_SUCCESS) {
		prepare_cipher_header(data_type, &auth_enc_info,
				encrypted_fek, TEE_FS_KM_FEK_SIZE,
				cipher_header);

		*out_size = cipher_header_size + cipher_text_size;
	}

fail:
	return res;
}

static TEE_Result do_decryption(enum tee_file_data_type data_type,
		uint8_t *encrypted_fek,
		uint8_t *aad, uint32_t aad_len,
		uint8_t *in, uint32_t in_size,
		uint8_t *out, size_t *out_size)
{
	TEE_Result res = TEE_SUCCESS;
	struct auth_enc_info auth_enc_info;
	uint8_t *cipher_header = in;
	uint32_t cipher_header_size = get_cipher_header_size(data_type);
	uint8_t *cipher_text = in + cipher_header_size;
	uint32_t cipher_text_size = in_size - cipher_header_size;
	uint8_t fek[TEE_FS_KM_FEK_SIZE];

	/*
	 * In buffer  := |<Cipher Header>|<Cipher Text>|
	 * Out buffer := |Meta data or Block TEE data|
	 *
	 * FEK = AES_DECRYPT(SSK, Encrypted_FEK)
	 * Out buffer = AES_GCM_DECRYPT(FEK, IV, AAD, <Cipher Text>)
	 */

	if (data_type == FILE_HEADER) {
		struct fh_cipher_header *hdr =
				(struct fh_cipher_header *)cipher_header;

		auth_enc_info.iv = hdr->iv;
		auth_enc_info.iv_len = sizeof(hdr->iv);
		auth_enc_info.tag = hdr->tag;
		auth_enc_info.tag_len = sizeof(hdr->tag);

		memcpy(fek, hdr->encrypted_fek, TEE_FS_KM_FEK_SIZE);

	} else {
		struct block_cipher_header *hdr =
				(struct block_cipher_header *)cipher_header;

		auth_enc_info.iv = hdr->iv;
		auth_enc_info.iv_len = sizeof(hdr->iv);
		auth_enc_info.tag = hdr->tag;
		auth_enc_info.tag_len = sizeof(hdr->tag);

		memcpy(fek, encrypted_fek, TEE_FS_KM_FEK_SIZE);
	}

	res = fek_crypt(TEE_MODE_DECRYPT, fek, TEE_FS_KM_FEK_SIZE);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to decrypt FEK, res=0x%x", res);
		return res;
	}

	auth_enc_info.key = fek;
	auth_enc_info.key_len = sizeof(fek);
	auth_enc_info.aad = aad;
	auth_enc_info.aad_len = aad_len;

	return do_auth_enc(TEE_MODE_DECRYPT,
			&auth_enc_info,
			cipher_text, cipher_text_size,
			out, out_size);
}

struct tee_fs_key_manager_operations key_manager_ops = {
	.get_cipher_header_size = get_cipher_header_size,
	.generate_fek = generate_fek,
	.get_encrypted_fek = get_encrypted_fek,
	.do_encryption = do_encryption,
	.do_decryption = do_decryption
};

service_init(init_key_manager);

