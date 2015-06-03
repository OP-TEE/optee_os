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
#include <tee/tee_cryp_utl.h>
#include <tee/tee_cryp_provider.h>
#include <tee/tee_enc_fs_key_manager.h>
#include <compiler.h>
#include <trace.h>

#define CHIP_ID_LENGTH        32
#define ENC_FS_HMAC_ALG       TEE_ALG_HMAC_SHA256
#define ENC_FS_AUTH_ENC_ALG   TEE_ALG_AES_GCM
#define ENC_FS_ENC_FFK_ALG    TEE_ALG_AES_ECB_NOPAD
#define ENC_FS_SSK_SIZE       TEE_SHA256_HASH_SIZE
#define ENC_FS_FEK_SIZE       16  /* bytes */
#define ENC_FS_IV_LEN         12  /* bytes */
#define ENC_FS_MAX_TAG_LEN    16  /* bytes */

struct tee_enc_fs_ssk {
	int is_init;
	uint8_t key[ENC_FS_SSK_SIZE];
};

struct aad {
	uint8_t encrypted_key[ENC_FS_FEK_SIZE];
	uint8_t iv[ENC_FS_IV_LEN];
};

struct enc_fs_file_header {
	struct aad aad;
	uint8_t tag[ENC_FS_MAX_TAG_LEN];
};

static struct tee_enc_fs_ssk enc_fs_ssk = { 0, { 0 } };
static uint8_t string_for_ssk_gen[] = "ONLY_FOR_ENC_FS_SSK";


static TEE_Result fek_crypt(TEE_OperationMode mode,
			uint8_t *key, int size)
{
	TEE_Result res;
	uint8_t *ctx = NULL;
	size_t ctx_size;
	uint8_t dst_key[ENC_FS_FEK_SIZE];

	if (!key)
		return TEE_ERROR_BAD_PARAMETERS;

	if (size != ENC_FS_FEK_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	if (enc_fs_ssk.is_init == 0)
		return TEE_ERROR_GENERIC;

	res = crypto_ops.cipher.get_ctx_size(ENC_FS_ENC_FFK_ALG, &ctx_size);
	if (res != TEE_SUCCESS)
		return res;

	ctx = malloc(ctx_size);
	if (!ctx)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = crypto_ops.cipher.init(ctx, ENC_FS_ENC_FFK_ALG,
			mode, enc_fs_ssk.key, ENC_FS_SSK_SIZE,
			NULL, 0, NULL, 0);
	if (res != TEE_SUCCESS)
		goto exit;

	res = crypto_ops.cipher.update(ctx, ENC_FS_ENC_FFK_ALG,
			mode, true, key, size, dst_key);
	if (res != TEE_SUCCESS)
		goto exit;

	crypto_ops.cipher.final(ctx, ENC_FS_ENC_FFK_ALG);

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

	res = crypto_ops.mac.get_ctx_size(ENC_FS_HMAC_ALG, &hash_ctx_size);
	if (res != TEE_SUCCESS)
		return res;

	ctx = malloc(hash_ctx_size);
	if (!ctx)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = crypto_ops.mac.init(ctx, ENC_FS_HMAC_ALG, huk, huk_size);
	if (res != TEE_SUCCESS)
		goto exit;

	res = crypto_ops.mac.update(ctx, ENC_FS_HMAC_ALG,
			message, message_size);
	if (res != TEE_SUCCESS)
		goto exit;

	res = crypto_ops.hash.final(ctx, ENC_FS_HMAC_ALG, ssk, ssk_size);
	if (res != TEE_SUCCESS)
		goto exit;

	res = TEE_SUCCESS;

exit:
	free(ctx);
	return res;
}

static TEE_Result enc_fs_init_key_manager(void)
{
	int res = TEE_SUCCESS;

	if (enc_fs_ssk.is_init == 0) {
		struct tee_hw_unique_key huk;
		uint8_t chip_id[CHIP_ID_LENGTH];
		uint8_t *message;

		/* Secure Storage Key Generation:
		 *
		 *     SSK = HMAC(HUK, message)
		 *     message := concatenate(chip_id, static string)
		 * */

		message = malloc(sizeof(chip_id) + sizeof(string_for_ssk_gen));
		if (!message) {
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto exit;
		}

		tee_otp_get_hw_unique_key(&huk);
		tee_otp_get_die_id(chip_id, sizeof(chip_id));

		memcpy(message, chip_id, sizeof(chip_id));
		memcpy(message + sizeof(chip_id), string_for_ssk_gen,
				sizeof(string_for_ssk_gen));

		res = generate_ssk(enc_fs_ssk.key, sizeof(enc_fs_ssk.key),
				huk.data, sizeof(huk.data),
				message, sizeof(message));

		free(message);

		if (res == TEE_SUCCESS)
			enc_fs_ssk.is_init = 1;
	}

exit:
	return res;
}

static TEE_Result do_auth_enc(TEE_OperationMode mode,
		struct enc_fs_file_header *hdr,
		uint8_t *fek, int fek_len,
		uint8_t *data_in, size_t in_size,
		uint8_t *data_out, size_t *out_size)
{
	TEE_Result res = TEE_SUCCESS;
	uint8_t *ctx = NULL;
	size_t ctx_size;
	size_t tag_len = ENC_FS_MAX_TAG_LEN;

	if ((mode != TEE_MODE_ENCRYPT) && (mode != TEE_MODE_DECRYPT))
		return TEE_ERROR_BAD_PARAMETERS;

	res = crypto_ops.authenc.get_ctx_size(ENC_FS_AUTH_ENC_ALG, &ctx_size);
	if (res != TEE_SUCCESS)
		return res;

	ctx = malloc(ctx_size);
	if (!ctx)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = crypto_ops.authenc.init(ctx, ENC_FS_AUTH_ENC_ALG,
			mode, fek, fek_len, hdr->aad.iv,
			ENC_FS_IV_LEN, ENC_FS_MAX_TAG_LEN,
			sizeof(struct aad), in_size);
	if (res != TEE_SUCCESS)
		goto exit;

	res = crypto_ops.authenc.update_aad(ctx, ENC_FS_AUTH_ENC_ALG,
			mode, (uint8_t *)&hdr->aad,
			sizeof(struct aad));
	if (res != TEE_SUCCESS)
		goto exit;

	if (mode == TEE_MODE_ENCRYPT) {
		res = crypto_ops.authenc.enc_final(ctx, ENC_FS_AUTH_ENC_ALG,
				data_in, in_size, data_out, out_size,
				hdr->tag, &tag_len);
	} else {
		res = crypto_ops.authenc.dec_final(ctx, ENC_FS_AUTH_ENC_ALG,
				data_in, in_size, data_out, out_size,
				hdr->tag, tag_len);
	}

	if (res != TEE_SUCCESS)
		goto exit;

	crypto_ops.authenc.final(ctx, ENC_FS_AUTH_ENC_ALG);

exit:
	free(ctx);
	return res;
}

static TEE_Result do_file_encryption(struct enc_fs_file_header *hdr,
			uint8_t *fek, int fek_len,
			uint8_t *plaintext, size_t plaintext_size,
			uint8_t *data_out, size_t *out_size)
{
	TEE_Result res = TEE_SUCCESS;
	size_t header_size = tee_enc_fs_get_file_header_size();
	uint8_t *ciphertext = NULL;
	size_t ciphertext_size;

	if (*out_size != (header_size + plaintext_size))
		return TEE_ERROR_SHORT_BUFFER;

	ciphertext = data_out + header_size;
	ciphertext_size = plaintext_size;

	res = do_auth_enc(TEE_MODE_ENCRYPT, hdr, fek, fek_len,
			plaintext, plaintext_size,
			ciphertext, &ciphertext_size);

	if (res == TEE_SUCCESS) {
		memcpy(data_out, hdr, header_size);
		*out_size = header_size + ciphertext_size;
	}

	return res;
}

static TEE_Result do_file_decryption(struct enc_fs_file_header *hdr,
			uint8_t *fek, int fek_len,
			uint8_t *ciphertext, size_t ciphertext_size,
			uint8_t *plaintext, size_t *plaintext_size)
{
	if (ciphertext_size != *plaintext_size)
		return TEE_ERROR_SHORT_BUFFER;

	return do_auth_enc(TEE_MODE_DECRYPT, hdr, fek, fek_len,
			ciphertext, ciphertext_size, plaintext, plaintext_size);
}

size_t tee_enc_fs_get_file_header_size(void)
{
	return sizeof(struct enc_fs_file_header);
}

TEE_Result tee_enc_fs_file_encryption(uint8_t *plaintext, size_t plaintext_size,
			uint8_t *data_out, size_t *out_size)
{
	TEE_Result res = TEE_SUCCESS;
	struct enc_fs_file_header file_header;
	uint8_t fek[ENC_FS_FEK_SIZE];

	res = generate_fek(fek, ENC_FS_FEK_SIZE);
	if (res != TEE_SUCCESS)
		return res;

	res = generate_iv(file_header.aad.iv, ENC_FS_IV_LEN);
	if (res != TEE_SUCCESS)
		return res;

	memcpy(file_header.aad.encrypted_key, fek, ENC_FS_FEK_SIZE);
	res = fek_crypt(TEE_MODE_ENCRYPT,
			file_header.aad.encrypted_key, ENC_FS_FEK_SIZE);
	if (res != TEE_SUCCESS)
		return res;

	res = do_file_encryption(&file_header, fek, ENC_FS_FEK_SIZE,
			plaintext, plaintext_size, data_out, out_size);

	return res;
}

TEE_Result tee_enc_fs_file_decryption(uint8_t *data_in, size_t in_size,
			uint8_t *plaintext, size_t *plaintext_size)
{
	TEE_Result res = TEE_SUCCESS;
	struct enc_fs_file_header *hdr = (struct enc_fs_file_header *)data_in;
	uint8_t *ciphertext = data_in + sizeof(struct enc_fs_file_header);
	int ciphertext_size = in_size - sizeof(struct enc_fs_file_header);
	uint8_t fek[ENC_FS_FEK_SIZE];

	memcpy(fek, hdr->aad.encrypted_key, ENC_FS_FEK_SIZE);
	res = fek_crypt(TEE_MODE_DECRYPT, fek, ENC_FS_FEK_SIZE);
	if (res != TEE_SUCCESS)
		return res;

	res = do_file_decryption(hdr, fek, ENC_FS_FEK_SIZE,
			ciphertext, ciphertext_size, plaintext, plaintext_size);

	return res;
}

service_init(enc_fs_init_key_manager);

