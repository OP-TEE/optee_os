// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) Foundries Ltd. 2020 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#include <crypto/crypto.h>
#include <kernel/panic.h>
#include <se050.h>
#include <string.h>

void crypto_aes_enc_block(const void *enc_key, size_t enc_keylen,
			  unsigned int rounds, const void *src, void *dst)
{
	sss_se05x_symmetric_t c = { 0 };
	sss_se05x_object_t key_obj = { 0 };
	sss_status_t st = 0;
	size_t dst_len = 16; /* as per mbedtls */
	uint32_t oid = 0;

	st = sss_se05x_key_object_init(&key_obj, se050_kstore);
	if (st != kStatus_SSS_Success)
		panic();

	st = se050_get_oid(kKeyObject_Mode_Transient, &oid);
	if (st != kStatus_SSS_Success)
		panic();

	/* AES */
	st = sss_se05x_key_object_allocate_handle(&key_obj, oid,
						  kSSS_KeyPart_Default,
						  kSSS_CipherType_AES, 0,
						  kKeyObject_Mode_Transient);
	if (st != kStatus_SSS_Success)
		panic();

	st = sss_se05x_key_store_set_key(se050_kstore, &key_obj,
					 enc_key, enc_keylen,
					 (enc_keylen * 8), NULL, 0);
	if (st != kStatus_SSS_Success)
		panic();

	/* AES-ECB encrypt */
	st = sss_se05x_symmetric_context_init(&c, se050_session, &key_obj,
					      kAlgorithm_SSS_AES_ECB,
					      kMode_SSS_Encrypt);
	if (st != kStatus_SSS_Success)
		panic();

	st = sss_se05x_cipher_one_go(&c, (uint8_t *)enc_key, enc_keylen,
				     (uint8_t *)src, (uint8_t *)dst, dst_len);
	if (st != kStatus_SSS_Success)
		panic();

	sss_se05x_key_store_erase_key(se050_kstore, &key_obj);
	sss_se05x_symmetric_context_free(&c);
}
