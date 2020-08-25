// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) Foundries Ltd. 2020 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#include <crypto/crypto.h>
#include "fsl_sss_user_apis.h"

#define MAC_BLOCK_SIZE 16

/* readability */
#define USR_FUNC(_x) sss_user_impl_ ##_x

/*
 * Session
 */
sss_status_t USR_FUNC(session_open)(sss_user_impl_session_t *s,
				    sss_type_t subsystem,
				    uint32_t application_id __unused,
				    sss_connection_type_t type,
				    void *data __unused)
{
	if (!s || type != kSSS_ConnectionType_Plain)
		return kStatus_SSS_Fail;

	memset(s, 0, sizeof(*s));
	s->subsystem = subsystem;

	return kStatus_SSS_Success;
}

void USR_FUNC(session_close)(sss_user_impl_session_t *session)
{
	if (session)
		memset(session, 0, sizeof(*session));
}

/*
 * Key object
 */
sss_status_t USR_FUNC(key_object_init)(sss_user_impl_object_t *key,
				       sss_user_impl_key_store_t *store)
{
	if (!key || !store)
		return kStatus_SSS_Fail;

	memset(key, 0, sizeof(*key));
	key->keyStore = store;

	return kStatus_SSS_Success;
}

void USR_FUNC(key_object_free)(sss_user_impl_object_t *p)
{
}

sss_status_t USR_FUNC(key_object_allocate_handle)(sss_user_impl_object_t *key,
						  uint32_t key_id,
						  sss_key_part_t key_part,
						  sss_cipher_type_t type,
						  size_t len,
						  uint32_t options)
{
	return kStatus_SSS_Success;
}

/*
 * Key Store
 */
sss_status_t USR_FUNC(key_store_context_init)(sss_user_impl_key_store_t *store,
					      sss_user_impl_session_t *s)
{
	if (!s || !store)
		return kStatus_SSS_Fail;

	memset(store, 0, sizeof(*store));
	store->session = s;

	return kStatus_SSS_Success;
}

void USR_FUNC(key_store_context_free)(sss_user_impl_key_store_t *store)
{
	if (store)
		memset(store, 0, sizeof(*store));
}

sss_status_t USR_FUNC(key_store_allocate)(sss_user_impl_key_store_t *store,
					  uint32_t id __unused)
{
	if (!store || !store->session)
		return kStatus_SSS_Fail;

	return  kStatus_SSS_Success;
}

sss_status_t USR_FUNC(key_store_set_key)(sss_user_impl_key_store_t *store,
					 sss_user_impl_object_t *key,
					 const uint8_t *data,
					 size_t data_len,
					 size_t key_len __unused,
					 void *options __unused,
					 size_t options_len __unused)
{
	if (!data || !key)
		return kStatus_SSS_Fail;

	memcpy(key->key, data, data_len);

	return kStatus_SSS_Success;
}

sss_status_t USR_FUNC(key_store_get_key)(sss_user_impl_key_store_t *store,
					 sss_user_impl_object_t *key,
					 uint8_t *data, size_t *data_len,
					 size_t *key_len)
{
	return kStatus_SSS_Success;
}

sss_status_t USR_FUNC(key_store_generate_key)(sss_user_impl_key_store_t *s,
					      sss_user_impl_object_t *k,
					      size_t len, void *options)
{
	return kStatus_SSS_Fail;
}

/*
 * Mac
 */
sss_status_t USR_FUNC(mac_init)(sss_user_impl_mac_t *ctx)
{
	if (!ctx)
		return kStatus_SSS_Fail;

	return kStatus_SSS_Success;
}

sss_status_t USR_FUNC(mac_context_init)(sss_user_impl_mac_t *ctx,
					sss_user_impl_session_t *session,
					sss_user_impl_object_t *key,
					sss_algorithm_t algorithm,
					sss_mode_t mode)
{
	if (!ctx || !key)
		return kStatus_SSS_Fail;

	ctx->keyObject = key;

	if (algorithm != kAlgorithm_SSS_CMAC_AES)
		return kStatus_SSS_Fail;

	if (crypto_mac_alloc_ctx(&ctx->mac, TEE_ALG_AES_CMAC))
		return kStatus_SSS_Fail;

	if (crypto_mac_init(ctx->mac, key->key, sizeof(key->key)))
		return kStatus_SSS_Fail;

	return kStatus_SSS_Success;
}

void USR_FUNC(mac_context_free)(sss_user_impl_mac_t *ctx)
{
	crypto_mac_free_ctx(ctx->mac);
}

sss_status_t USR_FUNC(mac_update)(sss_user_impl_mac_t *ctx,
				  const uint8_t *msg, size_t msg_len)
{
	if (crypto_mac_update(ctx->mac, msg, msg_len))
		return kStatus_SSS_Fail;

	return kStatus_SSS_Success;
}

sss_status_t USR_FUNC(mac_finish)(sss_user_impl_mac_t *ctx,
				  uint8_t *mac, size_t *len)
{
	if (crypto_mac_final(ctx->mac, mac, len))
		return kStatus_SSS_Fail;

	return kStatus_SSS_Success;
}

sss_status_t USR_FUNC(mac_one_go)(sss_user_impl_mac_t *ctx,
				  const uint8_t *msg, size_t msg_len,
				  uint8_t *mac, size_t *mac_len)
{
	if (crypto_mac_update(ctx->mac, msg, msg_len))
		return kStatus_SSS_Fail;

	if (crypto_mac_final(ctx->mac, mac, *mac_len))
		return kStatus_SSS_Fail;

	return kStatus_SSS_Success;
}

/*
 * Symmetric
 */
sss_status_t USR_FUNC(symmetric_context_init)(sss_user_impl_symmetric_t *c,
					      sss_user_impl_session_t *s,
					      sss_user_impl_object_t *key,
					      sss_algorithm_t algorithm,
					      sss_mode_t mode)
{
	if (!c || !s || !key)
		return kStatus_SSS_Fail;

	if (algorithm != kAlgorithm_SSS_AES_CBC)
		return kStatus_SSS_Fail;

	c->keyObject = key;
	c->mode = mode;

	if (crypto_cipher_alloc_ctx(&c->cipher, TEE_ALG_AES_CBC_NOPAD))
		return kStatus_SSS_Fail;

	return kStatus_SSS_Success;
}

sss_status_t USR_FUNC(cipher_one_go)(sss_user_impl_symmetric_t *ctx,
				     uint8_t *iv, size_t iv_len,
				     const uint8_t *src, uint8_t *dst,
				     size_t len)
{
	TEE_OperationMode mode = TEE_MODE_DECRYPT;

	if (ctx->mode == kMode_SSS_Encrypt)
		mode = TEE_MODE_ENCRYPT;

	if (crypto_cipher_init(ctx->cipher, mode,
			       ctx->keyObject->key,
			       sizeof(ctx->keyObject->key),
			       NULL, 0,
			       iv, iv_len))
		return kStatus_SSS_Fail;

	if (crypto_cipher_update(ctx->cipher, 0, true, src, len, dst))
		return kStatus_SSS_Fail;

	crypto_cipher_final(ctx->cipher);

	return kStatus_SSS_Success;
}

void USR_FUNC(symmetric_context_free)(sss_user_impl_symmetric_t *ctx)
{
	if (!ctx->cipher)
		return;

	crypto_cipher_free_ctx(ctx->cipher);
}

/*
 * Derive key
 */
sss_status_t USR_FUNC(derive_key_context_init)(sss_user_impl_derive_key_t *dk,
					       sss_user_impl_session_t *s,
					       sss_user_impl_object_t *k,
					       sss_algorithm_t algorithm,
					       sss_mode_t mode)
{
	return kStatus_SSS_Fail;
}

sss_status_t USR_FUNC(derive_key_go)(sss_user_impl_derive_key_t *ctx,
				     const uint8_t *salt, size_t salt_len,
				     const uint8_t *info, size_t info_len,
				     sss_user_impl_object_t *p, uint16_t d,
				     uint8_t *h, size_t *h_len)
{
	return kStatus_SSS_Fail;
}

sss_status_t USR_FUNC(derive_key_dh)(sss_user_impl_derive_key_t *ctx,
				     sss_user_impl_object_t *p,
				     sss_user_impl_object_t *q)
{
	return kStatus_SSS_Fail;
}

void USR_FUNC(derive_key_context_free)(sss_user_impl_derive_key_t *ctx)
{
}

/*
 * Asymmetric
 */
sss_status_t USR_FUNC(asymmetric_context_init)(sss_user_impl_asymmetric_t *c,
					       sss_user_impl_session_t *s,
					       sss_user_impl_object_t *k,
					       sss_algorithm_t algorithm,
					       sss_mode_t mode)
{
	return kStatus_SSS_Fail;
}

void USR_FUNC(asymmetric_context_free)(sss_user_impl_asymmetric_t *ctx)
{
}

sss_status_t USR_FUNC(asymmetric_sign_digest)(sss_user_impl_asymmetric_t *c,
					      uint8_t *dgst, size_t dgst_len,
					      uint8_t *sig, size_t *sig_len)
{
	return kStatus_SSS_Fail;
}

/*
 * Digest
 */
sss_status_t USR_FUNC(digest_context_init)(sss_user_impl_digest_t *ctx,
					   sss_user_impl_session_t *session,
					   sss_algorithm_t algorithm,
					   sss_mode_t mode)
{
	return kStatus_SSS_Fail;
}

sss_status_t USR_FUNC(digest_one_go)(sss_user_impl_digest_t *ctx,
				     const uint8_t *m, size_t m_len,
				     uint8_t *d, size_t *d_len)
{
	return kStatus_SSS_Fail;
}

void USR_FUNC(digest_context_free)(sss_user_impl_digest_t *ctx)
{
}

/*
 * RNG
 */
sss_status_t USR_FUNC(rng_context_free)(sss_user_impl_rng_context_t *ctx)
{
	return kStatus_SSS_Success;
}

sss_status_t USR_FUNC(rng_context_init)(sss_user_impl_rng_context_t *ctx,
					sss_user_impl_session_t *session)
{
	srand(time(NULL));

	return kStatus_SSS_Success;
}

sss_status_t USR_FUNC(rng_get_random)(sss_user_impl_rng_context_t *ctx,
				      uint8_t *data, size_t len)
{
	size_t i = 0;

	if (!ctx)
		return kStatus_SSS_Fail;

	for (i = 0; i < len; i++)
		data[i] = (uint8_t)rand();

	return kStatus_SSS_Success;
}
