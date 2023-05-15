/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2021, STMicroelectronics - All Rights Reserved
 *
 * Authenticated Encryption interface calling the crypto driver
 */
#ifndef __DRVCRYPT_AUTHENC_H__
#define __DRVCRYPT_AUTHENC_H__

#include <crypto/crypto_impl.h>
#include <tee_api_types.h>

/*
 * Authenticated Encryption operation context
 */
struct crypto_authenc {
	struct crypto_authenc_ctx authenc_ctx;	/* Crypto authenc API context */
	void *ctx;				/* Authenc context */
	struct drvcrypt_authenc *op;		/* Reference to the operation */
};

/*
 * Authenticated Encryption algorithm initialization data
 */
struct drvcrypt_authenc_init {
	void *ctx;		     /* Software context */
	bool encrypt;		     /* Encrypt or decrypt direction */
	struct drvcrypt_buf key;     /* First key */
	struct drvcrypt_buf nonce;   /* Nonce */
	size_t tag_len;		     /* Tag length  */
	size_t aad_len;		     /* Additional Authenticated Data length */
	size_t payload_len;	     /* Payload length */
};

/*
 * Authenticated Encryption algorithm update_aad data
 */
struct drvcrypt_authenc_update_aad {
	void *ctx;		 /* Software context */
	bool encrypt;		 /* Encrypt or decrypt direction */
	struct drvcrypt_buf aad; /* Additional Authenticated Data buffer */
};

/*
 * Authenticated Encryption algorithm update_aad data
 */
struct drvcrypt_authenc_update_payload {
	void *ctx;		 /* Software context */
	bool encrypt;		 /* Encrypt or decrypt direction */
	struct drvcrypt_buf src; /* Buffer source (message or cipher) */
	struct drvcrypt_buf dst; /* Buffer destination (cipher or message) */
};

/*
 * Authenticated Encryption algorithm final data
 */
struct drvcrypt_authenc_final {
	void *ctx;		 /* Software context */
	bool encrypt;		 /* Encrypt or decrypt direction */
	struct drvcrypt_buf src; /* Buffer source (message or cipher) */
	struct drvcrypt_buf dst; /* Buffer destination (cipher or message) */
	struct drvcrypt_buf tag; /* Tag buffer */
};

/*
 * Crypto library authenc driver operations
 */
struct drvcrypt_authenc {
	/* Allocate context */
	TEE_Result (*alloc_ctx)(void **ctx, uint32_t algo);
	/* Free context */
	void (*free_ctx)(void *ctx);
	/* Initialize the authenc operation */
	TEE_Result (*init)(struct drvcrypt_authenc_init *dinit);
	/* Update the authenc operation with associated data */
	TEE_Result (*update_aad)(struct drvcrypt_authenc_update_aad *dupdate);
	/* Update the authenc operation with payload data */
	TEE_Result (*update_payload)(struct drvcrypt_authenc_update_payload *d);
	/* Update (or not) with payload data and get tag for encrypt op. */
	TEE_Result (*enc_final)(struct drvcrypt_authenc_final *dfinal);
	/* Update (or not) with payload data and verify tag for decrypt op. */
	TEE_Result (*dec_final)(struct drvcrypt_authenc_final *dfinal);
	/* Finalize the authenc operation */
	void (*final)(void *ctx);
	/* Copy authenc context */
	void (*copy_state)(void *dst_ctx, void *src_ctx);
};

/*
 * Register an authenc processing driver in the crypto API
 *
 * @ops - Driver operations
 */
static inline TEE_Result drvcrypt_register_authenc(struct drvcrypt_authenc *ops)
{
	return drvcrypt_register(CRYPTO_AUTHENC, (void *)ops);
}

#endif /* __DRVCRYPT_AUTHENC_H__ */
