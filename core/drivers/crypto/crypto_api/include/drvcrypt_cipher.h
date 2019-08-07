/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2018-2020 NXP
 *
 * Cipher interface calling the crypto driver.
 */
#ifndef __DRVCRYPT_CIPHER_H__
#define __DRVCRYPT_CIPHER_H__

#include <crypto/crypto_impl.h>
#include <tee_api_types.h>

/*
 * Cipher operation context
 */
struct crypto_cipher {
	struct crypto_cipher_ctx cipher_ctx; /* Crypto cipher API context */
	void *ctx;                           /* Cipher context */
	struct drvcrypt_cipher *op;          /* Reference to the operation */
};

/*
 * Cipher algorithm initialization data
 */
struct drvcrypt_cipher_init {
	void *ctx;		  /* Software context */
	bool encrypt;		  /* Encrypt or decrypt direction */
	struct drvcrypt_buf key1; /* First key */
	struct drvcrypt_buf key2; /* Second key */
	struct drvcrypt_buf iv;	  /* Initial vector */
};

/*
 * Cipher algorithm update data
 */
struct drvcrypt_cipher_update {
	void *ctx;		 /* Software context */
	bool encrypt;		 /* Encrypt or decrypt direction */
	bool last;		 /* Last block to handle */
	struct drvcrypt_buf src; /* Buffer source (message or cipher) */
	struct drvcrypt_buf dst; /* Buffer dest (message or cipher) */
};

/*
 * Crypto library cipher driver operations
 */
struct drvcrypt_cipher {
	/* Allocate context */
	TEE_Result (*alloc_ctx)(void **ctx, uint32_t algo);
	/* Free context */
	void (*free_ctx)(void *ctx);
	/* Initialize the cipher operation */
	TEE_Result (*init)(struct drvcrypt_cipher_init *dinit);
	/* Update the cipher operation */
	TEE_Result (*update)(struct drvcrypt_cipher_update *dupdate);
	/* Finalize the cipher operation */
	void (*final)(void *ctx);
	/* Copy cipher context */
	void (*copy_state)(void *dst_ctx, void *src_ctx);
};

/*
 * Register a cipher processing driver in the crypto API
 *
 * @ops - Driver operations
 */
static inline TEE_Result drvcrypt_register_cipher(struct drvcrypt_cipher *ops)
{
	return drvcrypt_register(CRYPTO_CIPHER, (void *)ops);
}

#endif /* __DRVCRYPT_CIPHER_H__ */
