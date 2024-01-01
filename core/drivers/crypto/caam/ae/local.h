/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2024 NXP
 */
#ifndef __LOCAL_H__
#define __LOCAL_H__

#include <caam_utils_dmaobj.h>
#include <drvcrypt.h>
#include <drvcrypt_authenc.h>

/* Maximum AAD size */
#define AAD_LENGTH_OVERFLOW 0xFF00

/*
 * Cipher Algorithm definition
 */
struct cipheralg {
	uint32_t type; /* Algo type for operation */
	uint8_t size_block; /* Computing block size */
	uint8_t size_ctx; /* CAAM Context Register size */
	uint8_t ctx_offset; /* CAAM Context Register offset */
	struct caamdefkey def_key; /* Define accepted key size */

	TEE_Result (*initialize)(struct drvcrypt_authenc_init *dinit);
	TEE_Result (*final)(struct drvcrypt_authenc_final *dfinal);
};

struct caam_ae_ctx {
	uint32_t *descriptor;       /* Job descriptor */

	size_t tag_length;          /* Hash tag length */
	size_t aad_length;          /* Additional data length */
	size_t payload_length;      /* Data length */

	bool encrypt;               /* Encrypt direction */

	struct caambuf key;         /* Cipher key */
	struct caambuf initial_ctx; /* Initial CCM context */
	struct caambuf ctx;         /* Saved context for multi-part update */
	struct caambuf nonce;       /* Initial GCM Nonce value */

	struct caamblock buf_aad;   /* Additional Data buffer if needed */
	struct caamblock blockbuf;  /* Temporary Block buffer */

	bool (*do_block)(struct caam_ae_ctx *caam_ctx, bool encrypt,
			 struct caamdmaobj *src, struct caamdmaobj *dst,
			 bool final);

	const struct cipheralg *alg; /* Reference to the algo constants */
};

/*
 * Update of the Authenticated Encryption Operation.
 *
 * @ctx      AE Cipher context
 * @src      Source data to encrypt/decrypt
 * @dst      [out] Destination data encrypted/decrypted
 * @last     Last update flag
 */
TEE_Result caam_ae_do_update(struct caam_ae_ctx *ctx, struct drvcrypt_buf *src,
			     struct drvcrypt_buf *dst, bool last);

/*
 * Initialization of the AES GCM operation
 *
 * @dinit  Data initialization object
 */
TEE_Result caam_ae_initialize_gcm(struct drvcrypt_authenc_init *dinit);

/*
 * Finalize the AES GCM operation
 *
 * @dfinal  Last data object
 */
TEE_Result caam_ae_final_gcm(struct drvcrypt_authenc_final *dfinal);

#endif /* __LOCAL_H__ */
