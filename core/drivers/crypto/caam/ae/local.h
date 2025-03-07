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
 * @type:		Algo type for operation
 * @size_block:		Computing block size
 * @size_ctx:		CAAM Context Register size
 * @ctx_offset:		CAAM Context Register offset
 * @def_key:		Define accepted key size
 * @initialize:		Initialize function
 * @final:		Final function
 */
struct cipheralg {
	uint32_t type;
	uint8_t size_block;
	uint8_t size_ctx;
	uint8_t ctx_offset;
	struct caamdefkey def_key;

	TEE_Result (*initialize)(struct drvcrypt_authenc_init *dinit);
	TEE_Result (*final)(struct drvcrypt_authenc_final *dfinal);
};

/*
 * CAAM Authenticated Encryption Context
 *
 * @descriptor:		Job descriptor
 * @tag_length:		Hash tag length
 * @aad_length:		Additional data length
 * @payload_length:	Data length
 * @encrypt:		Encrypt direction
 * @key:		Cipher key
 * @initial_ctx:	Initial CCM context
 * @ctx:		Saved context for multi-part update
 * @nonce:		Initial GCM Nonce value
 * @buf_add:		Additional Data buffer if needed
 * @blockbuf:		Temporary Block buffer
 * @do_block:		Block Encryption operation function
 * @alg:		Reference to the algo constants
 */
struct caam_ae_ctx {
	uint32_t *descriptor;

	size_t tag_length;
	size_t aad_length;
	size_t payload_length;

	bool encrypt;

	struct caambuf key;
	struct caambuf initial_ctx;
	struct caambuf ctx;
	struct caambuf nonce;

	struct caamblock buf_aad;
	struct caamblock blockbuf;

	bool (*do_block)(struct caam_ae_ctx *caam_ctx, bool encrypt,
			 struct caamdmaobj *src, struct caamdmaobj *dst,
			 bool final);

	const struct cipheralg *alg;
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

/*
 * Initialization of the AES CCM operation
 *
 * @dinit  Data initialization object
 */
TEE_Result caam_ae_initialize_ccm(struct drvcrypt_authenc_init *dinit);

/*
 * Finalize the AES CCM operation
 *
 * @dfinal  Last data object
 */
TEE_Result caam_ae_final_ccm(struct drvcrypt_authenc_final *dfinal);

#endif /* __LOCAL_H__ */
