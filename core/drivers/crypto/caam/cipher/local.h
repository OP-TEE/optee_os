/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2018-2019 NXP
 *
 * CAAM Cipher Local header.
 */
#ifndef __LOCAL_H__
#define __LOCAL_H__

#include <drvcrypt.h>
#include <drvcrypt_cipher.h>

/*
 * Definition of flags tagging which key(s) is required
 */
#define NEED_KEY1  BIT(0)
#define NEED_KEY2  BIT(1)
#define NEED_IV    BIT(2)
#define NEED_TWEAK BIT(3)

/*
 * Cipher Algorithm definition
 */
struct cipheralg {
	uint32_t type;             /* Algo type for operation */
	uint8_t size_block;        /* Computing block size */
	uint8_t size_ctx;          /* CAAM Context Register size */
	uint8_t ctx_offset;        /* CAAM Context Register offset */
	uint8_t require_key;       /* Tag defining key(s) required */
	struct caamdefkey def_key; /* Key size accepted */

	TEE_Result (*update)(struct drvcrypt_cipher_update *dupdate);
};

/*
 * Full Cipher data SW context
 */
struct cipherdata {
	uint32_t *descriptor;        /* Job descriptor */
	bool encrypt;                /* Encrypt direction */
	struct caambuf key1;         /* First Key */
	struct caambuf key2;         /* Second Key */
	struct caambuf tweak;        /* XTS Tweak */
	struct caambuf ctx;          /* CAAM Context Register */
	struct caamblock blockbuf;   /* Temporary Block buffer */
	const struct cipheralg *alg; /* Reference to the algo constants */
};

/*
 * Update of the cipher operation of complete block except
 * if last block. Last block can be partial block.
 *
 * @ctx      Cipher context
 * @savectx  Save or not the context
 * @keyid    Id of the key to be used during operation
 * @encrypt  Encrypt or decrypt direction
 * @src      Source data to encrypt/decrypt
 * @dst      [out] Destination data encrypted/decrypted
 * @blockbuf Saved block during previous streaming update
 */
enum caam_status caam_cipher_block(struct cipherdata *ctx, bool savectx,
				   uint8_t keyid, bool encrypt,
				   struct caambuf *src, struct caambuf *dst,
				   bool blockbuf);

/*
 * Update of the cipher operation in xts mode.
 *
 * @dupdate  Data update object
 */
TEE_Result caam_cipher_update_xts(struct drvcrypt_cipher_update *dupdate);

#endif /* __LOCAL_H__ */
