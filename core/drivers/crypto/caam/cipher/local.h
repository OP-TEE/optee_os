/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2018-2021 NXP
 *
 * CAAM Cipher Local header.
 */
#ifndef __LOCAL_H__
#define __LOCAL_H__

#include <caam_utils_dmaobj.h>
#include <drvcrypt.h>
#include <drvcrypt_cipher.h>

/*
 * Definition of the maximum number of CAAM Job descriptor entries
 */
#ifdef CFG_CAAM_64BIT
#define MAX_DESC_ENTRIES 22
#else
#define MAX_DESC_ENTRIES 16
#endif

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

	/* Additionnal Data for the MAC */
	unsigned int mode; /* MAC TEE_CHAIN_MODE* */
	size_t countdata;  /* MAC Number of input data */
};

/*
 * Cipher additionnal data block
 */
enum caam_cipher_block {
	CIPHER_BLOCK_NONE = 0,
	CIPHER_BLOCK_IN,
	CIPHER_BLOCK_OUT,
	CIPHER_BLOCK_BOTH,
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
 */
enum caam_status caam_cipher_block(struct cipherdata *ctx, bool savectx,
				   uint8_t keyid, bool encrypt,
				   struct caamdmaobj *src,
				   struct caamdmaobj *dst);

/*
 * Update of the cipher operation in xts mode.
 *
 * @dupdate  Data update object
 */
TEE_Result caam_cipher_update_xts(struct drvcrypt_cipher_update *dupdate);

/*
 * Initialization of the cipher operation
 *
 * @dinit  Data initialization object
 */
TEE_Result caam_cipher_initialize(struct drvcrypt_cipher_init *dinit);

/*
 * Free software context
 *
 * @ctx    Caller context variable
 */
void caam_cipher_free(void *ctx);

/*
 * Copy software Context
 *
 * @dst_ctx  [out] Reference the context destination
 * @src_ctx  Reference the context source
 */
void caam_cipher_copy_state(void *dst_ctx, void *src_ctx);

#endif /* __LOCAL_H__ */
