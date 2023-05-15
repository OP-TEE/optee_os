/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2019-2021 NXP
 *
 * CAAM hash/HMAC local header.
 */
#ifndef __LOCAL_H__
#define __LOCAL_H__

#include <caam_common.h>

/*
 * Full hashing/HMAC data SW context
 */
struct hashctx {
	uint32_t *descriptor;	   /* Job descriptor */
	struct caamblock blockbuf; /* Temporary block buffer */
	struct caambuf ctx;	   /* Hash context used by the CAAM */
	const struct hashalg *alg; /* Reference to the algo constants */
	struct caambuf key;	   /* HMAC split key */
	bool initialized;	   /* Context initialization flag */
};

/*
 * Hash/HMAC algorithm definition
 */
struct hashalg {
	uint32_t type;	     /* Algo type for operation */
	uint8_t size_digest; /* Digest size */
	uint8_t size_block;  /* Computing block size */
	uint8_t size_ctx;    /* CAAM context register size (8 + digest size) */
	uint8_t size_key;    /* HMAC split key size */
};

/* First part CAAM HW context - message length */
#define HASH_MSG_LEN 8

/*
 * Initialization of the hash/HMAC operation
 *
 * @ctx   Operation software context
 */
TEE_Result caam_hash_hmac_init(struct hashctx *ctx);

/*
 * Update the hash/HMAC operation
 *
 * @ctx   Operation software context
 * @data  Data to hash
 * @len   Data length
 */
TEE_Result caam_hash_hmac_update(struct hashctx *ctx, const uint8_t *data,
				 size_t len);

/*
 * Finalize the hash/HMAC operation
 *
 * @ctx     Operation software context
 * @digest  [out] Hash digest buffer
 * @len     Digest buffer length
 */
TEE_Result caam_hash_hmac_final(struct hashctx *ctx, uint8_t *digest,
				size_t len);

/*
 * Copy sofware hashing context
 *
 * @dst  [out] Reference the destination context
 * @src  Reference the source context
 */
void caam_hash_hmac_copy_state(struct hashctx *dst, struct hashctx *src);

/*
 * Free the software context
 *
 * @ctx    [in/out] Caller context variable
 */
void caam_hash_hmac_free(struct hashctx *ctx);

/*
 * Get hash/HMAC algorithm definition
 *
 * @algo   Hash algorithm
 */
const struct hashalg *caam_hash_get_alg(uint32_t algo);

/*
 * Allocate the internal hashing data context
 *
 * @ctx    [in/out] Caller context variable
 */
TEE_Result caam_hash_hmac_allocate(struct hashctx *ctx);

#endif /* __LOCAL_H__ */
