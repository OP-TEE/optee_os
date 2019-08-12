/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015, Linaro Limited
 */
#ifndef SIGNED_HDR_H
#define SIGNED_HDR_H

#include <inttypes.h>
#include <tee_api_types.h>
#include <stdlib.h>

enum shdr_img_type {
	SHDR_TA = 0,
	SHDR_BOOTSTRAP_TA = 1,
};

#define SHDR_MAGIC	0x4f545348

/**
 * struct shdr - signed header
 * @magic:	magic number must match SHDR_MAGIC
 * @img_type:	image type, values defined by enum shdr_img_type
 * @img_size:	image size in bytes
 * @algo:	algorithm, defined by public key algorithms TEE_ALG_*
 *		from TEE Internal API specification
 * @hash_size:	size of the signed hash
 * @sig_size:	size of the signature
 * @hash:	hash of an image
 * @sig:	signature of @hash
 */
struct shdr {
	uint32_t magic;
	uint32_t img_type;
	uint32_t img_size;
	uint32_t algo;
	uint16_t hash_size;
	uint16_t sig_size;
	/*
	 * Commented out element used to visualize the layout dynamic part
	 * of the struct.
	 *
	 * hash is accessed through the macro SHDR_GET_HASH and
	 * signature is accessed through the macro SHDR_GET_SIG
	 *
	 * uint8_t hash[hash_size];
	 * uint8_t sig[sig_size];
	 */
};

#define SHDR_GET_SIZE(x)	(sizeof(struct shdr) + (x)->hash_size + \
				 (x)->sig_size)
#define SHDR_GET_HASH(x)	(uint8_t *)(((struct shdr *)(x)) + 1)
#define SHDR_GET_SIG(x)		(SHDR_GET_HASH(x) + (x)->hash_size)

struct shdr_bootstrap_ta {
	uint8_t uuid[sizeof(TEE_UUID)];
	uint32_t ta_version;
};

/*
 * Allocates a struct shdr large enough to hold the entire header,
 * excluding a subheader like struct shdr_bootstrap_ta.
 */
struct shdr *shdr_alloc_and_copy(const struct shdr *img, size_t img_size);

/* Frees a previously allocated struct shdr */
static inline void shdr_free(struct shdr *shdr)
{
	free(shdr);
}

/*
 * Verifies the signature in the @shdr.
 *
 * Note that the static part of struct shdr and payload still need to be
 * checked against the hash contained in the header.
 *
 * Returns TEE_SUCCESS on success or TEE_ERROR_SECURITY on failure
 */
TEE_Result shdr_verify_signature(const struct shdr *shdr);

#endif /*SIGNED_HDR_H*/
