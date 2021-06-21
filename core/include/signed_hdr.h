/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015, Linaro Limited
 */
#ifndef SIGNED_HDR_H
#define SIGNED_HDR_H

#include <inttypes.h>
#include <stdlib.h>
#include <tee_api_types.h>
#include <util.h>

enum shdr_img_type {
	SHDR_TA = 0,
	SHDR_BOOTSTRAP_TA = 1,
	SHDR_ENCRYPTED_TA = 2,
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

static inline size_t shdr_get_size(const struct shdr *shdr)
{
	size_t s = sizeof(*shdr);

	if (ADD_OVERFLOW(s, shdr->hash_size, &s) ||
	    ADD_OVERFLOW(s, shdr->sig_size, &s))
		return 0;

	return s;
}

#define SHDR_GET_SIZE(x)	shdr_get_size((x))
#define SHDR_GET_HASH(x)	(uint8_t *)(((struct shdr *)(x)) + 1)
#define SHDR_GET_SIG(x)		(SHDR_GET_HASH(x) + (x)->hash_size)

/**
 * struct shdr_bootstrap_ta - bootstrap TA subheader
 * @uuid:	UUID of the TA
 * @ta_version:	Version of the TA
 */
struct shdr_bootstrap_ta {
	uint8_t uuid[sizeof(TEE_UUID)];
	uint32_t ta_version;
};

/**
 * struct shdr_encrypted_ta - encrypted TA header
 * @enc_algo:	authenticated encyption algorithm, defined by symmetric key
 *		algorithms TEE_ALG_* from TEE Internal API
 *		specification
 * @flags:	authenticated encyption flags
 * @iv_size:	size of the initialization vector
 * @tag_size:	size of the authentication tag
 * @iv:		initialization vector
 * @tag:	authentication tag
 */
struct shdr_encrypted_ta {
	uint32_t enc_algo;
	uint32_t flags;
	uint16_t iv_size;
	uint16_t tag_size;
	/*
	 * Commented out element used to visualize the layout dynamic part
	 * of the struct.
	 *
	 * iv is accessed through the macro SHDR_ENC_GET_IV and
	 * tag is accessed through the macro SHDR_ENC_GET_TAG
	 *
	 * uint8_t iv[iv_size];
	 * uint8_t tag[tag_size];
	 */
};

#define SHDR_ENC_KEY_TYPE_MASK	0x1

enum shdr_enc_key_type {
	SHDR_ENC_KEY_DEV_SPECIFIC = 0,
	SHDR_ENC_KEY_CLASS_WIDE = 1,
};

static inline size_t shdr_enc_get_size(const struct shdr_encrypted_ta *ehdr)
{
	size_t s = sizeof(*ehdr);

	if (ADD_OVERFLOW(s, ehdr->iv_size, &s) ||
	    ADD_OVERFLOW(s, ehdr->tag_size, &s))
		return 0;

	return s;
}

#define SHDR_ENC_GET_SIZE(x)	shdr_enc_get_size((x))
#define SHDR_ENC_GET_IV(x)	((uint8_t *) \
				 (((struct shdr_encrypted_ta *)(x)) + 1))
#define SHDR_ENC_GET_TAG(x)	({ typeof(x) _x = (x); \
				   (SHDR_ENC_GET_IV(_x) + _x->iv_size); })

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
