/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015, Linaro Limited
 */
#ifndef __SIGNED_HDR_H
#define __SIGNED_HDR_H

#include <inttypes.h>
#include <stdlib.h>
#include <tee_api_types.h>
#include <util.h>

enum shdr_img_type {
	SHDR_TA = 0,
	SHDR_BOOTSTRAP_TA = 1,
	SHDR_ENCRYPTED_TA = 2,
	SHDR_SUBKEY = 3,
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
 * struct shdr_subkey - subkey header
 * @uuid:		UUID of the subkey
 * @name_size:		The size of a name field that follows right
 *			after this header, before the next signed header.
 * @subkey_version:	Version of the subkey
 * @max_depth:		Maximum depth supported below this subkey
 * @algo:		Algorithm, defined by public key algorithms TEE_ALG_*
 *			from TEE Internal API specification
 * @attr_count:		Number of attributes for the public key matching
 *			@algo.
 * @attrs:		Attributes for the public key matching @algo.
 * @attrs[].id:		Attribute ID TEE_ATTR_* from GlobalPlatform
 * @attrs[].offs:	Offset of the attribute value from start of
 *			struct shdr_subkey
 * @attrs[].size:	Attribute size
 *
 * The @uuid defines UUID URN Namespace (RFC4122), the next UUID after this
 * header (another subkey or a TA) must be in the namespace of this UUID.
 * This means that further subkeys or TAs have their UUID fixed in the
 * hierarchy and cannot be moved up or below another subkey.
 *
 * If @name_size is non-zero it indicates that a name field of this size
 * exists and is used to generate the UUID of the following TA or subkey.
 * If it's zero the following TA or subkey must have a matching UUID.
 *
 * The @subkey_version field is used as a rollback measure. The version is
 * checked against earlier saved values of this subkey. If the latest known
 * version is less than this the stored value is updated. If the latest
 * known version is larger than this then the subkey is refused.
 *
 * The @max_depth defines how many levels are allowed below this subkey,
 * the value 0 means only TAs are allowed below. The value 1 means that
 * eventual subkeys below must have the value 0 in their @max_depth field.
 *
 * Each attribute of @attrs must be within range of the image size of this
 * header defined in the preceding struct shdr.
 *
 * The next struct shdr is found right after the indicated end of the
 * previous struct shdr. Signature verification starts over with the
 * next struct shdr using this subkey instead of the root key.
 */
struct shdr_subkey {
	uint8_t uuid[sizeof(TEE_UUID)];
	uint32_t name_size;
	uint32_t subkey_version;
	uint32_t max_depth;
	uint32_t algo;
	uint32_t attr_count;
	struct shdr_subkey_attr {
		uint32_t id;
		uint32_t offs;
		uint32_t size;
	} attrs[];
};

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
struct shdr *shdr_alloc_and_copy(size_t offs, const void *img, size_t img_size);

/* Frees a previously allocated struct shdr */
static inline void shdr_free(struct shdr *shdr)
{
	free(shdr);
}

struct shdr_pub_key {
	uint32_t main_algo;
	uint8_t uuid[sizeof(TEE_UUID)];
	uint8_t next_uuid[sizeof(TEE_UUID)];
	uint32_t max_depth;
	uint32_t name_size;
	uint32_t version;
	union {
		struct rsa_public_key *rsa;
	} pub_key;
};

TEE_Result shdr_load_pub_key(const struct shdr *shdr, size_t offs,
			     const uint8_t *ns_img, size_t ns_img_size,
			     const uint8_t next_uuid[sizeof(TEE_UUID)],
			     uint32_t max_depth, struct shdr_pub_key *key);
void shdr_free_pub_key(struct shdr_pub_key *key);
TEE_Result shdr_verify_signature2(struct shdr_pub_key *key,
				  const struct shdr *shdr);

/*
 * Verifies the signature in the @shdr.
 *
 * Note that the static part of struct shdr and payload still need to be
 * checked against the hash contained in the header.
 *
 * Returns TEE_SUCCESS on success or TEE_ERROR_SECURITY on failure
 */
TEE_Result shdr_verify_signature(const struct shdr *shdr);

#endif /*__SIGNED_HDR_H*/
