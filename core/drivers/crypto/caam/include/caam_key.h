/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2023 NXP
 */
#ifndef __CAAM_KEY_H__
#define __CAAM_KEY_H__

#include <caam_types.h>
#include <crypto/crypto.h>
#include <types_ext.h>

/*
 * CAAM Key types
 */
enum caam_key_type {
	CAAM_KEY_PLAIN_TEXT = 0, /* Plain text key or red key */
	CAAM_KEY_BLACK_ECB, /* Black key AES-ECB encrypted */
	CAAM_KEY_BLACK_CCM, /* Black key AES-CCM encrypted */
	CAAM_KEY_MAX_VALUE, /* Max value - not valid */
};

/*
 * CAAM key structure
 */
struct caamkey {
	struct caambuf buf; /* Key buffer */
	enum caam_key_type key_type; /* CAAM Key type */
	size_t sec_size; /* Security key size */
	bool is_blob; /* Shows if the key is in blob format */
};

/*
 * Returns the default key type for CAAM key generation.
 * The CAAM can only generate one key type.
 */
static inline enum caam_key_type caam_key_default_key_gen_type(void)
{
	return CAAM_KEY_BLACK_CCM;
}

/*
 * Print CAAM Key structure
 *
 * @trace Additional log string
 * @key Key to print
 */
void caam_key_dump(const char *trace, const struct caamkey *key);

/*
 * Allocate CAAM key buffer based on the CAAM key type, key security size, and
 * whether it is in a blob format or not.
 *
 * @key CAAM key to allocate
 */
enum caam_status caam_key_alloc(struct caamkey *key);

/*
 * Free the CAAM key buffer
 *
 * @key CAAM key to free
 */
void caam_key_free(struct caamkey *key);

/*
 * Perform a cache operation on CAAM key buffer.
 *
 * @op Cache operation type
 * @key CAAM key buffer to operate
 */
void caam_key_cache_op(enum utee_cache_operation op, const struct caamkey *key);

/*
 * Encapsulate or decapsulate the given CAAM key
 *
 * @in_key CAAM Key to encapsulate or decapsulate
 * @out_key CAAM Key operation result. The out_key is allocated by the function.
 */
enum caam_status caam_key_operation_blob(const struct caamkey *in_key,
					 struct caamkey *out_key);

/*
 * Deserialize CAAM key structure from binary buffer
 *
 * @data	Buffer input
 * @size	Buffer input size
 * @key		CAAM key structure to populate
 * @sec_size	Security key size to deserialize, optional. If not needed,
 *		set it to 0.
 */
enum caam_status caam_key_deserialize_from_bin(uint8_t *data, size_t size,
					       struct caamkey *key,
					       size_t sec_size);

/*
 * Serialize CAAM key structure to binary buffer
 *
 * @data	Buffer output
 * @size	Buffer output size
 * @key		CAAM key structure to serialize
 */
enum caam_status caam_key_serialize_to_bin(uint8_t *data, size_t size,
					   const struct caamkey *key);

/*
 * Deserialize CAAM key structure from bignum
 *
 * @inkey	Bignum input
 * @outkey	CAAM key structure to populate
 * @size_sec	Security key size to deserialize, optional. If not needed,
 *		set it to zero.
 */
enum caam_status caam_key_deserialize_from_bn(const struct bignum *inkey,
					      struct caamkey *outkey,
					      size_t size_sec);

/*
 * Serialize CAAM key structure to bignum
 *
 * @outkey	Bignum output
 * @inkey	CAAM key structure to serialize
 */
enum caam_status caam_key_serialize_to_bn(struct bignum *outkey,
					  const struct caamkey *inkey);

/*
 * Return the key buffer size needed given the CAAM key type, key security size,
 * and whether it is in a blob format or not
 *
 * @key	CAAM key structure input
 */
size_t caam_key_get_alloc_size(const struct caamkey *key);

/*
 * Return the buffer size needed to serialize the given CAAM key structure
 *
 * @key		CAAM Key structure to serialize
 * @size	returned buffer size
 */
enum caam_status caam_key_serialized_size(const struct caamkey *key,
					  size_t *size);

/*
 * Encapsulate a plain text key to CAAM black key.
 *
 * @key		CAAM key to encapsulate
 * @key_type	CAAM key encapsulation type
 */
enum caam_status caam_key_black_encapsulation(struct caamkey *key,
					      enum caam_key_type key_type);

/*
 * CAAM Key initialization
 */
enum caam_status caam_key_init(void);
#endif /* __CAAM_KEY_H__ */
