// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017-2020, Linaro Limited
 */

#include <assert.h>
#include <pkcs11_ta.h>
#include <string.h>
#include <util.h>
#include <tee_api.h>
#include <tee_internal_api_extensions.h>

#include "pkcs11_helpers.h"
#include "token_capabilities.h"

#define ALLOWED_PKCS11_CKFM	\
	(PKCS11_CKFM_ENCRYPT | PKCS11_CKFM_DECRYPT |		\
	 PKCS11_CKFM_DERIVE | PKCS11_CKFM_DIGEST |		\
	 PKCS11_CKFM_SIGN | PKCS11_CKFM_SIGN_RECOVER |		\
	 PKCS11_CKFM_VERIFY | PKCS11_CKFM_VERIFY_RECOVER |	\
	 PKCS11_CKFM_GENERATE |	PKCS11_CKFM_GENERATE_KEY_PAIR |	\
	 PKCS11_CKFM_WRAP | PKCS11_CKFM_UNWRAP)

/*
 * Definition of supported processings for a PKCS#11 mechanisms
 * @id: Mechanism ID
 * @flags: Valid PKCS11_CKFM_* for a mechanism as per PKCS#11
 * @one_shot: true of mechanism can be used for a one-short processing
 * @string: Helper string of the mechanism ID for debug purpose
 */
struct pkcs11_mechachism_modes {
	uint32_t id;
	uint32_t flags;
	bool one_shot;
#if CFG_TEE_TA_LOG_LEVEL > 0
	const char *string;
#endif
};

#if CFG_TEE_TA_LOG_LEVEL > 0
#define MECHANISM(_label, _flags, _single_part)	\
	{					\
		.id = _label,			\
		.one_shot = (_single_part),	\
		.flags = (_flags),		\
		.string = #_label,		\
	}
#else
#define MECHANISM(_label, _flags, _single_part)	\
	{					\
		.id = _label,			\
		.one_shot = (_single_part),	\
		.flags = (_flags),		\
	}
#endif

#define SINGLE_PART_ONLY	true
#define ANY_PART		false

#define CKFM_CIPHER		(PKCS11_CKFM_ENCRYPT | PKCS11_CKFM_DECRYPT)
#define CKFM_WRAP_UNWRAP	(PKCS11_CKFM_WRAP | PKCS11_CKFM_UNWRAP)
#define CKFM_CIPHER_WRAP	(CKFM_CIPHER | CKFM_WRAP_UNWRAP)
#define CKFM_CIPHER_WRAP_DERIVE	(CKFM_CIPHER_WRAP | PKCS11_CKFM_DERIVE)
#define CKFM_AUTH_NO_RECOVER	(PKCS11_CKFM_SIGN | PKCS11_CKFM_VERIFY)
#define CKFM_AUTH_WITH_RECOVER	(PKCS11_CKFM_SIGN_RECOVER | \
				 PKCS11_CKFM_VERIFY_RECOVER)

/* PKCS#11 specificies permitted operation for each mechanism  */
static const struct pkcs11_mechachism_modes pkcs11_modes[] = {
	/* AES */
	MECHANISM(PKCS11_CKM_AES_ECB, CKFM_CIPHER_WRAP, ANY_PART),
	MECHANISM(PKCS11_CKM_AES_CBC, CKFM_CIPHER_WRAP, ANY_PART),
	MECHANISM(PKCS11_CKM_AES_CBC_PAD, CKFM_CIPHER_WRAP, ANY_PART),
	MECHANISM(PKCS11_CKM_AES_CTS, CKFM_CIPHER_WRAP, ANY_PART),
	MECHANISM(PKCS11_CKM_AES_CTR, CKFM_CIPHER_WRAP, ANY_PART),
	MECHANISM(PKCS11_CKM_AES_GCM, CKFM_CIPHER_WRAP, ANY_PART),
	MECHANISM(PKCS11_CKM_AES_CMAC, CKFM_AUTH_NO_RECOVER, ANY_PART),
	MECHANISM(PKCS11_CKM_AES_CMAC_GENERAL, CKFM_AUTH_NO_RECOVER, ANY_PART),
	MECHANISM(PKCS11_CKM_AES_ECB_ENCRYPT_DATA, PKCS11_CKFM_DERIVE,
		  ANY_PART),
	MECHANISM(PKCS11_CKM_AES_CBC_ENCRYPT_DATA, PKCS11_CKFM_DERIVE,
		  ANY_PART),
	MECHANISM(PKCS11_CKM_AES_KEY_GEN, PKCS11_CKFM_GENERATE, ANY_PART),
	MECHANISM(PKCS11_CKM_GENERIC_SECRET_KEY_GEN, PKCS11_CKFM_GENERATE,
		  ANY_PART),
	/* Digest */
	MECHANISM(PKCS11_CKM_MD5, PKCS11_CKFM_DIGEST, ANY_PART),
	MECHANISM(PKCS11_CKM_SHA_1, PKCS11_CKFM_DIGEST, ANY_PART),
	MECHANISM(PKCS11_CKM_SHA224, PKCS11_CKFM_DIGEST, ANY_PART),
	MECHANISM(PKCS11_CKM_SHA256, PKCS11_CKFM_DIGEST, ANY_PART),
	MECHANISM(PKCS11_CKM_SHA384, PKCS11_CKFM_DIGEST, ANY_PART),
	MECHANISM(PKCS11_CKM_SHA512, PKCS11_CKFM_DIGEST, ANY_PART),
	/* HMAC */
	MECHANISM(PKCS11_CKM_MD5_HMAC, CKFM_AUTH_NO_RECOVER, ANY_PART),
	MECHANISM(PKCS11_CKM_SHA_1_HMAC, CKFM_AUTH_NO_RECOVER, ANY_PART),
	MECHANISM(PKCS11_CKM_SHA224_HMAC, CKFM_AUTH_NO_RECOVER, ANY_PART),
	MECHANISM(PKCS11_CKM_SHA256_HMAC, CKFM_AUTH_NO_RECOVER, ANY_PART),
	MECHANISM(PKCS11_CKM_SHA384_HMAC, CKFM_AUTH_NO_RECOVER, ANY_PART),
	MECHANISM(PKCS11_CKM_SHA512_HMAC, CKFM_AUTH_NO_RECOVER, ANY_PART),
	MECHANISM(PKCS11_CKM_MD5_HMAC_GENERAL, CKFM_AUTH_NO_RECOVER, ANY_PART),
	MECHANISM(PKCS11_CKM_SHA_1_HMAC_GENERAL, CKFM_AUTH_NO_RECOVER,
		  ANY_PART),
	MECHANISM(PKCS11_CKM_SHA224_HMAC_GENERAL, CKFM_AUTH_NO_RECOVER,
		  ANY_PART),
	MECHANISM(PKCS11_CKM_SHA256_HMAC_GENERAL, CKFM_AUTH_NO_RECOVER,
		  ANY_PART),
	MECHANISM(PKCS11_CKM_SHA384_HMAC_GENERAL, CKFM_AUTH_NO_RECOVER,
		  ANY_PART),
	MECHANISM(PKCS11_CKM_SHA512_HMAC_GENERAL, CKFM_AUTH_NO_RECOVER,
		  ANY_PART),
	/* EC */
	MECHANISM(PKCS11_CKM_EC_KEY_PAIR_GEN, PKCS11_CKFM_GENERATE_KEY_PAIR,
		  ANY_PART),
	MECHANISM(PKCS11_CKM_ECDH1_DERIVE, PKCS11_CKFM_DERIVE,
		  ANY_PART),
	MECHANISM(PKCS11_CKM_ECDSA, CKFM_AUTH_NO_RECOVER, SINGLE_PART_ONLY),
	MECHANISM(PKCS11_CKM_ECDSA_SHA1, CKFM_AUTH_NO_RECOVER, ANY_PART),
	MECHANISM(PKCS11_CKM_ECDSA_SHA224, CKFM_AUTH_NO_RECOVER, ANY_PART),
	MECHANISM(PKCS11_CKM_ECDSA_SHA256, CKFM_AUTH_NO_RECOVER, ANY_PART),
	MECHANISM(PKCS11_CKM_ECDSA_SHA384, CKFM_AUTH_NO_RECOVER, ANY_PART),
	MECHANISM(PKCS11_CKM_ECDSA_SHA512, CKFM_AUTH_NO_RECOVER, ANY_PART),
	/* EDDSA */
	MECHANISM(PKCS11_CKM_EC_EDWARDS_KEY_PAIR_GEN,
		  PKCS11_CKFM_GENERATE_KEY_PAIR, ANY_PART),
	MECHANISM(PKCS11_CKM_EDDSA, CKFM_AUTH_NO_RECOVER, ANY_PART),
	/* RSA */
	MECHANISM(PKCS11_CKM_RSA_AES_KEY_WRAP, CKFM_CIPHER_WRAP,
		  SINGLE_PART_ONLY),
	MECHANISM(PKCS11_CKM_RSA_PKCS_KEY_PAIR_GEN,
		  PKCS11_CKFM_GENERATE_KEY_PAIR, ANY_PART),
	MECHANISM(PKCS11_CKM_RSA_PKCS, CKFM_CIPHER_WRAP | CKFM_AUTH_NO_RECOVER |
		  CKFM_AUTH_WITH_RECOVER, SINGLE_PART_ONLY),
	MECHANISM(PKCS11_CKM_RSA_PKCS_OAEP, CKFM_CIPHER_WRAP,
		  SINGLE_PART_ONLY),
	MECHANISM(PKCS11_CKM_RSA_PKCS_PSS, CKFM_AUTH_NO_RECOVER,
		  SINGLE_PART_ONLY),
	MECHANISM(PKCS11_CKM_MD5_RSA_PKCS, CKFM_AUTH_NO_RECOVER, ANY_PART),
	MECHANISM(PKCS11_CKM_SHA1_RSA_PKCS, CKFM_AUTH_NO_RECOVER, ANY_PART),
	MECHANISM(PKCS11_CKM_SHA1_RSA_PKCS_PSS, CKFM_AUTH_NO_RECOVER, ANY_PART),
	MECHANISM(PKCS11_CKM_SHA256_RSA_PKCS, CKFM_AUTH_NO_RECOVER, ANY_PART),
	MECHANISM(PKCS11_CKM_SHA384_RSA_PKCS, CKFM_AUTH_NO_RECOVER, ANY_PART),
	MECHANISM(PKCS11_CKM_SHA512_RSA_PKCS, CKFM_AUTH_NO_RECOVER, ANY_PART),
	MECHANISM(PKCS11_CKM_SHA256_RSA_PKCS_PSS, CKFM_AUTH_NO_RECOVER,
		  ANY_PART),
	MECHANISM(PKCS11_CKM_SHA384_RSA_PKCS_PSS, CKFM_AUTH_NO_RECOVER,
		  ANY_PART),
	MECHANISM(PKCS11_CKM_SHA512_RSA_PKCS_PSS, CKFM_AUTH_NO_RECOVER,
		  ANY_PART),
	MECHANISM(PKCS11_CKM_SHA224_RSA_PKCS, CKFM_AUTH_NO_RECOVER, ANY_PART),
	MECHANISM(PKCS11_CKM_SHA224_RSA_PKCS_PSS, CKFM_AUTH_NO_RECOVER,
		  ANY_PART),
};

#if CFG_TEE_TA_LOG_LEVEL > 0
const char *mechanism_string_id(enum pkcs11_mechanism_id id)
{
	const size_t offset = sizeof("PKCS11_CKM_") - 1;
	size_t n = 0;

	for (n = 0; n < ARRAY_SIZE(pkcs11_modes); n++)
		if (pkcs11_modes[n].id == id)
			return pkcs11_modes[n].string + offset;

	return "Unknown ID";
}
#endif /*CFG_TEE_TA_LOG_LEVEL*/

/*
 * Return true if @id is a valid mechanism ID
 */
bool mechanism_is_valid(enum pkcs11_mechanism_id id)
{
	size_t n = 0;

	for (n = 0; n < ARRAY_SIZE(pkcs11_modes); n++)
		if (id == pkcs11_modes[n].id)
			return true;

	return false;
}

/*
 * Return true if mechanism ID is valid and flags matches PKCS#11 compliancy
 */
bool __maybe_unused mechanism_flags_complies_pkcs11(uint32_t mechanism_type,
						    uint32_t flags)
{
	size_t n = 0;

	assert((flags & ~ALLOWED_PKCS11_CKFM) == 0);

	for (n = 0; n < ARRAY_SIZE(pkcs11_modes); n++) {
		if (pkcs11_modes[n].id == mechanism_type) {
			if (flags & ~pkcs11_modes[n].flags)
				EMSG("%s flags: 0x%"PRIx32" vs 0x%"PRIx32,
				     id2str_mechanism(mechanism_type),
				     flags, pkcs11_modes[n].flags);

			return (flags & ~pkcs11_modes[n].flags) == 0;
		}
	}

	/* Mechanism ID unexpectedly not found */
	return false;
}

bool mechanism_is_one_shot_only(uint32_t mechanism_type)
{
	size_t n = 0;

	for (n = 0; n < ARRAY_SIZE(pkcs11_modes); n++)
		if (pkcs11_modes[n].id == mechanism_type)
			return pkcs11_modes[n].one_shot;

	/* Mechanism ID unexpectedly not found */
	TEE_Panic(PKCS11_RV_NOT_FOUND);
	/* Dummy return to keep compiler happy */
	return false;
}

/*
 * Field single_part_only is unused from array token_mechanism[], hence
 * simply use ANY_PART for all mechanism there.
 */
#define TA_MECHANISM(_label, _flags)	MECHANISM((_label), (_flags), ANY_PART)

/*
 * Arrays that centralizes the IDs and processing flags for mechanisms
 * supported by each embedded token.
 */
const struct pkcs11_mechachism_modes token_mechanism[] = {
	TA_MECHANISM(PKCS11_CKM_AES_ECB, CKFM_CIPHER_WRAP),
	TA_MECHANISM(PKCS11_CKM_AES_CBC, CKFM_CIPHER_WRAP),
	TA_MECHANISM(PKCS11_CKM_AES_CTR, CKFM_CIPHER),
	TA_MECHANISM(PKCS11_CKM_AES_GCM, CKFM_CIPHER),
	TA_MECHANISM(PKCS11_CKM_AES_CTS, CKFM_CIPHER),
	TA_MECHANISM(PKCS11_CKM_AES_CMAC, CKFM_AUTH_NO_RECOVER),
	TA_MECHANISM(PKCS11_CKM_AES_CMAC_GENERAL, CKFM_AUTH_NO_RECOVER),
	TA_MECHANISM(PKCS11_CKM_AES_ECB_ENCRYPT_DATA, PKCS11_CKFM_DERIVE),
	TA_MECHANISM(PKCS11_CKM_AES_CBC_ENCRYPT_DATA, PKCS11_CKFM_DERIVE),
	TA_MECHANISM(PKCS11_CKM_ECDH1_DERIVE, PKCS11_CKFM_DERIVE),
	TA_MECHANISM(PKCS11_CKM_AES_KEY_GEN, PKCS11_CKFM_GENERATE),
	TA_MECHANISM(PKCS11_CKM_GENERIC_SECRET_KEY_GEN, PKCS11_CKFM_GENERATE),
	TA_MECHANISM(PKCS11_CKM_MD5, PKCS11_CKFM_DIGEST),
	TA_MECHANISM(PKCS11_CKM_SHA_1, PKCS11_CKFM_DIGEST),
	TA_MECHANISM(PKCS11_CKM_SHA224, PKCS11_CKFM_DIGEST),
	TA_MECHANISM(PKCS11_CKM_SHA256, PKCS11_CKFM_DIGEST),
	TA_MECHANISM(PKCS11_CKM_SHA384, PKCS11_CKFM_DIGEST),
	TA_MECHANISM(PKCS11_CKM_SHA512, PKCS11_CKFM_DIGEST),
	TA_MECHANISM(PKCS11_CKM_MD5_HMAC, CKFM_AUTH_NO_RECOVER),
	TA_MECHANISM(PKCS11_CKM_SHA_1_HMAC, CKFM_AUTH_NO_RECOVER),
	TA_MECHANISM(PKCS11_CKM_SHA224_HMAC, CKFM_AUTH_NO_RECOVER),
	TA_MECHANISM(PKCS11_CKM_SHA256_HMAC, CKFM_AUTH_NO_RECOVER),
	TA_MECHANISM(PKCS11_CKM_SHA384_HMAC, CKFM_AUTH_NO_RECOVER),
	TA_MECHANISM(PKCS11_CKM_SHA512_HMAC, CKFM_AUTH_NO_RECOVER),
	TA_MECHANISM(PKCS11_CKM_MD5_HMAC_GENERAL, CKFM_AUTH_NO_RECOVER),
	TA_MECHANISM(PKCS11_CKM_SHA_1_HMAC_GENERAL, CKFM_AUTH_NO_RECOVER),
	TA_MECHANISM(PKCS11_CKM_SHA224_HMAC_GENERAL, CKFM_AUTH_NO_RECOVER),
	TA_MECHANISM(PKCS11_CKM_SHA256_HMAC_GENERAL, CKFM_AUTH_NO_RECOVER),
	TA_MECHANISM(PKCS11_CKM_SHA384_HMAC_GENERAL, CKFM_AUTH_NO_RECOVER),
	TA_MECHANISM(PKCS11_CKM_SHA512_HMAC_GENERAL, CKFM_AUTH_NO_RECOVER),
	TA_MECHANISM(PKCS11_CKM_EC_KEY_PAIR_GEN,
		     PKCS11_CKFM_GENERATE_KEY_PAIR),
	TA_MECHANISM(PKCS11_CKM_EC_EDWARDS_KEY_PAIR_GEN,
		     PKCS11_CKFM_GENERATE_KEY_PAIR),
	TA_MECHANISM(PKCS11_CKM_ECDSA, CKFM_AUTH_NO_RECOVER),
	TA_MECHANISM(PKCS11_CKM_ECDSA_SHA1, CKFM_AUTH_NO_RECOVER),
	TA_MECHANISM(PKCS11_CKM_ECDSA_SHA224, CKFM_AUTH_NO_RECOVER),
	TA_MECHANISM(PKCS11_CKM_ECDSA_SHA256, CKFM_AUTH_NO_RECOVER),
	TA_MECHANISM(PKCS11_CKM_ECDSA_SHA384, CKFM_AUTH_NO_RECOVER),
	TA_MECHANISM(PKCS11_CKM_ECDSA_SHA512, CKFM_AUTH_NO_RECOVER),
	TA_MECHANISM(PKCS11_CKM_EDDSA, CKFM_AUTH_NO_RECOVER),
	TA_MECHANISM(PKCS11_CKM_RSA_AES_KEY_WRAP, CKFM_CIPHER_WRAP),
	TA_MECHANISM(PKCS11_CKM_RSA_PKCS_KEY_PAIR_GEN,
		     PKCS11_CKFM_GENERATE_KEY_PAIR),
	TA_MECHANISM(PKCS11_CKM_RSA_PKCS, CKFM_CIPHER | CKFM_AUTH_NO_RECOVER),
	TA_MECHANISM(PKCS11_CKM_RSA_PKCS_PSS, CKFM_AUTH_NO_RECOVER),
	TA_MECHANISM(PKCS11_CKM_MD5_RSA_PKCS, CKFM_AUTH_NO_RECOVER),
	TA_MECHANISM(PKCS11_CKM_SHA1_RSA_PKCS, CKFM_AUTH_NO_RECOVER),
	TA_MECHANISM(PKCS11_CKM_RSA_PKCS_OAEP, CKFM_CIPHER),
	TA_MECHANISM(PKCS11_CKM_SHA1_RSA_PKCS_PSS, CKFM_AUTH_NO_RECOVER),
	TA_MECHANISM(PKCS11_CKM_SHA256_RSA_PKCS, CKFM_AUTH_NO_RECOVER),
	TA_MECHANISM(PKCS11_CKM_SHA384_RSA_PKCS, CKFM_AUTH_NO_RECOVER),
	TA_MECHANISM(PKCS11_CKM_SHA512_RSA_PKCS, CKFM_AUTH_NO_RECOVER),
	TA_MECHANISM(PKCS11_CKM_SHA256_RSA_PKCS_PSS, CKFM_AUTH_NO_RECOVER),
	TA_MECHANISM(PKCS11_CKM_SHA384_RSA_PKCS_PSS, CKFM_AUTH_NO_RECOVER),
	TA_MECHANISM(PKCS11_CKM_SHA512_RSA_PKCS_PSS, CKFM_AUTH_NO_RECOVER),
	TA_MECHANISM(PKCS11_CKM_SHA224_RSA_PKCS, CKFM_AUTH_NO_RECOVER),
	TA_MECHANISM(PKCS11_CKM_SHA224_RSA_PKCS_PSS, CKFM_AUTH_NO_RECOVER),
};

/*
 * tee_malloc_mechanism_array - Allocate and fill array of supported mechanisms
 * @count: [in] [out] Pointer to number of mechanism IDs in client resource
 * Return allocated array of the supported mechanism IDs
 *
 * Allocates array with 32bit cells mechanism IDs for the supported ones only
 * if *@count covers number mechanism IDs exposed.
 */
uint32_t *tee_malloc_mechanism_list(size_t *out_count)
{
	size_t n = 0;
	size_t count = 0;
	uint32_t *array = NULL;

	for (n = 0; n < ARRAY_SIZE(token_mechanism); n++)
		if (token_mechanism[n].flags)
			count++;

	if (*out_count >= count)
		array = TEE_Malloc(count * sizeof(*array),
				   TEE_USER_MEM_HINT_NO_FILL_ZERO);

	*out_count = count;

	if (!array)
		return NULL;

	for (n = 0; n < ARRAY_SIZE(token_mechanism); n++) {
		if (token_mechanism[n].flags) {
			count--;
			array[count] = token_mechanism[n].id;
		}
	}
	assert(!count);

	return array;
}

uint32_t mechanism_supported_flags(enum pkcs11_mechanism_id id)
{
	size_t n = 0;

	for (n = 0; n < ARRAY_SIZE(token_mechanism); n++) {
		if (id == token_mechanism[n].id) {
			uint32_t flags = token_mechanism[n].flags;

			assert(mechanism_flags_complies_pkcs11(id, flags));
			return flags;
		}
	}

	return 0;
}

void pkcs11_mechanism_supported_key_sizes(uint32_t proc_id,
					  uint32_t *min_key_size,
					  uint32_t *max_key_size)
{
	switch (proc_id) {
	case PKCS11_CKM_GENERIC_SECRET_KEY_GEN:
		/* This mechanism expects the keysize to be returned in bits */
		*min_key_size = 1;		/* in bits */
		*max_key_size = 4096;		/* in bits */
		break;
	case PKCS11_CKM_MD5_HMAC:
	case PKCS11_CKM_MD5_HMAC_GENERAL:
		*min_key_size = 8;
		*max_key_size = 64;
		break;
	case PKCS11_CKM_SHA_1_HMAC:
	case PKCS11_CKM_SHA_1_HMAC_GENERAL:
		*min_key_size = 10;
		*max_key_size = 64;
		break;
	case PKCS11_CKM_SHA224_HMAC:
	case PKCS11_CKM_SHA224_HMAC_GENERAL:
		*min_key_size = 14;
		*max_key_size = 64;
		break;
	case PKCS11_CKM_SHA256_HMAC:
	case PKCS11_CKM_SHA256_HMAC_GENERAL:
		*min_key_size = 24;
		*max_key_size = 128;
		break;
	case PKCS11_CKM_SHA384_HMAC:
	case PKCS11_CKM_SHA384_HMAC_GENERAL:
		*min_key_size = 32;
		*max_key_size = 128;
		break;
	case PKCS11_CKM_SHA512_HMAC:
	case PKCS11_CKM_SHA512_HMAC_GENERAL:
		*min_key_size = 32;
		*max_key_size = 128;
		break;
	case PKCS11_CKM_AES_KEY_GEN:
	case PKCS11_CKM_AES_ECB:
	case PKCS11_CKM_AES_CBC:
	case PKCS11_CKM_AES_CBC_PAD:
	case PKCS11_CKM_AES_CTR:
	case PKCS11_CKM_AES_GCM:
	case PKCS11_CKM_AES_CTS:
	case PKCS11_CKM_AES_CMAC:
	case PKCS11_CKM_AES_CMAC_GENERAL:
		*min_key_size = 16;
		*max_key_size = 32;
		break;
	case PKCS11_CKM_EC_KEY_PAIR_GEN:
	case PKCS11_CKM_ECDSA:
	case PKCS11_CKM_ECDSA_SHA1:
	case PKCS11_CKM_ECDSA_SHA224:
	case PKCS11_CKM_ECDSA_SHA256:
	case PKCS11_CKM_ECDSA_SHA384:
	case PKCS11_CKM_ECDSA_SHA512:
	case PKCS11_CKM_ECDH1_DERIVE:
		*min_key_size = 160;	/* in bits */
		*max_key_size = 521;	/* in bits */
		break;
	case PKCS11_CKM_EC_EDWARDS_KEY_PAIR_GEN:
	case PKCS11_CKM_EDDSA:
		*min_key_size = 256;	/* in bits */
		*max_key_size = 448;	/* in bits */
		break;
	case PKCS11_CKM_RSA_PKCS_KEY_PAIR_GEN:
	case PKCS11_CKM_RSA_PKCS:
	case PKCS11_CKM_MD5_RSA_PKCS:
	case PKCS11_CKM_SHA1_RSA_PKCS:
	case PKCS11_CKM_RSA_PKCS_OAEP:
	case PKCS11_CKM_SHA1_RSA_PKCS_PSS:
	case PKCS11_CKM_SHA256_RSA_PKCS:
	case PKCS11_CKM_SHA384_RSA_PKCS:
	case PKCS11_CKM_SHA512_RSA_PKCS:
	case PKCS11_CKM_SHA256_RSA_PKCS_PSS:
	case PKCS11_CKM_SHA384_RSA_PKCS_PSS:
	case PKCS11_CKM_SHA512_RSA_PKCS_PSS:
	case PKCS11_CKM_SHA224_RSA_PKCS:
	case PKCS11_CKM_SHA224_RSA_PKCS_PSS:
		*min_key_size = 256;	/* in bits */
		*max_key_size = 4096;	/* in bits */
		break;
	default:
		*min_key_size = 0;
		*max_key_size = 0;
		break;
	}
}

void mechanism_supported_key_sizes_bytes(uint32_t proc_id,
					 uint32_t *min_key_size,
					 uint32_t *max_key_size)
{
	pkcs11_mechanism_supported_key_sizes(proc_id, min_key_size,
					     max_key_size);

	switch (proc_id) {
	case PKCS11_CKM_GENERIC_SECRET_KEY_GEN:
	case PKCS11_CKM_EC_EDWARDS_KEY_PAIR_GEN:
	case PKCS11_CKM_EC_KEY_PAIR_GEN:
	case PKCS11_CKM_ECDSA:
	case PKCS11_CKM_EDDSA:
	case PKCS11_CKM_ECDSA_SHA1:
	case PKCS11_CKM_ECDSA_SHA224:
	case PKCS11_CKM_ECDSA_SHA256:
	case PKCS11_CKM_ECDSA_SHA384:
	case PKCS11_CKM_ECDSA_SHA512:
	case PKCS11_CKM_RSA_PKCS_KEY_PAIR_GEN:
		/* Size is in bits -> convert to bytes and ceil */
		*min_key_size = ROUNDUP(*min_key_size, 8) / 8;
		*max_key_size = ROUNDUP(*max_key_size, 8) / 8;
		break;
	default:
		/* Size is already in bytes */
		break;
	}
}
