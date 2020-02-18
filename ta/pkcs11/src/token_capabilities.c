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

/* PKCS#11 specificies permitted operation for each mechanism  */
static const struct pkcs11_mechachism_modes pkcs11_modes[] = {
	MECHANISM(PKCS11_CKM_AES_ECB,
		  PKCS11_CKFM_ENCRYPT | PKCS11_CKFM_DECRYPT |
		  PKCS11_CKFM_DERIVE |
		  PKCS11_CKFM_WRAP | PKCS11_CKFM_UNWRAP,
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

/*
 * Arrays that centralizes the IDs and processing flags for mechanisms
 * supported by each embedded token. Currently none.
 */
const struct pkcs11_mechachism_modes token_mechanism[] = {
	MECHANISM(PKCS11_CKM_AES_ECB, 0, 0),
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
