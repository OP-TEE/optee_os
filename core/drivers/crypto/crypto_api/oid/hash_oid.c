// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2018-2020 NXP
 *
 * Brief   Definition of the Hash's OID
 */

/* Driver Crypto includes */
#include <drvcrypt_asn1_oid.h>
#include <utee_defines.h>

/*
 * Hash OID values
 */
const struct drvcrypt_oid drvcrypt_hash_oid[] = {
	/* empty entry */
	{ NULL, 0 },
	/* MD5 */
	{ DRVCRYPT_OID_ID_MD5, DRVCRYPT_OID_LEN(DRVCRYPT_OID_ID_MD5) },
	/* SHA1 */
	{ DRVCRYPT_OID_ID_SHA1, DRVCRYPT_OID_LEN(DRVCRYPT_OID_ID_SHA1) },
	/* SHA224 */
	{ DRVCRYPT_OID_ID_SHA224, DRVCRYPT_OID_LEN(DRVCRYPT_OID_ID_SHA224) },
	/* SHA256 */
	{ DRVCRYPT_OID_ID_SHA256, DRVCRYPT_OID_LEN(DRVCRYPT_OID_ID_SHA256) },
	/* SHA384 */
	{ DRVCRYPT_OID_ID_SHA384, DRVCRYPT_OID_LEN(DRVCRYPT_OID_ID_SHA384) },
	/* SHA512 */
	{ DRVCRYPT_OID_ID_SHA512, DRVCRYPT_OID_LEN(DRVCRYPT_OID_ID_SHA512) },
};

const struct drvcrypt_oid *drvcrypt_get_alg_hash_oid(uint32_t algo)
{
	uint32_t main_alg = TEE_ALG_GET_MAIN_ALG(algo);

	if (main_alg < ARRAY_SIZE(drvcrypt_hash_oid))
		return &drvcrypt_hash_oid[main_alg];

	return NULL;
}
