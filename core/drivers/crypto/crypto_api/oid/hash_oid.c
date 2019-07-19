// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018-2019 NXP
 *
 * @file    hash_oid.c
 *
 * @brief   Definition of the Hash's OID
 */

/* Driver Crypto includes */
#include <drvcrypt_asn1_oid.h>

/**
 * @brief   Hash OID values
 */
const struct drvcrypt_oid drvcrypt_hash_oid[MAX_HASH_SUPPORTED + 1] = {
	/* empty entry */
	{NULL, 0},
	/* MD5 */
	OID_DEF(OID_ID_MD5),
	/* SHA1 */
	OID_DEF(OID_ID_SHA1),
	/* SHA224 */
	OID_DEF(OID_ID_SHA224),
	/* SHA256 */
	OID_DEF(OID_ID_SHA256),
	/* SHA386 */
	OID_DEF(OID_ID_SHA384),
	/* SHA512 */
	OID_DEF(OID_ID_SHA512),
};

