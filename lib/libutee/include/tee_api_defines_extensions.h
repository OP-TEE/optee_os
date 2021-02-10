/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, Linaro Limited
 * Copyright (c) 2021, SumUp Services GmbH
 */

#ifndef TEE_API_DEFINES_EXTENSIONS_H
#define TEE_API_DEFINES_EXTENSIONS_H

/*
 * HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
 */

#define TEE_ALG_HKDF_MD5_DERIVE_KEY     0x800010C0
#define TEE_ALG_HKDF_SHA1_DERIVE_KEY    0x800020C0
#define TEE_ALG_HKDF_SHA224_DERIVE_KEY  0x800030C0
#define TEE_ALG_HKDF_SHA256_DERIVE_KEY  0x800040C0
#define TEE_ALG_HKDF_SHA384_DERIVE_KEY  0x800050C0
#define TEE_ALG_HKDF_SHA512_DERIVE_KEY  0x800060C0

#define TEE_TYPE_HKDF_IKM               0xA10000C0

#define TEE_ATTR_HKDF_IKM               0xC00001C0
#define TEE_ATTR_HKDF_SALT              0xD00002C0
#define TEE_ATTR_HKDF_INFO              0xD00003C0
#define TEE_ATTR_HKDF_OKM_LENGTH        0xF00004C0

/*
 * Concatenation Key Derivation Function (Concat KDF)
 * NIST SP 800-56A section 5.8.1
 */

#define TEE_ALG_CONCAT_KDF_SHA1_DERIVE_KEY    0x800020C1
#define TEE_ALG_CONCAT_KDF_SHA224_DERIVE_KEY  0x800030C1
#define TEE_ALG_CONCAT_KDF_SHA256_DERIVE_KEY  0x800040C1
#define TEE_ALG_CONCAT_KDF_SHA384_DERIVE_KEY  0x800050C1
#define TEE_ALG_CONCAT_KDF_SHA512_DERIVE_KEY  0x800060C1

#define TEE_TYPE_CONCAT_KDF_Z                 0xA10000C1

#define TEE_ATTR_CONCAT_KDF_Z                 0xC00001C1
#define TEE_ATTR_CONCAT_KDF_OTHER_INFO        0xD00002C1
#define TEE_ATTR_CONCAT_KDF_DKM_LENGTH        0xF00003C1

/*
 * PKCS #5 v2.0 Key Derivation Function 2 (PBKDF2)
 * RFC 2898 section 5.2
 * https://www.ietf.org/rfc/rfc2898.txt
 */

#define TEE_ALG_PBKDF2_HMAC_SHA1_DERIVE_KEY 0x800020C2

#define TEE_TYPE_PBKDF2_PASSWORD            0xA10000C2

#define TEE_ATTR_PBKDF2_PASSWORD            0xC00001C2
#define TEE_ATTR_PBKDF2_SALT                0xD00002C2
#define TEE_ATTR_PBKDF2_ITERATION_COUNT     0xF00003C2
#define TEE_ATTR_PBKDF2_DKM_LENGTH          0xF00004C2

/*
 * PKCS#1 v1.5 RSASSA pre-hashed sign/verify
 */

#define TEE_ALG_RSASSA_PKCS1_V1_5	0xF0000830

/*
 *  TDEA CMAC (NIST SP800-38B)
 */
#define TEE_ALG_DES3_CMAC	0xF0000613

/*
 * Implementation-specific object storage constants
 */

/* Storage is provided by the Rich Execution Environment (REE) */
#define TEE_STORAGE_PRIVATE_REE	 0x80000000
/* Storage is the Replay Protected Memory Block partition of an eMMC device */
#define TEE_STORAGE_PRIVATE_RPMB 0x80000100
/* Was TEE_STORAGE_PRIVATE_SQL, which isn't supported any longer */
#define TEE_STORAGE_PRIVATE_SQL_RESERVED  0x80000200

/*
 * Extension of "Memory Access Rights Constants"
 * #define TEE_MEMORY_ACCESS_READ             0x00000001
 * #define TEE_MEMORY_ACCESS_WRITE            0x00000002
 * #define TEE_MEMORY_ACCESS_ANY_OWNER        0x00000004
 *
 * TEE_MEMORY_ACCESS_NONSECURE : if set TEE_CheckMemoryAccessRights()
 * successfully returns only if target vmem range is mapped non-secure.
 *
 * TEE_MEMORY_ACCESS_SECURE : if set TEE_CheckMemoryAccessRights()
 * successfully returns only if target vmem range is mapped secure.

 */
#define TEE_MEMORY_ACCESS_NONSECURE          0x10000000
#define TEE_MEMORY_ACCESS_SECURE             0x20000000

/*
 * Implementation-specific login types
 */

/* Private login method for REE kernel clients */
#define TEE_LOGIN_REE_KERNEL		0x80000000

#endif /* TEE_API_DEFINES_EXTENSIONS_H */
