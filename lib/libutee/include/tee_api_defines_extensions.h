/*
 * Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
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
 * Implementation-specific object storage constants
 */

/* Storage is provided by the Rich Execution Environment (REE) */
#define TEE_STORAGE_PRIVATE_REE	 0x80000000
/* Storage is the Replay Protected Memory Block partition of an eMMC device */
#define TEE_STORAGE_PRIVATE_RPMB 0x80000100

#endif /* TEE_API_DEFINES_EXTENSIONS_H */
