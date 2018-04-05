# OP-TEE HKDF key derivation support

OP-TEE implements the *HMAC-based Extract-and-Expand Key Derivation Function
(HKDF)* specified in [RFC 5869](http://tools.ietf.org/html/rfc5869). This
file documents the extensions to the *GlobalPlatform TEE Internal Core API
Specification v1.1* that were implemented to support this algorithm. Trusted
Applications should include `<tee_api_defines_extensions.h>` to import the
definitions.

Note that the implementation follows the recommendations of version 1.1 of the
specification for adding new algorithms. It should make it compatible with
future changes to the official specification.

You can disable this extension by setting the following in `conf.mk`:

    CFG_CRYPTO_HKDF := n

## p.95 Add new object type to TEE_PopulateTransientObject

The following entry shall be added to Table 5-8:

Object type       | Parts
:-----------------|:--------------------------------------------
TEE_TYPE_HKDF_IKM | The TEE_ATTR_HKDF_IKM (Input Keying Material) part must be provided.

## p.121 Add new algorithms for TEE_AllocateOperation

The following entry shall be added to Table 6-3:

Algorithm                   | Possible Modes
:---------------------------|:--------------
TEE_ALG_HKDF_MD5_DERIVE_KEY <br> TEE_ALG_HKDF_SHA1_DERIVE_KEY <br> TEE_ALG_HKDF_SHA224_DERIVE_KEY <br> TEE_ALG_HKDF_SHA256_DERIVE_KEY <br> TEE_ALG_HKDF_SHA384_DERIVE_KEY <br> TEE_ALG_HKDF_SHA512_DERIVE_KEY <br> TEE_ALG_HKDF_SHA512_DERIVE_KEY | TEE_MODE_DERIVE

## p.126 Explain usage of HKDF algorithms in TEE_SetOperationKey

In the bullet list about operation mode, the following shall be added:

    * For the HKDF algorithms, the only supported mode is TEE_MODE_DERIVE.

## p.150 Define TEE_DeriveKey input attributes for new algorithms

The following sentence shall be deleted:

    The TEE_DeriveKey function can only be used with the algorithm
    TEE_ALG_DH_DERIVE_SHARED_SECRET

The following entry shall be added to Table 6-7:

Algorithm                   | Possible operation parameters
:---------------------------|:-----------------------------
TEE_ALG_HKDF_MD5_DERIVE_KEY <br> TEE_ALG_HKDF_SHA1_DERIVE_KEY <br> TEE_ALG_HKDF_SHA224_DERIVE_KEY <br> TEE_ALG_HKDF_SHA256_DERIVE_KEY <br> TEE_ALG_HKDF_SHA384_DERIVE_KEY <br> TEE_ALG_HKDF_SHA512_DERIVE_KEY <br> TEE_ALG_HKDF_SHA512_DERIVE_KEY | TEE_ATTR_HKDF_OKM_LENGTH: Number of bytes in the Output Keying Material <br> TEE_ATTR_HKDF_SALT (optional) Salt to be used during the extract step <br> TEE_ATTR_HKDF_INFO (optional) Info to be used during the expand step <br>

## p.152 Add new algorithm identifiers

The following entries shall be added to Table 6-8:

Algorithm                      | Identifier
:------------------------------|:----------
TEE_ALG_HKDF_MD5_DERIVE_KEY    | 0x800010C0
TEE_ALG_HKDF_SHA1_DERIVE_KEY   | 0x800020C0
TEE_ALG_HKDF_SHA224_DERIVE_KEY | 0x800030C0
TEE_ALG_HKDF_SHA256_DERIVE_KEY | 0x800040C0
TEE_ALG_HKDF_SHA384_DERIVE_KEY | 0x800050C0
TEE_ALG_HKDF_SHA512_DERIVE_KEY | 0x800060C0

## p.154 Define new main algorithm

In Table 6-9 in section 6.10.1, a new value shall be added to the value column
for row bits [7:0]:

Bits       | Function                                       | Value
:----------|:-----------------------------------------------|:-----------------
Bits [7:0] | Identifiy the main underlying algorithm itself | ...<br>0xC0: HKDF

The function column for bits[15:12] shall also be modified to read:

Bits         | Function                                     | Value
:------------|:---------------------------------------------|:-----------
Bits [15:12] | Define the message digest for asymmetric signature algorithms or HKDF |

## p.155 Add new object type for HKDF input keying material

The following entry shall be added to Table 6-10:

Name              | Identifier | Possible sizes
:-----------------|:-----------|:--------------------------------
TEE_TYPE_HKDF_IKM | 0xA10000C0 | 8 to 4096 bits (multiple of 8)

## p.156 Add new operation attributes for HKDF salt and info

The following entries shall be added to Table 6-11:

Name                     | Value      | Protection | Type  | Comment
:------------------------|:-----------|:-----------|:------|:--------
TEE_ATTR_HKDF_IKM        | 0xC00001C0 | Protected  | Ref   |
TEE_ATTR_HKDF_SALT       | 0xD00002C0 | Public     | Ref   |
TEE_ATTR_HKDF_INFO       | 0xD00003C0 | Public     | Ref   |
TEE_ATTR_HKDF_OKM_LENGTH | 0xF00004C0 | Public     | Value |

