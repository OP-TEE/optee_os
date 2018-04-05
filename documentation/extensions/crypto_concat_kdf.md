# Concatenation Key Derivation Function (Concat KDF)

This document describes the OP-TEE implementation of the key derivation function
specified in section 5.8.1 of NIST publication [SP 800-56A](http://csrc.nist.gov/publications/nistpubs/800-56A/SP800-56A_Revision1_Mar08-2007.pdf), *Recommendation for Pair-Wise Key Establishment Schemes Using Discrete Logarithm Cryptography*. This function is known as *Concatenation KDF* or *Concat
KDF*.

You may disable this extension by setting the following configuration variable
in `conf.mk`:

    CFG_CRYPTO_CONCAT_KDF := n

## Implementation notes

All key and parameter sizes must be multiples of 8 bits. That is:
- Input parameters: the shared secret (*Z*) and *OtherInfo*
- Output parameter: the derived key (*DerivedKeyingMaterial*)

In addition, the maximum size of the derived key is limited by the size of an
object of type TEE_TYPE_GENERIC_SECRET (512 bytes).

This implementation does *not* enforce any requirement on the content of the
*OtherInfo* parameter. It is the application's responsibility to make sure this
parameter is constructed as specified by the NIST specification if compliance
is desired.


## API extension

To support the Concat KDF, the *GlobalPlatform TEE Internal Core API Specification
v1.1* was extended with new algorithm descriptors, new object types, and new
object attributes as described below.

### p.95 Add new object type to TEE_PopulateTransientObject

The following entry shall be added to Table 5-8:

Object type           | Parts
:---------------------|:--------------------------------------------
TEE_TYPE_CONCAT_KDF_Z | The TEE_ATTR_CONCAT_KDF_Z part (input shared secret) must be provided.

### p.121 Add new algorithms for TEE_AllocateOperation

The following entry shall be added to Table 6-3:

Algorithm                   | Possible Modes
:---------------------------|:--------------
TEE_ALG_CONCAT_KDF_SHA1_DERIVE_KEY <br> TEE_ALG_CONCAT_KDF_SHA224_DERIVE_KEY <br> TEE_ALG_CONCAT_KDF_SHA256_DERIVE_KEY <br> TEE_ALG_CONCAT_KDF_SHA384_DERIVE_KEY <br> TEE_ALG_CONCAT_KDF_SHA512_DERIVE_KEY <br> TEE_ALG_CONCAT_KDF_SHA512_DERIVE_KEY | TEE_MODE_DERIVE

### p.126 Explain usage of HKDF algorithms in TEE_SetOperationKey

In the bullet list about operation mode, the following shall be added:

    * For the Concat KDF algorithms, the only supported mode is TEE_MODE_DERIVE.

### p.150 Define TEE_DeriveKey input attributes for new algorithms

The following sentence shall be deleted:

    The TEE_DeriveKey function can only be used with the algorithm
    TEE_ALG_DH_DERIVE_SHARED_SECRET

The following entry shall be added to Table 6-7:

Algorithm                   | Possible operation parameters
:---------------------------|:-----------------------------
TEE_ALG_CONCAT_KDF_SHA1_DERIVE_KEY <br> TEE_ALG_CONCAT_KDF_SHA224_DERIVE_KEY <br> TEE_ALG_CONCAT_KDF_SHA256_DERIVE_KEY <br> TEE_ALG_CONCAT_KDF_SHA384_DERIVE_KEY <br> TEE_ALG_CONCAT_KDF_SHA512_DERIVE_KEY <br> TEE_ALG_CONCAT_KDF_SHA512_DERIVE_KEY | TEE_ATTR_CONCAT_KDF_DKM_LENGTH: up to 512 bytes. This parameter is mandatory. <br> TEE_ATTR_CONCAT_KDF_OTHER_INFO

### p.152 Add new algorithm identifiers

The following entries shall be added to Table 6-8:

Algorithm                            | Identifier
:------------------------------------|:----------
TEE_ALG_CONCAT_KDF_SHA1_DERIVE_KEY   | 0x800020C1
TEE_ALG_CONCAT_KDF_SHA224_DERIVE_KEY | 0x800030C1
TEE_ALG_CONCAT_KDF_SHA256_DERIVE_KEY | 0x800040C1
TEE_ALG_CONCAT_KDF_SHA384_DERIVE_KEY | 0x800050C1
TEE_ALG_CONCAT_KDF_SHA512_DERIVE_KEY | 0x800060C1

### p.154 Define new main algorithm

In Table 6-9 in section 6.10.1, a new value shall be added to the value column
for row bits [7:0]:

Bits       | Function                                       | Value
:----------|:-----------------------------------------------|:-----------------
Bits [7:0] | Identifiy the main underlying algorithm itself | ...<br>0xC1: Concat KDF

The function column for bits[15:12] shall also be modified to read:

Bits         | Function                                     | Value
:------------|:---------------------------------------------|:-----------
Bits [15:12] | Define the message digest for asymmetric signature algorithms or Concat KDF |

### p.155 Add new object type for Concat KDF input shared secret

The following entry shall be added to Table 6-10:

Name                              | Identifier | Possible sizes
:---------------------------------|:-----------|:--------------------------------
TEE_TYPE_CONCAT_KDF_Z             | 0xA10000C1 | 8 to 4096 bits (multiple of 8)

### p.156 Add new operation attributes for Concat KDF

The following entries shall be added to Table 6-11:

Name                               | Value      | Protection | Type  | Comment
:----------------------------------|:-----------|:-----------|:------|:--------
TEE_ATTR_CONCAT_KDF_Z              | 0xC00001C1 | Protected  | Ref   | The shared secret (*Z*)
TEE_ATTR_CONCAT_KDF_OTHER_INFO     | 0xD00002C1 | Public     | Ref   | *OtherInfo*
TEE_ATTR_CONCAT_KDF_DKM_LENGTH     | 0xF00003C1 | Public     | Value | The length (in bytes) of the derived keying material to be generated, maximum 512. This is *KeyDataLen* / 8.
