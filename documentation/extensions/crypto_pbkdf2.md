# PKCS #5 v2.0 Key Derivation Function 2 (PBKDF2)

This document describes the OP-TEE implementation of the key derivation function
specified in [RFC 2898](https://www.ietf.org/rfc/rfc2898.txt) section 5.2. This
RFC is a republication of PKCS #5 v2.0 from RSA Laboratories' Public-Key
Cryptography Standards (PKCS) series.

You may disable this extension by setting the following configuration variable
in `conf.mk`:

    CFG_CRYPTO_PBKDF2 := n

## API extension

To support PBKDF2, the *GlobalPlatform TEE Internal Core API Specification
v1.1* was extended with a new algorithm descriptor, new object types, and new
object attributes as described below.

### p.95 Add new object type to TEE_PopulateTransientObject

The following entry shall be added to Table 5-8:

Object type              | Parts
:------------------------|:--------------------------------------------
TEE_TYPE_PBKDF2_PASSWORD | The TEE_ATTR_PBKDF2_PASSWORD part must be provided.

### p.121 Add new algorithms for TEE_AllocateOperation

The following entry shall be added to Table 6-3:

Algorithm                   | Possible Modes
:---------------------------|:--------------
TEE_ALG_PBKDF2_HMAC_SHA1_DERIVE_KEY | TEE_MODE_DERIVE

### p.126 Explain usage of PBKDF2 algorithm in TEE_SetOperationKey

In the bullet list about operation mode, the following shall be added:

    * For the PBKDF2 algorithm, the only supported mode is TEE_MODE_DERIVE.

### p.150 Define TEE_DeriveKey input attributes for new algorithms

The following sentence shall be deleted:

    The TEE_DeriveKey function can only be used with the algorithm
    TEE_ALG_DH_DERIVE_SHARED_SECRET

The following entry shall be added to Table 6-7:

Algorithm                   | Possible operation parameters
:---------------------------|:-----------------------------
TEE_ALG_PBKDF2_HMAC_SHA1_DERIVE_KEY | TEE_ATTR_PBKDF2_DKM_LENGTH: up to 512 bytes. This parameter is mandatory. <br> TEE_ATTR_PBKDF2_SALT <br> TEE_ATTR_PBKDF2_ITERATION_COUNT: This parameter is mandatory.

### p.152 Add new algorithm identifiers

The following entries shall be added to Table 6-8:

Algorithm                            | Identifier
:------------------------------------|:----------
TEE_ALG_PBKDF2_HMAC_SHA1_DERIVE_KEY  | 0x800020C2

### p.154 Define new main algorithm

In Table 6-9 in section 6.10.1, a new value shall be added to the value column
for row bits [7:0]:

Bits       | Function                                       | Value
:----------|:-----------------------------------------------|:-----------------
Bits [7:0] | Identifiy the main underlying algorithm itself | ...<br>0xC2: PBKDF2

The function column for bits[15:12] shall also be modified to read:

Bits         | Function                                     | Value
:------------|:---------------------------------------------|:-----------
Bits [15:12] | Define the message digest for asymmetric signature algorithms or PBKDF2 |

### p.155 Add new object type for PBKDF2 password

The following entry shall be added to Table 6-10:

Name                              | Identifier | Possible sizes
:---------------------------------|:-----------|:--------------------------------
TEE_TYPE_PBKDF2_PASSWORD          | 0xA10000C2 | 8 to 4096 bits (multiple of 8)

### p.156 Add new operation attributes for Concat KDF

The following entries shall be added to Table 6-11:

Name                               | Value      | Protection | Type  | Comment
:----------------------------------|:-----------|:-----------|:------|:--------
TEE_ATTR_PBKDF2_PASSWORD           | 0xC00001C2 | Protected  | Ref   |
TEE_ATTR_PBKDF2_SALT               | 0xD00002C2 | Public     | Ref   |
TEE_ATTR_PBKDF2_ITERATION_COUNT    | 0xF00003C2 | Public     | Value |
TEE_ATTR_PBKDF2_DKM_LENGTH         | 0xF00004C2 | Public     | Value | The length (in bytes) of the derived keying material to be generated, maximum 512.
