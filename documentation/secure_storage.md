# Secure Storage in OP-TEE

## Background

Secure Storage in OP-TEE is implemented according to what has been defined
in GloblaPlatform’s TEE Internal API specification (here called Trusted
Storage). This specification mandates that it should be possible to store
general-purpose data and key material that guarantees confidentiality and
integrity of the data stored and the atomicity of the operations that modifies
the storage (atomicity here means that either the entire operation completes
successfully or no write is done).

There are currently two secure storage implementations in OP-TEE:

- The first one relies on the normal world (REE) file system. It is described in
  this document and is the default implementation. It is enabled at compile time
  by `CFG_REE_FS=y`.
- The second one makes use of the Replay Protected Memory Block (RPMB) partition
  of an eMMC device, and is enabled by setting `CFG_RPMB_FS=y`. It is described
  in [secure_storage_rpmb.md](secure_storage_rpmb.md).

It is possible to use the normal world file systems and the RPMB implementations
simultaneously. For this, two OP-TEE specific storage identifiers have been
defined: `TEE_STORAGE_PRIVATE_REE` and `TEE_STORAGE_PRIVATE_RPMB`. Depending
on the compile-time configuration, one or several values may be used.
The value `TEE_STORAGE_PRIVATE` selects the REE FS when available, otherwise the
RPMB FS (in this order).

The rest of this document describes the REE FS only.

## Overview

![Secure Storage System Architecture](images/secure_storage/secure_storage_system_architecture.png
"Secure Storage System Architecture")

### Source Files in OP-TEE OS

| source file |     |
| ----------- | --- |
| **[core/tee/tee_svc_storage.c](../core/tee/tee_svc_storage.c)** | TEE trusted storage service calls |
| **[core/tee/tee_ree_fs.c](../core/tee/tee_ree_fs)** | TEE file system & REE file operation interface |
| **[core/tee/fs_htree.c](../core/tee/fs_htree.c)** | Hash tree |
| **[core/tee/tee_fs_key_manager.c](../core/tee/tee_fs_key_manager.c)** | Key manager |
| **[lib/libutee/](../lib/libutee/)** | GlobalPlatform Internal API library |

### Basic File Operation Flow

When a TA is calling the write function provided by GP Trusted Storage API to
write data to a persistent object, a corresponding syscall implemented in TEE
Trusted Storage Service will be called, which in turn will invoke a series of
TEE file operations to store the data. TEE file system will then encrypt the
data and send REE file operation commands and the encrypted data to TEE
supplicant by a series of RPC messages. TEE supplicant will receive the
messages and store the encrypted data accordingly to the Linux file system.
Reading files are handled in a similar manner.

### GlobalPlatform Trusted Storage Requirement

Below is an excerpt from the specification, listing the most vital requirements:

> 1. The Trusted Storage may be backed by non-secure resources as long as
>    suitable cryptographic protection is applied, which MUST be as strong as
>    the means used to protect the TEE code and data itself.
> 2. The Trusted Storage MUST be bound to a particular device, which means that
>    it MUST be accessible or modifiable only by authorized TAs running in the
>    same TEE and on the same device as when the data was created.
> 3. Ability to hide sensitive key material from the TA itself.
> 4. Each TA has access to its own storage space that is shared among all the
>    instances of that TA but separated from the other TAs.
> 5. The Trusted Storage must provide a minimum level of protection against
>    rollback attacks. It is accepted that the actually physical storage may be
>    in an insecure area and so is vulnerable to actions from outside of the
>    TEE. Typically, an implementation may rely on the REE for that purpose
>    (protection level 100) or on hardware assets controlled by the TEE
>    (protection level 1000).
>
> (see GP TEE Internal Core API section 2.5 and 5.2)

If configured with `CFG_RPMB_FS=y` the protection against rollback is controlled
by the TEE and is set to 1000. If `CFG_RPMB_FS=n`, there's no protection against
rollback, and the protection level is set to 0.

### TEE File Structure in Linux File System

OP-TEE by default uses `/data/tee/` as the secure storage space in the Linux
file system. Each persistent object is assigned an internal identifier. It is
an integer which is visible in the Linux file system as
`/data/tee/<file number>`.

A directory file, `/data/tee/dirf.db`, lists all the
objects that are in the secure storage. All normal world files are integrity
protected and encrypted, as described below.

## Key Manager

Key manager is an component in TEE file system, and is responsible for handling
data encryption and decryption and also management of the sensitive key
materials. There are three types of keys used by the key manager: the Secure
Storage Key (SSK), the TA Storage KEY (TSK) and the File Encryption Key (FEK).

### Secure Storage Key (SSK)

SSK is a per-device key and is generated and stored in secure memory when OP-TEE
is booting. SSK is used to derive the TA Storage Key (TSK).

SSK is derived by:
> SSK = HMAC<sub>SHA256</sub> (HUK, Chip ID || "static string")

The functions to get Hardware Unique Key (HUK) and chip ID depend on platform
implementation.

Currently, in OP-TEE OS we only have a per-device key, SSK, which is used for
secure storage subsystem, but, for the future we might need to create different
per-device keys for different subsystems using the same algorithm as we
generate the SSK; An easy way to generate different per-device keys for
different subsystems is using different static strings to generate the keys.

### Trusted Application Storage Key (TSK)

The TSK is a per-Trusted Application key, which is generated from the SSK and
the TA's identifier (UUID). It is used to protect the FEK, in other words,
to encrypt/decrypt the FEK.

TSK is derived by:
> TSK = HMAC<sub>SHA256</sub> (SSK, TA_UUID)

### File Encryption Key (FEK)

When a new TEE file is created, key manager will generate a new FEK by
PRNG (pesudo random number generator) for the TEE file and store the encrypted
FEK in meta file. FEK is used for encrypting/decrypting the TEE file information
stored in meta file or the data stored in block file.

## Hash Tree

The hash tree is responsible for handling data encryption and decryption of
a secure storage file.

The hash tree is implemented as a binary tree where
each node (`struct tee_fs_htree_node_image` below) in the tree protects its
two child nodes and a data block.

The meta data is stored in a header (`struct tee_fs_htree_image` below)
which also protects the top node.

All fields (header, nodes, and blocks) are duplicated with two versions, 0
and 1, to ensure atomic updates. See
[core/tee/fs_htree.c](../core/tee/fs_htree.c) for details.

### Meta Data Encryption Flow

![Meta Data Encryption](images/secure_storage/meta_data_encryption.png
"Meta data encryption")

A new meta IV will be generated by PRNG when a meta data needs to be updated.
The size of meta IV is defined in
[core/include/tee/fs_htree.h](../core/include/tee/fs_htree.h)

The data structures of meta data and node data are defined in
[core/include/tee/fs_htree.h](../core/include/tee/fs_htree.h) as follows:

``` c
struct tee_fs_htree_node_image {
        uint8_t hash[TEE_FS_HTREE_HASH_SIZE];
        uint8_t iv[TEE_FS_HTREE_IV_SIZE];
        uint8_t tag[TEE_FS_HTREE_TAG_SIZE];
        uint16_t flags;
};

struct tee_fs_htree_meta {
        uint64_t length;
};

struct tee_fs_htree_imeta {
        struct tee_fs_htree_meta meta;
        uint32_t max_node_id;
};

struct tee_fs_htree_image {
        uint8_t iv[TEE_FS_HTREE_IV_SIZE];
        uint8_t tag[TEE_FS_HTREE_TAG_SIZE];
        uint8_t enc_fek[TEE_FS_HTREE_FEK_SIZE];
        uint8_t imeta[sizeof(struct tee_fs_htree_imeta)];
        uint32_t counter;
};
```

### Block Data Encryption Flow

![Block Data Encryption](images/secure_storage/block_data_encryption.png
"Block data encryption")

A new block IV will be generated by PRNG when a block data needs to be updated.
The size of block IV is defined in
[core/include/tee/fs_htree.h](../core/include/tee/fs_htree.h)

## Atomic Operation

According to GlobalPlatform Trusted Storage requirement of the atomicity, the
following operations should support atomic update:
> Write, Truncate, Rename, Create and Delete

The strategy used in OP-TEE secure storage to guarantee the atomicity is
out-of-place update.

## Important caveats

Currently **no OP-TEE platform is able to support retrieval of the Hardware
Unique Key or Chip ID required for secure operation**.

For all platforms, a constant key is used, resulting in no protection against
decryption, or Secure Storage duplication to other devices.

This is because information about how to retrieve key data from the SoC is
considered sensitive by the vendors and it is not freely available.

In OP-TEE, there are APIs for reading keys generically from
One-Time-Programmable (OTP) memory. But there are no existing platform
implementations.

To allow Secure Storage to operate securely on your platform, you must define
implementations in your platform code for:

``` c
 TEE_Result tee_otp_get_hw_unique_key(struct tee_hw_unique_key *hwkey);
 int tee_otp_get_die_id(uint8_t *buffer, size_t len);
```

These implementations should fetch the key data from your SoC-specific e-fuses,
or crypto unit according to the method defined by your SoC vendor.

## Reference

* [SFO15 Secure Storage (slides)](http://connect.linaro.org/resource/sfo15/sfo15-503-secure-storage-in-op-tee/)
* [LAS16 Secure Storage (slides)](http://connect.linaro.org/resource/las16/las16-504/)
* [SFO17 Secure Storage (slides)](http://connect.linaro.org/resource/sfo17/sfo17-309/)
* [TEE Internal Core API Specification v1.1](http://www.globalplatform.org/specificationsdevice.asp)
