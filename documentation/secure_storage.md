# Secure Storage In OP-TEE

## Background

Secure Storage (SST) in OP-TEE is implemented according to what has been defined
in GloblaPlatform’s TEE Internal API specification (here called Trusted
Storage). This specification mandates that it should be possible to store
general-purpose data and key material that guarantees confidentiality and
integrity of the data stored and the atomicity of the operations that modifies
the storage (atomicity here means that either the entire operation completes
successfully or no write is done).

There are currently three secure storage implementations in OP-TEE:

- The first one relies on the normal world (REE) file system. It is described in
this document and is the default implementation. It is enabled at compile time
by CFG_REE_FS=y.
- The second one makes use of the Replay Protected Memory Block (RPMB) partition
of an eMMC device, and is enabled by setting `CFG_RPMB_FS=y`. It is described
in [secure_storage_rpmb.md](secure_storage_rpmb.md).
- The third one stores objects in a SQLite database in normal world. It is
enabled by `CFG_SQL_FS=y`. See [secure_storage_sql.md](secure_storage_sql.db).

It is possible to use the normal world filesystems and the RPMB implementations
simultaneously. For this, three OP-TEE specific storage identifiers have been
defined: TEE_STORAGE_PRIVATE_REE, TEE_STORAGE_PRIVATE_RPMB and
TEE_STORAGE_PRIVATE_SQL. Depending on the
compile-time configuration, one or several values may be used.
The value TEE_STORAGE_PRIVATE selects the REE FS when available, otherwise the
RPMB FS if available, otherwise the SQL FS (in this order).

The rest of this document describes the REE FS only.

## Overview

![Secure Storage System Architecture](images/secure_storage/secure_storage_system_architecture.png
"Secure Storage System Architecture")

### Source Files In OP-TEE OS

- **[core/tee/tee_svc_storage.c](../core/tee/tee_svc_storage.c):** TEE trusted
storage service calls
- **[core/tee/tee_ree_fs.c](../core/tee/tee_ree_fs):** TEE file system & REE
file operation interface
- **[core/tee/tee_fs_key_manager.c](../core/tee/tee_fs_key_manager.c):** Key
manager
- **[lib/libutee/](../lib/libutee/):** GlobalPlatform Internal API library

### Basic File Operation Flow

When a TA is calling the write function provided by GP Trusted Storage API to
write data to a persistent object, a corresponding syscall implemented in TEE
Trusted Storage Service will be called, which in turn will invoke a series of
TEE file operations to store the data. TEE file system will then encrypt the
data and send REE file operation commands and the encrypted
data to TEE supplicant by a series of RPC messages. TEE supplicant will receive
the messages and store the encrypted data accordingly to the Linux file
system. Reading files are handled in a similar manner.

### GlobalPlatform Trusted Storage Requirement

Below is an excerpt from the specification listing the most vital requirements:

1. The Trusted Storage may be backed by non-secure resources as long as suitable
   cryptographic protection is applied, which MUST be as strong as the means
   used to protect the TEE code and data itself
2. The Trusted Storage MUST be bound to a particular device, which means that it
   MUST be accessible or modifiable only by authorized TAs running in the same
   TEE and on the same device as when the data was created.
3. Ability to hide sensitive key material from the TA itself.
4. Each TA has access to its own storage space that is shared among all the
   instances of that TA but separated from the other TAs.
5. The Trusted Storage must provide a minimum level of protection against
   rollback attacks. It is accepted that the actually physical storage may be in
   an unsecure areas and so is vulnerable to actions from outside of the TEE.
   Typically, an implementation may rely on the REE for that purpose (protection
   level 100) or on hardware assets controlled by the TEE (protection level
   1000).

### TEE File Structure In Linux File System

![TEE File Structure](images/secure_storage/tee_file_structure.png
"TEE file structure in Linux file system")

OP-TEE by default use "/data/tee/" as the secure storage space in Linux
file system. For each TA, OP-TEE use the TA's UUID to create a standalone folder
for it under the secure storage space folder. For a persistent object belonging
to a specific TA, OP-TEE creates a TEE file is object-id under the TA folder.

All fields in the REE file are duplicated with two versions 0 and 1. The
active meta-data block is selected by the lowest bit in the
meta-counter.  The active file block is selected by corresponding bit
number instruct tee_fs_file_info.backup_version_table.

The atomicity of each operation is ensured by updating meta-counter when
everything in the secondary blocks (both meta-data and file-data blocks)
are successfully written.  The main purpose of the code is to perform block
encryption and authentication of the file data, and properly handle seeking
through the file. One file (in the sense of struct tee_file_operations)
maps to one file in the REE filesystem, and has the following structure:
```
[ 4 bytes meta-counter]
[ meta-data version 0][ meta-data version 1 ]
[ Block 0 version 0 ][ Block 0 version 1 ]
[ Block 1 version 0 ][ Block 1 version 1 ]
...
[ Block n version 0 ][ Block n version 1 ]
```

One meta-data block is built up as:
```
[ struct meta_header | struct tee_fs_get_header_size ]
```

One data block is built up as:
```
[ struct block_header | BLOCK_FILE_SIZE bytes ]
```

The reason why we store the TEE file content in many small blocks is to
accelerate the file update speed when handling a large file. The block size
(FILE_BLOCK_SIZE) and the maximum number of blocks of a TEE file
(NUM_BLOCKS_PER_FILE) are defined in
[core/tee/tee_ree_fs.c](../core/tee/tee_ree_fs.c).

For now, the default block size is 4KB and the maximum number of blocks of a
TEE file is 1024.

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

#### TA storage space isolation

OP-TEE provides different folders for different TAs in Linux file system for
storing their own TEE files, but OP-TEE cannot prevent an attacker from
directly copying a TEE file from one TA's folder to another TA's folder in
Linux file system.

The TSK offers an effective protection against this kind of attack. If an
attacker copies an TEE file from one TA's folder to another TA's folder,
this TA would not be able to obtain the plaintext of the TEE file.

### File Encryption Key (FEK)

When a new TEE file is created, key manager will generate a new FEK by
PRNG (pesudo random number generator) for the TEE file and store the encrypted
FEK in meta file. FEK is used for encrypting/decrypting the TEE file information
stored in meta file or the data stored in block file.

### Meta Data Encryption Flow

![Meta Data Encryption](images/secure_storage/meta_data_encryption.png
"Meta data encryption")

A new meta IV will be generated by PRNG when a meta data needs to be updated.
The default size of meta IV is defined in
[core/include/tee/tee_fs_key_manager.h](../core/include/tee/tee_fs_key_manager.h)

The data structure of meta data is defined in
[core/tee/tee_fs_private.h](../core/tee/tee_fs_private.h) as follows:

```
struct tee_fs_file_info {
    size_t length;
    uint32_t backup_version_table[NUM_BLOCKS_PER_FILE / 32];
};
```

### Block Data Encryption Flow

![Block Data Encryption](images/secure_storage/block_data_encryption.png
"Block data encryption")

A new block IV will be generated by PRNG when a block data needs to be updated.
The default size of block IV is defined in
[core/include/tee/tee_fs_key_manager.h](../core/include/tee/tee_fs_key_manager.h)

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

In OP-TEE, there are apis for reading the keys generically from "One-Time
Programmable" memory, or OTP.  But there are no existing platform implementations.

To allow Secure Storage to operate securely on your platform, you must:

 - enable CFG_OTP_SUPPORT on your platform

 - In your platform code, define implementations for:

```
 void tee_otp_get_hw_unique_key(struct tee_hw_unique_key *hwkey);
 int tee_otp_get_die_id(uint8_t *buffer, size_t len);
```

These implementations should fetch the key data from your SoC-specific e-fuses,
or crypto unit according to the method defined by your SoC vendor.

## Future Work

- **TEE file renaming attack detection**

OP-TEE creates a specific folder under the TA's folder for each TEE file in
Linux file system and use the filename of the TEE file as the folder's name.
If an attacker directly rename the name of a TEE file folder, the renamed
TEE file is still a valid TEE file in OP-TEE.

A solution to detect the attack is using TEE filename as AAD when calculating
the tag of meta file.

- **Rollback attack detection**

An attacker can backup each version of a TEE file directly from Linux file
system and can replace the TEE file by an old version one sooner or later.

The basic idea of detecting rollback attack is to add write counter both in
meta file and another storage which has anti-rollback capability such as eMMC
RPMB partition.

## Reference

* [Secure Storage Presentation](http://www.slideshare.net/linaroorg/sfo15503-secure-storage-in-optee)
* [TEE Internal Core API Specification v1.1](http://www.globalplatform.org/specificationsdevice.asp)
