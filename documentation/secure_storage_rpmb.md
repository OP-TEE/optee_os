# RPMB Secure Storage

## Introduction

This document describes the RPMB secure storage implementation in OP-TEE,
which is enabled by setting CFG_RPMB_FS=y. Trusted Applications may use
this implementation by passing a storage ID equal to
TEE_STORAGE_PRIVATE_RPMB, or TEE_STORAGE_PRIVATE if CFG_REE_FS is disabled.
For details about RPMB, please refer to the JEDEC eMMC specification
[[1]](#JEDECeMMC).

The architecture is depicted below.

```
            NORMAL WORLD           :            SECURE WORLD
                                   :
 U        tee-supplicant           :        Trusted application
 S           (rpmb.c)              :        (secure storage API)
 E         ^          ^            :                  ^
 R         |          |            :~~~~~~~~~~~~~~~~~~|~~~~~~~~~~~~~~~~~~~~
 ~~~~~~~ ioctl ~~~~~~~|~~~~~~~~~~~~:                  v
 K         |          |            :               OP-TEE
 E         v          v            :         (tee_svc_storage.c)
 R  MMC/SD subsys.  OP-TEE driver  : (tee_rpmb_fs.c, tee_fs_key_manager.c)
 N         ^                 ^     :                  ^
 E         |                 |     :                  |
 L         v                 |     :                  |
     Controller driver       |     :                  |
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~|~~~~~~~~~~~~~~~~~~~~~~~~|~~~~~~~~~~~~~~~~~~~~
                             v                        v
                           Secure monitor / EL3 firmware
```

For information about the `ioctl()` interface to the MMC/SD subsystem in the
Linux kernel, see the Linux core MMC header file [[2]](#mmc-core-h) and the
mmc-utils repository [[3]](#mmc-utils).

## The Secure Storage API

This part is common with the REE-based filesystem. The interface between the
system calls in [core/tee/tee_svc_storage.c](../core/tee/tee_svc_storage.c) and
the RPMB filesystem is the **tee_file_operations** structure `tee_file_ops`.

## The RPMB filesystem

The FS implementation is entirely in
[core/tee/tee_rpmb_fs.c](../core/tee/tee_rpmb_fs.c).

The RPMB partition is divided in three parts:

- The first 128 bytes are reserved for partition data (struct
**rpmb_fs_partition**).
- At offset 512 is the File Allocation Table (FAT). It is an array of
struct **rpmb_fat_entry** elements, one per file. The FAT grows dynamically as
files are added to the filesystem. Among other things, each entry has the start
address for the file data, its size, and the filename.
- Starting from the end of the RPMB partition and extending downwards is the
file data area.

Space in the partition is allocated by the general-purpose allocator functions:
`tee_mm_alloc()` and `tee_mm_alloc2()`.

All file operations are atomic. This is achieved thanks to the following
properties:
- Writing one single block of data to the RPMB partition is guaranteed to be
atomic by the eMMC specification.
- The FAT block for the modified file is always updated last, after data have
been written successfully.
- Updates to file content is done in-place only if the data do not span more
than the "reliable write block count" blocks. Otherwise, or if the file needs
to be extended, a new file is created.

## Device access

There is no eMMC controller driver in OP-TEE. The device operations all have to
go through the normal world. They are handled by the `tee-supplicant` process
which further relies on the kernel's `ioctl()` interface to access the device.
`tee-supplicant` also has an emulation mode which implements a virtual RPMB
device for test purposes.

RPMB operations are the following:
- Reading device information (partition size, reliable write block count)
- Programming the security key. This key is used for authentication purposes.
Note that it is different from the Secure Storage Key (SSK) defined below, which
is used for encryption. Like the SSK however, the security key is also derived
from a hardware unique key or identifier. Currently, the function
`tee_otp_get_hw_unique_key()` is used to generate the RPMB security key.
- Reading the write counter value. The write counter is used in the HMAC
computation during read and write requests. The value is read at initialization
time, and stored in the **tee_rpmb_ctx** structure, `rpmb_ctx->wr_cnt`.
- Reading or writing blocks of data

RPMB operations are initiated on request from the FS layer. Memory buffers for
requests and responses are allocated in shared memory using
`thread_optee_rpc_alloc_payload()`.
Buffers are passed to the normal world in a `TEE_RPC_RPMB_CMD` message, thanks
to the `thread_rpc_cmd()` function. Most RPMB requests and responses use the
data frame format defined by the JEDEC eMMC specification.

HMAC authentication is implemented here also.

## Encryption

The FS encryption routines are in [core/tee/tee_fs_key_manager.c](../core/tee/tee_fs_key_manager.c).

Block encryption protects file data. The algorithm is 128-bit AES in Cipher Block Chaining
(CBC) mode with Encrypted Salt-Sector Initialization Vector (ESSIV)
[[4]](#CBC-ESSIV).

- During OP-TEE initialization, a 128-bit AES Secure Storage Key (SSK) is
derived from a Hardware Unique Key (HUK). It is kept in secure memory and never
written to disk. A Trusted Application Storage Key is derived from the SSK and
the TA UUID.
- For each file, a 128-bit encrypted File Encryption Key (FEK) is randomly
generated when the file is created, encrypted with the TSK and stored in the FAT
entry for the file.
- Each 256-byte block of data is then encrypted in CBC mode. The initialization
vector is obtained by the ESSIV algorithm, that is, by encrypting the block
number with a hash of the FEK. This allows direct access to any block in the
file, as follows:
```
    FEK = AES-Decrypt(TSK, encrypted FEK);
    k = SHA256(FEK);
    IV = AES-Encrypt(128 bits of k, block index padded to 16 bytes)
	Encrypted block = AES-CBC-Encrypt(FEK, IV, block data);
	Decrypted block = AES-CBC-Decrypt(FEK, IV, encrypted block data);
```


SSK, TSK and FEK handling is common with the REE-based secure storage, while the AES
CBC block encryption is used only for RPMB (the REE implementation uses GCM).

The FAT is not encrypted.

## REE FS

If configured with both CFG_REE_FS=y and CFG_RPMB_FS=y the REE FS will
create a special file, "dirfile.db.hash" in RPMB which hold a hash
representing the state of REE FS.

## References

- <a name="JEDECeMMC"></a>[1] _Embedded Multi-Media Card (e•MMC) Electrical Standard (5.1)_, JEDEC JESD84-B51, February 2015
- <a name="mmc-core-h"></a>[2] [linux/mmc/core.h](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/tree/include/linux/mmc/core.h), Linux kernel sources
- <a name="mmc-utils"></a>[3] The [mmc-utils](http://git.kernel.org/cgit/linux/kernel/git/cjb/mmc-utils.git) repository
- <a name="CBC-ESSIV"></a>[4] [_Cipher Block Chaining_](https://en.wikipedia.org/wiki/Disk_encryption_theory#Cipher-block_chaining_.28CBC.29),
Wikipedia
