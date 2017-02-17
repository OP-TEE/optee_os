# OP-TEE crypto implementation

This document describes how the TEE Cryptographic Operations API is implemented,
how the default crypto provider may be configured at compile time, and how it may
be replaced by another implementation.

## Overview

There are several layers from the Trusted Application to the actual crypto
algorithms. Most of the crypto code runs in kernel mode inside the TEE core.

Here is a schematic view of a typical call to the crypto API. The numbers in
square brackets ([1], [2]...) refer to the sections below.

        some_function()                              (Trusted App)
    [1]   TEE_*()                       User space   (libutee.a)
    ------- utee_*() -----------------------------------------------
    [2]       tee_svc_*()               Kernel space
    [3]         crypto_ops.*()                       (libtomcrypt.a)
    [4]           /* LibTomCrypt */                  (libtomcrypt.a)

## The TEE Cryptographic Operations API [1]

OP-TEE implements the TEE Internal API defined by the GlobalPlatform association
in the *TEE Internal API Specification* (GPD_SPE_010). This includes
cryptographic functions that span various cryptographic needs: message digests,
symmetric ciphers, message authentication codes (MAC), authenticated encryption,
asymmetric operations (encryption/decryption or signing/verifying), key
derivation, and random data generation. These functions make up the TEE
Cryptographic Operations API.

The Internal API is implemented in
[tee_api_operations.c](../lib/libutee/tee_api_operations.c), which is
compiled into a static library: `${O}/ta_arm{32,64}-lib/libutee/libutee.a`.

Most API functions perform some parameter checking and manipulations, then
invoke some **utee_\*** function to switch to kernel mode and perform the
low-level work.

The **utee_\*** functions are declared in
[utee_syscalls.h](../lib/libutee/include/utee_syscalls.h)
and implemented in
[utee_syscalls_asm.S](../lib/libutee/arch/arm/utee_syscalls_asm.S).
They are simple system call wrappers which use the **SVC**
instruction to switch to the appropriate system service in the OP-TEE kernel.

## The crypto services [2]

All cryptography-related system calls are declared in
[tee_svc_cryp.h](../core/include/tee/tee_svc_cryp.h) and implemented in
[tee_svc_cryp.c](../core/tee/tee_svc_cryp.c).
In addition to dealing with the usual work required at the user/kernel interface
(checking parameters and copying memory buffers between user and kernel space),
the system calls invoke a private abstraction layer: the **crypto_ops**
structure, which is declared in
[tee_cryp_provider.h](../core/include/tee/tee_cryp_provider.h).
It serves two main purposes:

1. Allow for alternative implementations, such as hardware-accelerated versions.
2. Provide an easy way to disable some families of algorithms at compile-time
   to save space. See *LibTomCrypt* below.

## struct crypto_ops [3]

The **crypto_ops** structure contains pointer to functions that implement the
actual algorithms and helper functions. The TEE Core has one global instance of
this structure. The default implementation, based on
[LibTomCrypt](https://github.com/libtom/libtomcrypt), is as follows:

```c
/* core/lib/libtomcrypt/tee_ltc_provider.c */

/*
 * static functions: tee_ltc_init(), hash_get_ctx_size(), etc.
 *     ...
 */

struct crypto_ops crypto_ops = {
	.name = "LibTomCrypt provider",
	.init = tee_ltc_init,
#if defined(_CFG_CRYPTO_WITH_HASH)
	.hash = {
		.get_ctx_size = hash_get_ctx_size,
		.init = hash_init,
		.update = hash_update,
		.final = hash_final,
	},
#endif
#if defined(_CFG_CRYPTO_WITH_CIPHER)
	.cipher = {
		.final = cipher_final,
		.get_block_size = cipher_get_block_size,
		.get_ctx_size = cipher_get_ctx_size,
		.init = cipher_init,
		.update = cipher_update,
	},
#endif
	/* ... */
}
```

As shown above, it is allowed to omit some pointers, in which case they will be
set to NULL by the compiler and not used by the system service layer.
When a Trusted Application calls **TEE_AllocateOperation()**  to request an
operation that is not available, it receives an error status
(**TEE_ERROR_NOT_IMPLEMENTED**) but it will not panic.

## Public/private key format

**crypto_ops** uses implementation-specific types to hold key data
for asymmetric algorithms. For instance, here is how a public RSA key is
represented:

```c
/* core/include/tee/tee_cryp_provider.h */

struct rsa_public_key {
	struct bignum *e;	/* Public exponent */
	struct bignum *n;	/* Modulus */
};
```

This is also how such keys are stored inside the TEE object attributes
(**TEE_ATTR_RSA_PUBLIC_KEY** in this case).

**struct bignum** is an opaque type, known to the underlying implementation
only. **struct bignum_ops** provides functions so that the system services can
manipulate data of this type. This includes allocation/deallocation, copy, and
conversion to or from the big endian binary format.


```c
/*  core/include/tee/tee_cryp_provider.h */

struct bignum_ops {
	/* ... */
	struct bignum *(*allocate)(size_t size_bits);
	TEE_Result (*bin2bn)(const uint8_t *from, size_t fromsize,
			     struct bignum *to);
	void (*bn2bin)(const struct bignum *from, uint8_t *to);
};

struct crypto_ops {
	/* ... */
	struct bignum_ops bignum;
};
```

## LibTomCrypt [4]

Some algorithms may be disabled at compile time if they are not needed, in order
to reduce the size of the OP-TEE image and reduces its memory usage. This is done
by setting the appropriate configuration variable. For example:

    $ make CFG_CRYPTO_AES=n              # disable AES only
    $ make CFG_CRYPTO_{AES,DES}=n        # disable symmetric ciphers
    $ make CFG_CRYPTO_{DSA,RSA,DH,ECC}=n # disable public key algorithms
    $ make CFG_CRYPTO=n                  # disable all algorithms

Please refer to [core/lib/libtomcrypt/sub.mk](../core/lib/libtomcrypt/sub.mk)
for the list of all supported variables.

Note that the application interface is **not** modified when algorithms are
disabled. This means, for instance, that the functions **TEE_CipherInit()**,
**TEE_CipherUpdate()** and **TEE_CipherFinal()** would remain present in
`libutee.a` even if all symmetric ciphers are disabled (they would simply
return **TEE_ERROR_NOT_IMPLEMENTED**).

## How to add a new crypto implementation

To add a new implementation, the default one in
[core/lib/libtomcrypt](../core/lib/libtomcrypt) should
be used as a reference. A proof-of-concept implementation based on OpenSSL was
developed when the `crypto_ops` abstraction layer was introduced. It is not
included in the main branch of the OP-TEE repository essentially due to
licensing concerns; however it is available in the
[poc/openssl_cryptolib](https://github.com/OP-TEE/optee_os/tree/poc/openssl_cryptolib)
branch.

Here are the main things to consider when adding a new crypto provider:

- Put all the new code in its own directory under `core/lib`.
- Avoid modifying [tee_svc_cryp.c](../core/tee/tee_svc_cryp.c). It should not be
  needed.
- Your own **struct crypto_ops crypto_ops = ...** should be defined in a file at
  the top level of your new directory.
- Although not all pointers in **crypto_ops** need to be defined, all are
  required for compliance to the GlobalPlatform specification.
- If you intend to make some algorithms optional, please try to re-use the same
  names for configuration variables as the default implementation.
