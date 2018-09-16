# General Extensions to the GlobalPlatform TEE Internal Core API

This document describes the OP-TEE extensions introduced with respect to the
GlobalPlatform TEE Internal Core API Specifications v1.1.

Specific extensions documentation are part of:
* Cryptographic Extensions
  * [Concatenation Key Derivation](crypto_concat_kdf.md)
  * [HMAC Key Derivation](crypto_hkdf.md)
  * [Public-Key Key Derivation](crypto_pbkdf2.md)
  * [PKCS#1 v1.5 RSA sign/verify without the hash OID](crypto_rsassa_pkcs1_v1_5.md)


# Cache Maintenance Support
Following functions have been introduced in order to operate with cache:

    TEE_Result TEE_CacheClean(char *buf, size_t len);
    TEE_Result TEE_CacheFlush(char *buf, size_t len);
    TEE_Result TEE_CacheInvalidate(char *buf, size_t len);

These functions are available to any Trusted Application defined with the flag TA_FLAG_CACHE_MAINTENANCE sets on. When not set, each function returns the error code TEE_ERROR_NOT_SUPPORTED.

Within these extensions, a Trusted Application is able to operate on the data cache, with the following specification:

Function              | Description
:---------------------|:----------
TEE_CacheClean()      | Write back to memory any dirty data cache lines. The line is marked as not dirty. The valid bit is unchanged
TEE_CacheFlush()      | Purges any valid data cache lines. Any dirty cache lines                 are first written back to memory, then the cache line is invalidated.
TEE_CacheInvalidate() | Invalidate any valid data cache lines. Any dirty line are not written back to memory.

In the following 2 cases, the error code TEE_ERROR_ACCESS_DENIED is returned:
* the memory range has not the write access, that is TEE_MEMORY_ACCESS_WRITE is not set.
* the memory is not a User Space memory
