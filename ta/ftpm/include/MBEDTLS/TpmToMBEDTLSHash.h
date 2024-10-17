/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2024, Linaro Limited
 */

#ifndef __TPMTOMBEDTLSHASH_H
#define __TPMTOMBEDTLSHASH_H

#define HASH_ALIGNMENT RADIX_BYTES

#include <stdint.h>
#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>

/*
 * Define the internal name used for each of the hash state structures to
 * the name used by the library.
 * These defines need to be known in all parts of the TPM so that the
 * structure sizes can be properly computed when needed.
 */

#define tpmHashStateSHA1_t mbedtls_sha1_context
#define tpmHashStateSHA256_t mbedtls_sha256_context
#define tpmHashStateSHA384_t mbedtls_sha512_context
#define tpmHashStateSHA512_t mbedtls_sha512_context

/*
 * The defines below are only needed when compiling CryptHash.c or
 * CryptSmac.c.
 */
#ifdef _CRYPT_HASH_C_

/*
 * TPMCmd/tpm/src//crypt/CryptHash.c needs this to be defined here.
 */
typedef BYTE *PBYTE;

#define HASH_START_METHOD_DEF void(HASH_START_METHOD)(PANY_HASH_STATE state)
#define HASH_START(_hs) ((_hs)->def->method.start)(&(_hs)->state);

#define HASH_DATA_METHOD_DEF						  \
	void(HASH_DATA_METHOD)(PANY_HASH_STATE state, const BYTE *buffer, \
			       size_t size)
#define HASH_DATA(_hs, dInSize, dIn)					  \
	((_hs)->def->method.data)(&(_hs)->state, dIn, dInSize)

#define HASH_END_METHOD_DEF						  \
	void(HASH_END_METHOD)(PANY_HASH_STATE state, BYTE * buffer)
#define HASH_END(_hs, buffer) ((_hs)->def->method.end)(&(_hs)->state, buffer)

#define HASH_STATE_COPY_METHOD_DEF					  \
	void(HASH_STATE_COPY_METHOD)(PANY_HASH_STATE to,		  \
				     PCANY_HASH_STATE from, size_t size)
#define HASH_STATE_COPY(hs_out, hs_in)					  \
	((hs_in)->def->method.copy)(&(hs_out)->state, &(hs_in)->state,	  \
				  (hs_in)->def->contextSize)

#define HASH_STATE_EXPORT_METHOD_DEF					  \
	void(HASH_STATE_EXPORT_METHOD)(BYTE * to, PCANY_HASH_STATE from,  \
				       size_t size)
#define HASH_STATE_EXPORT(to, _hs)					  \
	((_hs)->def->method.copyOut)(					  \
		&(((BYTE *)(to))[offsetof(HASH_STATE, state)]),		  \
		&(_hs)->state, (_hs)->def->contextSize)

#define HASH_STATE_IMPORT_METHOD_DEF					  \
	void(HASH_STATE_IMPORT_METHOD)(PANY_HASH_STATE to, const BYTE *from, \
				       size_t size)
#define HASH_STATE_IMPORT(_hs, from)					  \
	((_hs)->def->method.copyIn)(					  \
		&(_hs)->state,						  \
		&(((const BYTE *)(from))[offsetof(HASH_STATE, state)]),	  \
		(_hs)->def->contextSize)

static inline int tpmHashStart_SHA1(mbedtls_sha1_context *ctx)
{
	mbedtls_sha1_init(ctx);
	return mbedtls_sha1_starts(ctx);
}
#define tpmHashData_SHA1 mbedtls_sha1_update
static inline int tpmHashEnd_SHA1(mbedtls_sha1_context *ctx, BYTE *buffer)
{
	int e = mbedtls_sha1_finish(ctx, buffer);

	mbedtls_sha1_free(ctx);
	return e;
}
#define tpmHashStateCopy_SHA1 memcpy
#define tpmHashStateExport_SHA1 memcpy
#define tpmHashStateImport_SHA1 memcpy

static inline int tpmHashStart_SHA256(mbedtls_sha256_context *ctx)
{
	mbedtls_sha256_init(ctx);
	return mbedtls_sha256_starts(ctx, 0);
}
#define tpmHashData_SHA256 mbedtls_sha256_update
static inline int tpmHashEnd_SHA256(mbedtls_sha256_context *ctx, BYTE *buffer)
{
	int e = mbedtls_sha256_finish(ctx, buffer);
	mbedtls_sha256_free(ctx);
	return e;
}
#define tpmHashStateCopy_SHA256 memcpy
#define tpmHashStateExport_SHA256 memcpy
#define tpmHashStateImport_SHA256 memcpy

/* SHA-384 is implemented using SHA-512, only initialized differently. */
static inline int tpmHashStart_SHA384(mbedtls_sha512_context *ctx)
{
	mbedtls_sha512_init(ctx);
	return mbedtls_sha512_starts(ctx, 1);
}
#define tpmHashData_SHA384 mbedtls_sha512_update
#define tpmHashEnd_SHA384 tpmHashEnd_SHA512
#define tpmHashStateCopy_SHA384 tpmHashStateCopy_SHA512
#define tpmHashStateExport_SHA384 tpmHashStateExport_SHA512
#define tpmHashStateImport_SHA384 tpmHashStateImport_SHA512

static inline int tpmHashStart_SHA512(mbedtls_sha512_context *ctx)
{
	mbedtls_sha512_init(ctx);
	return mbedtls_sha512_starts(ctx, 0);
}
#define tpmHashData_SHA512 mbedtls_sha512_update
static inline int tpmHashEnd_SHA512(mbedtls_sha512_context *ctx, BYTE *buffer)
{
	int e = mbedtls_sha512_finish(ctx, buffer);
	mbedtls_sha512_free(ctx);
	return e;
}
#define tpmHashStateCopy_SHA512 memcpy
#define tpmHashStateExport_SHA512 memcpy
#define tpmHashStateImport_SHA512 memcpy

#endif /*_CRYPT_HASH_C_*/

#define LibHashInit()
#define HashLibSimulationEnd()

#endif /*__TPMTOMBEDTLSHASH_H*/
