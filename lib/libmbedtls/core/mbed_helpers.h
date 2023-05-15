/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2018, ARM Limited
 * Copyright (C) 2019, Linaro Limited
 */

#ifndef MBED_HELPERS_H
#define MBED_HELPERS_H

#include <crypto/crypto.h>
#include <mbedtls/aes.h>
#include <mbedtls/bignum.h>
#include <mbedtls/ctr_drbg.h>
#include <tee_api_types.h>

static inline int mbd_rand(void *rng_state __unused, unsigned char *output,
			size_t len)
{
	if (crypto_rng_read(output, len))
		return MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED;
	return 0;
}

static inline void mbed_copy_mbedtls_aes_context(mbedtls_aes_context *dst,
						 mbedtls_aes_context *src)
{
	*dst = *src;
#if !defined(MBEDTLS_AES_ALT)
#if defined(MBEDTLS_PADLOCK_C) && defined(MBEDTLS_PADLOCK_ALIGN16)
	/*
	 * This build configuration should not occur, but just in case error out
	 * here. It needs special handling of the rk pointer, see
	 * mbedtls_aes_setkey_enc().
	 */
#error Do not know how to copy mbedtls_aes_context::rk
#endif
	dst->rk = dst->buf;
#endif
}

TEE_Result mbed_gen_random_upto(mbedtls_mpi *n, mbedtls_mpi *max);
#endif /*MBED_HELPERS_H*/
