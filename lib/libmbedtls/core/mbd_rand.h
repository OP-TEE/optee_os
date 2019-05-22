/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2018, ARM Limited
 * Copyright (C) 2019, Linaro Limited
 */

#ifndef __MBD_RAND_H
#define __MBD_RAND_H

#include <crypto/crypto.h>
#include <mbedtls/ctr_drbg.h>

static inline int mbd_rand(void *rng_state __unused, unsigned char *output,
			size_t len)
{
	if (crypto_rng_read(output, len))
		return MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED;
	return 0;
}

#endif /*__MBD_RAND_H*/
