// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021 Huawei Technologies Co., Ltd
 */

#include <compiler.h>
#include <crypto/crypto.h>
#include <mbedtls/bignum.h>
#include <stddef.h>
#include <tee_api_defines.h>
#include <tee_api_types.h>

#include "mbed_helpers.h"

/* Generate random number 1 <= n < max */
TEE_Result mbed_gen_random_upto(mbedtls_mpi *n, mbedtls_mpi *max)
{
	size_t sz = mbedtls_mpi_size(max);
	bool found = false;
	int mres = 0;

	do {
		mres = mbedtls_mpi_fill_random(n, sz, mbd_rand, NULL);
		if (mres)
			return TEE_ERROR_BAD_STATE;
		if (mbedtls_mpi_bitlen(n) != 0 &&
		    mbedtls_mpi_cmp_mpi(n, max) == -1)
			found = true;
	} while (!found);

	return TEE_SUCCESS;
}

