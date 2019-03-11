/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014-2019, Linaro Limited
 */

#include <crypto/crypto.h>
#include <tee_api_defines.h>
#include <types_ext.h>

static inline bool bn_alloc_max(struct bignum **s)
{
	*s = crypto_bignum_allocate(CFG_CORE_BIGNUM_MAX_BITS);

	return *s;
}

static inline TEE_Result convert_ltc_verify_status(int ltc_res, int ltc_stat)
{
	switch (ltc_res) {
	case CRYPT_OK:
		if (ltc_stat == 1)
			return TEE_SUCCESS;
		else
			return TEE_ERROR_SIGNATURE_INVALID;
	case CRYPT_INVALID_PACKET:
		return TEE_ERROR_SIGNATURE_INVALID;
	default:
		return TEE_ERROR_GENERIC;
	}
}
