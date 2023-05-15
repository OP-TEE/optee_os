// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) Foundries Ltd. 2020 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#include <crypto/crypto.h>
#include <rng_support.h>
#include <se050.h>
#include <tee/tee_cryp_utl.h>

static TEE_Result do_rng_read(void *buf, size_t blen)
{
	sss_status_t status = kStatus_SSS_Success;
	sss_se05x_rng_context_t rng = { };

	sss_se05x_rng_context_init(&rng, se050_session);
	status = sss_se05x_rng_get_random(&rng, buf, blen);
	sss_se05x_rng_context_free(&rng);

	if (status != kStatus_SSS_Success)
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

void plat_rng_init(void)
{
}

TEE_Result hw_get_random_bytes(void *buf, size_t blen)
{
	if (!buf)
		return TEE_ERROR_BAD_PARAMETERS;

	return do_rng_read(buf, blen);
}
