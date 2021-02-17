// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) Foundries Ltd. 2020 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#include <crypto/crypto.h>
#include <kernel/panic.h>
#include <kernel/tee_time.h>
#include <rng_support.h>
#include <se050.h>
#include <string.h>
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
	TEE_Result res = TEE_SUCCESS;
	TEE_Time t;

#ifndef CFG_SECURE_TIME_SOURCE_REE
	/*
	 * This isn't much of a seed. Ideally we should either get a seed from
	 * a hardware RNG or from a previously saved seed.
	 *
	 * Seeding with hardware RNG is currently up to the platform to
	 * override this function.
	 *
	 * Seeding with a saved seed will require cooperation from normal
	 * world, this is still TODO.
	 */
	res = tee_time_get_sys_time(&t);
#else
	EMSG("Warning: seeding PRNG with zeroes");
	memset(&t, 0, sizeof(t));
#endif
	/* only need to initialize the prng */
	if (!res)
		res = crypto_prng_init(&t, sizeof(t));
	if (res) {
		EMSG("Failed to initialize PRNG: %#" PRIx32, res);
		panic();
	}
}

void crypto_rng_add_event(enum crypto_rng_src sid, unsigned int *pnum,
			  const void *data, size_t dlen)
{
	/* only need to add entropy to the prng */
	crypto_prng_add_event(sid, pnum, data, dlen);
}

TEE_Result crypto_rng_read(void *buf, size_t blen)
{
	if (!buf)
		return TEE_ERROR_BAD_PARAMETERS;

	return do_rng_read(buf, blen);
}

uint8_t hw_get_random_byte(void)
{
	uint8_t data = 0;

	if (do_rng_read(&data, 1))
		return 0;

	return data;
}
