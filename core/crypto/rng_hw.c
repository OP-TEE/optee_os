// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2018, Linaro Limited */

#include <compiler.h>
#include <crypto/crypto.h>
#include <kernel/panic.h>
#include <rng_support.h>
#include <tee/tee_cryp_utl.h>
#include <types_ext.h>

/* This is a HW RNG, no need for seeding */
TEE_Result crypto_rng_init(const void *data __unused, size_t dlen __unused)
{
	return TEE_SUCCESS;
}

/* This is a HW RNG, no need to add entropy */
void crypto_rng_add_event(enum crypto_rng_src sid __unused,
			  unsigned int *pnum __unused,
			  const void *data __unused,
			  size_t dlen __unused)
{
}

TEE_Result crypto_rng_read(void *buf, size_t blen)
{
	if (!buf)
		return TEE_ERROR_BAD_PARAMETERS;

	return hw_get_random_bytes(buf, blen);
}
