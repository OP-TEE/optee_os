// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2018, Linaro Limited */

#include <compiler.h>
#include <crypto/crypto.h>
#include <rng_support.h>
#include <tee/tee_cryp_utl.h>
#include <types_ext.h>

TEE_Result __weak crypto_rng_init(const void *data __unused,
				  size_t dlen __unused)
{
	return TEE_SUCCESS;
}

void __weak crypto_rng_add_event(enum crypto_rng_src sid __unused,
				 unsigned int *pnum __unused,
				 const void *data __unused,
				 size_t dlen __unused)
{
}

TEE_Result __weak crypto_rng_read(void *buf, size_t blen)
{
	uint8_t *b = buf;
	size_t n;

	if (!b)
		return TEE_ERROR_BAD_PARAMETERS;

	for (n = 0; n < blen; n++)
		b[n] = hw_get_random_byte();

	return TEE_SUCCESS;
}

