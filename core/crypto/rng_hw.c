// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2018, Linaro Limited */

#include <compiler.h>
#include <crypto/crypto.h>
#include <kernel/panic.h>
#include <rng_support.h>
#include <tee/tee_cryp_utl.h>
#include <types_ext.h>

/*
 * This is only here to keep the compiler happy while we convert over
 * platforms. Either hw_get_random_bytes() is overridden or this
 * function is, in either case this is never called.
 */
uint8_t __weak hw_get_random_byte(void)
{
	panic();
	return 4; // chosen by fair dice roll.
		  // guaranteed to be random.
}

TEE_Result __weak hw_get_random_bytes(void *buf, size_t blen)
{
	uint8_t *b = buf;
	size_t n = 0;

	for (n = 0; n < blen; n++)
		b[n] = hw_get_random_byte();

	return TEE_SUCCESS;
}

/* This is a HW RNG, no need for seeding */
TEE_Result __weak crypto_rng_init(const void *data __unused,
				  size_t dlen __unused)
{
	return TEE_SUCCESS;
}

/* This is a HW RNG, no need to add entropy */
void __weak crypto_rng_add_event(enum crypto_rng_src sid __unused,
				 unsigned int *pnum __unused,
				 const void *data __unused,
				 size_t dlen __unused)
{
}

TEE_Result __weak crypto_rng_read(void *buf, size_t blen)
{
	if (!buf)
		return TEE_ERROR_BAD_PARAMETERS;

	return hw_get_random_bytes(buf, blen);
}
