// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2018, Linaro Limited */

#include <compiler.h>
#include <crypto/crypto.h>
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
	return get_rng_array(buf, blen);
}

