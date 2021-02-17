/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2021, Foundries.io Ltd
 */

#ifndef TEE_RANDOM_H
#define TEE_RANDOM_H

#include "tee_api_types.h"

#ifdef CFG_PRNG_SOURCE_RANDOM_REE
TEE_Result tee_random_add_ree_random(enum crypto_rng_src sid,
				     unsigned int *pnum);
#else
static inline TEE_Result
tee_random_add_ree_random(enum crypto_rng_src sid __unused,
			  unsigned int *pnum __unused)
{
	return TEE_SUCCESS;
}
#endif
#endif /* TEE_RANDOM_H */
