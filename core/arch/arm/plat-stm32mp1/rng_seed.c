// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020-2022, Linaro Limited
 */

#include <drivers/stm32_rng.h>
#include <kernel/panic.h>
#include <tee/tee_cryp_utl.h>
#include <trace.h>

#define PRNG_SEED_SIZE			16

/* Override weak plat_rng_init with platform handler to seed PRNG */
void plat_rng_init(void)
{
	uint8_t seed[PRNG_SEED_SIZE] = { };

	if (stm32_rng_read(seed, sizeof(seed)))
		panic();

	if (crypto_rng_init(seed, sizeof(seed)))
		panic();

	DMSG("PRNG seeded with RNG1");
}
