// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2021, EPAM Systems. All rights reserved. */

#include <assert.h>
#include <kernel/panic.h>
#include <kernel/spinlock.h>
#include <platform_config.h>
#include <rng_support.h>
#include <trace.h>

#include "romapi.h"

#define SCRATCH_BUF_SZ		4096

static uint8_t scratch_buf[SCRATCH_BUF_SZ] __nex_bss
					__aligned(RCAR_CACHE_LINE_SZ);
static unsigned int spin_lock __nex_data = SPINLOCK_UNLOCK;

/*
 * It is inefficient to call ROM_GetRndVector() every time we want 8 bits of
 * random data, so we will cache the unused values for latter use.
 */
static uint8_t rng_cache[PLAT_RND_VECTOR_SZ] __nex_bss
					__aligned(RCAR_CACHE_LINE_SZ);
static uint8_t rng_cache_pos __nex_data = PLAT_RND_VECTOR_SZ;

uint8_t hw_get_random_byte(void)
{
	uint32_t exceptions = cpu_spin_lock_xsave(&spin_lock);
	uint8_t ret_val = 0;

	assert(rng_cache_pos <= PLAT_RND_VECTOR_SZ);

	if (rng_cache_pos == PLAT_RND_VECTOR_SZ) {
		uint32_t ret = plat_rom_getrndvector(rng_cache, scratch_buf,
						     sizeof(scratch_buf));

		if (ret != 0)
			panic("ROM_GetRndVector() returned error!");

		rng_cache_pos = 0;
	}

	ret_val = rng_cache[rng_cache_pos++];
	cpu_spin_unlock_xrestore(&spin_lock, exceptions);

	return ret_val;
}
