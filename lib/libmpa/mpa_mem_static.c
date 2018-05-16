// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */
#include "mpa.h"
#include <util.h>
#include <trace.h>

mpanum mpa_alloc_static_temp_var_size(int size_bits, mpanum *var,
				      mpa_scratch_mem pool)
{
	*var = mempool_alloc(pool->pool, mpa_StaticVarSizeInU32(size_bits) *
					 sizeof(uint32_t));
	if (*var)
		mpa_init_static(*var, mpa_StaticVarSizeInU32(size_bits));

	return *var;
}

mpanum mpa_alloc_static_temp_var(mpanum *var, mpa_scratch_mem pool)
{
	return mpa_alloc_static_temp_var_size(pool->bn_bits, var, pool);
}

/*------------------------------------------------------------
 *
 *  mpa_free_static_temp_var
 *
 */
void mpa_free_static_temp_var(mpanum *var, mpa_scratch_mem pool)
{
	if (!var || !(*var))
		return;

	mempool_free(pool->pool, *var);
}

