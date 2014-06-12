/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include "mpa.h"

/*
 * Remove the #undef if you like debug print outs and assertions
 * for this file.
 */
/*#undef DEBUG_ME */
#include "mpa_debug.h"
#include "mpa_assert.h"

/*
 *  mpa_init_scratch_mem
 */
void mpa_init_scratch_mem(mpa_scratch_mem pool, int nr_vars, int max_bits)
{
	/*
	 * Check the max size of a string
	 * if we support up to 'n' bits of a big number,
	 *     that means 2^n = 2^4^(n/4) = 16^(n/4)
	 * Because of grouping of '1' (worst case), this has to be
	 * multiplied by 2
	 * Because internal computation needs twice the number of bits,
	 * multiply by 2
	 * Plus the sign
	 * Plus \0 at the end
	 * ==>  (n/4)*2+1+1 ~ n+2
	 */
	ASSERT(((max_bits + 2) <= mpa_get_str_size()),
	       "! (max_bits/4) <= mpa_get_str_size()");

	pool->nrof_vars = nr_vars;
	pool->alloc_size = mpa_StaticTempVarSizeInU32(max_bits);
	pool->bit_size = max_bits;
	mpa_memset(pool->m, 0,
		   ASIZE_TO_U32(pool->nrof_vars * pool->alloc_size) * 4);
}

/*------------------------------------------------------------
 *
 *  mpa_alloc_static_temp_var
 *
 */
mpanum mpa_alloc_static_temp_var(mpanum *var, mpa_scratch_mem pool)
{
	int idx;
	mpa_num_base *tvar;

	idx = 0;
	tvar = (void *)pool->m;
	while (tvar->alloc != 0 && idx < pool->nrof_vars) {
		tvar =
		    (void *)&pool->m[idx *
				     mpa_StaticTempVarSizeInU32(pool->
								bit_size)];
		idx++;
	}
	if ((4 < tvar->alloc) != 0) {
		DPRINT("Out of temp vars. Dumping pattern : 0x%X\n",
		       __mpa_get_alloced_pattern(pool));
		DPRINT("TOO SMALL SCRATCH MEM AREA. THIS MUST NOT HAPPEN!\n");
		return NULL;
	}
	*var = tvar;
	mpa_init_static(*var, mpa_StaticTempVarSizeInU32(pool->bit_size));
	return *var;
}

/*------------------------------------------------------------
 *
 *  mpa_free_static_temp_var
 *
 */
void mpa_free_static_temp_var(mpanum *var, mpa_scratch_mem pool)
{
	IDENTIFIER_NOT_USED(pool);

	if (*var != NULL) {
		/* mark it as free */
		(*var)->alloc = 0;
	}
}

/*------------------------------------------------------------
 *
 *  mpa_get_alloced_pattern
 *
 */
uint32_t __mpa_get_alloced_pattern(mpa_scratch_mem pool)
{
	uint32_t p;
	int idx;
	mpa_num_base *tvar;

	p = 0;
	for (idx = 0; idx < pool->nrof_vars; idx++) {
		tvar =
		    (void *)&pool->m[idx *
				     mpa_StaticTempVarSizeInU32(pool->
								bit_size)];
		if (tvar->alloc != 0)
			p ^= (1 << idx);
	}
	return p;
}
