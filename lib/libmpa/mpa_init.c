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
 *  mpa_init_static
 */
void mpa_init_static(mpanum src, uint32_t len)
{
	src->alloc = U32_TO_ASIZE(len - MPA_NUMBASE_METADATA_SIZE_IN_U32);
	src->size = 0;
	if (src->alloc > 0)
		src->d[0] = 0;
}

/*------------------------------------------------------------
 *
 *  mpa_InitStaticFMMContext
 *
 */
void mpa_init_static_fmm_context(mpa_fmm_context_base *context, uint32_t len)
{
	mpa_asize_t m_alloc;

	m_alloc =
	    U32_TO_ASIZE((mpa_asize_t) len -
			 (mpa_asize_t) MPA_FMM_CONTEXT_METADATA_SIZE_IN_U32);
	/* clear the array before halfing into r and r2 */
	mpa_memset(context->m, 0, m_alloc * BYTES_PER_WORD);
	m_alloc /= 2;

	/* setup context content */
	context->n_inv = 0;

	context->r_ptr = (void *)context->m;
	context->r_ptr->alloc =
	    m_alloc - U32_TO_ASIZE(MPA_NUMBASE_METADATA_SIZE_IN_U32);
	context->r_ptr->size = 0;

	context->r2_ptr = (void *)(context->m + m_alloc);
	context->r2_ptr->alloc =
	    m_alloc - U32_TO_ASIZE(MPA_NUMBASE_METADATA_SIZE_IN_U32);
	context->r2_ptr->size = 0;
}
