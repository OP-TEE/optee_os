// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
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
