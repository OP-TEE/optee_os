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

#include <string.h>
#include <user_ta_header.h>
#include <kernel/tee_ta_manager_unpg.h>
#include <tee/tee_hash.h>
#include <kernel/tee_core_trace.h>

struct tee_ta_ctx_head tee_ctxes = TAILQ_HEAD_INITIALIZER(tee_ctxes);

/*-----------------------------------------------------------------------------
 * Find ta session for a va_addr
 * Executed in abort mode
 *---------------------------------------------------------------------------*/
static struct tee_ta_ctx *tee_ta_find_context(const uint32_t va_addr)
{
	struct tee_ta_ctx *ctx;
	uintptr_t smem;		/* start memory address for session */
	uintptr_t emem;		/* end memory address for session */

	TAILQ_FOREACH(ctx, &tee_ctxes, link) {
		smem = tee_mm_get_smem(ctx->mm);
		emem = smem + ctx->smem_size;

		/*
		 * If the address is in the range of virtual memory for this
		 * session we have found it.
		 */
		if (va_addr >= smem && va_addr <= emem)
			break;
	}
	return ctx;
}

/*-----------------------------------------------------------------------------
 * Load and verify a page at va_addr
 * Executed in abort mode
 *---------------------------------------------------------------------------*/
void *tee_ta_load_page(const uint32_t va_addr)
{
	struct tee_ta_ctx *ts = tee_ta_find_context(va_addr);
	uint32_t smem;      /* start memory address for session */
	uint32_t spage;     /* start of page to load */
	uint32_t npage;     /* normal world page data to copy */
	uint32_t page_idx;  /* page index relative to start of this session */
	uint32_t page_bit;  /* bit number page_idx set for rw data */
	void *hash_offset;  /* hash of page data */
	uint32_t cpy_size = SMALL_PAGE_SIZE;
	size_t hash_size;
	uint32_t remain_data;

	/* Address has a session ? */
	TEE_ASSERT(ts != NULL);

	spage = va_addr & 0xFFFFF000;
	smem = tee_mm_get_smem(ts->mm);
	npage = (uint32_t) (ts->nmem) + spage - smem;
	page_idx = ((spage - smem) >> SMALL_PAGE_SHIFT);
	page_bit = 1 << page_idx;
	if (tee_hash_get_digest_size(ts->head->hash_type, &hash_size) !=
	    TEE_SUCCESS) {
		EMSG("invalid hash type 0x%x",
		     (unsigned int)ts->head->hash_type);
		TEE_ASSERT(0);
	}

	remain_data = smem + ts->smem_size - spage;
	/*
	 * Check that there's more than just ZI in this page as we don't have
	 * any hash for a pure ZI page.
	 */
	if (remain_data > ts->head->zi_size) {
		if (remain_data - ts->head->zi_size < cpy_size) {
			cpy_size =
			    smem + ts->smem_size - ts->head->zi_size - spage;
		}

		/* copy memory */
		memcpy((void *)spage, (void *)npage, cpy_size);

		hash_offset =
		    (void *)(sizeof(ta_head_t) +
			     ts->head->nbr_func * sizeof(ta_func_head_t) +
			     hash_size * page_idx + (uint32_t) (ts->head));

		/* check hash */
		if (tee_hash_check(
			ts->head->hash_type,
			hash_offset, hash_size,
			(void *)spage, cpy_size) != TEE_SUCCESS) {
				/* Hash did not match. */
			EMSG("PH 0x%x failed", (unsigned int)spage);
			TEE_ASSERT(0);
		}
	}

	/* restore/update rw data */
	if (ts->head->ro_size < spage - smem + SMALL_PAGE_SIZE &&
	    (ts->rw_data_usage & page_bit) != 0) {
		uint32_t hi = MIN(ts->head->rw_size +
				  ts->head->zi_size + ts->head->ro_size,
				  spage - smem + SMALL_PAGE_SIZE);

		uint32_t lo = MAX(ts->head->ro_size,
				  (spage - smem));

		memcpy((void *)(smem + lo),
		       (void *)(ts->rw_data + (lo - ts->head->ro_size)),
		       hi - lo);
	}

	return (void *)ts;
}

/*-----------------------------------------------------------------------------
 * Checks if a page at va_addr contains rw data which should be saved
 * Returns 1 if the page contains data, 0 otherwise
 *
 * Executed in abort mode
 *---------------------------------------------------------------------------*/
uint32_t tee_ta_check_rw(const uint32_t va_addr, const void *ctx_handle)
{
	struct tee_ta_ctx *ctx;
	uint32_t smem;		/* start memroy address for session */
	uint32_t spage;		/* start address for page */

	/* check if session is still valid */
	TAILQ_FOREACH(ctx, &tee_ctxes, link) {
		if (ctx == ctx_handle)
			break;
	}
	if (ctx != ctx_handle) {
		/* session has been removed */
		/* XXX can this ever happen?? /EJENWIK 111219 */
		return 0;
	}

	smem = tee_mm_get_smem(ctx->mm);
	spage = va_addr & 0xFFFFF000;

	if (va_addr < smem || va_addr >= smem + ctx->smem_size) {
		/* Out of bounds nothing to remove */
		return 0;
	}

	/* check if we have ro data */
	if (ctx->head->ro_size < spage - smem + SMALL_PAGE_SIZE)
		return 1;

	return 0;
}

/*-----------------------------------------------------------------------------
 * Saves rw data in a page at va_addr
 * NOTE: No parameter checking! It is assumed that tee_ta_check_rw is called
 * prior this function
 *
 * Executed in abort mode
 *---------------------------------------------------------------------------*/
void tee_ta_save_rw(const uint32_t va_addr, const void *ctx_handle)
{
	struct tee_ta_ctx *ctx = (struct tee_ta_ctx *)ctx_handle;
	uint32_t smem;       /* start memory address for session */
	uint32_t spage;      /* start of page to save rw data from */
	uint32_t page_idx;   /* page index relative to start of this session */
	uint32_t page_bit;   /* bit number page_idx */
	uint32_t lo;         /* start offset (from smem) for rw data to save */
	uint32_t hi;         /* end offset (from smem) for rw data to save */

	smem = tee_mm_get_smem(ctx->mm);
	spage = va_addr & 0xFFFFF000;
	page_idx = ((spage - smem) >> SMALL_PAGE_SHIFT);
	page_bit = 1 << page_idx;

	lo = MAX(ctx->head->ro_size, (spage - smem));

	hi = MIN(ctx->head->rw_size + ctx->head->zi_size + ctx->head->ro_size,
		 (spage - smem + SMALL_PAGE_SIZE));

	memcpy((void *)(ctx->rw_data + lo - ctx->head->ro_size),
	       (void *)(smem + lo), hi - lo);

	/* update page usage */
	ctx->rw_data_usage |= page_bit;
}
