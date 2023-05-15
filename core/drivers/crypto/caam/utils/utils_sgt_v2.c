// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2021 NXP
 *
 * Scatter-gather entry management code for version 2
 */

#include <caam_common.h>
#include <caam_io.h>
#include <caam_utils_sgt.h>

void sgt_entry_trace(unsigned int idx __maybe_unused,
		     const struct caamsgtbuf *sgt __maybe_unused)
{
	SGT_TRACE("SGT[%d] (%p)", idx, &sgt->sgt[idx]);
	SGT_TRACE("SGT[%d]->data   = %p", idx, sgt->buf[idx].data);
	SGT_TRACE("SGT[%d]->length = %zu", idx, sgt->buf[idx].length);
	SGT_TRACE("SGT[%d]->paddr  = 0x%" PRIxPA, idx, sgt->buf[idx].paddr);
	SGT_TRACE("SGT[%d]->w1   = %" PRIx64, idx, sgt->sgt[idx].v2.w1);
	SGT_TRACE("SGT[%d]->w2   = %" PRIx64, idx, sgt->sgt[idx].v2.w2);
}

void sgt_entry_offset(union caamsgt *sgt, unsigned int offset)
{
	uint64_t w2 = 0;
	uint64_t len = 0;
	uint64_t off = 0;

	w2 = caam_read_val64(&sgt->v2.w2);

	/*
	 * Compute the new offset reading the one present and adding the
	 * input
	 */
	off = SGT_V2_ENTRY_OFFSET(w2);
	off += offset;

	/* Reading length and computing new value by subtracting the offset */
	len = SGT_V2_ENTRY_AVAIL_LENGTH(w2);
	len = (offset > len) ? 0 : len - offset;

	/* Clear the offset and length fields */
	w2 &= ~(BM_SGT_V2_OFFSET | BM_SGT_V2_AVAIL_LENGTH);

	/* Update offset and field */
	w2 |= BV_SGT_V2_OFFSET(offset) | BV_SGT_V2_AVAIL_LENGTH(len);

	caam_write_val64(&sgt->v2.w2, w2);
}

void caam_sgt_set_entry(union caamsgt *sgt, paddr_t paddr, size_t len,
			unsigned int offset, bool final_e)
{
	uint64_t w2 = 0;

	/* Write the address to set */
	caam_write_val64(&sgt->v2.w1, paddr);

	/* Compute the second word */
	w2 = (final_e ? BM_SGT_V2_F : 0) | BV_SGT_V2_OFFSET(offset) |
	     BM_SGT_V2_IVP | BV_SGT_V2_AVAIL_LENGTH(len);

	caam_write_val64(&sgt->v2.w2, w2);
}
