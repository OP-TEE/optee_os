// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2021 NXP
 *
 * Scatter-gather entry management code for version 1
 */

#include <caam_common.h>
#include <caam_io.h>
#include <caam_utils_sgt.h>

#define ENTRY_LEN(len) (((uint32_t)len) & GENMASK_32(29, 0))
#define BS_ENTRY_FINAL BIT32(30)

void sgt_entry_trace(unsigned int idx __maybe_unused,
		     const struct caamsgtbuf *sgt __maybe_unused)
{
	SGT_TRACE("SGT[%d] (%p)", idx, &sgt->sgt[idx]);
	SGT_TRACE("SGT[%d]->data   = %p", idx, sgt->buf[idx].data);
	SGT_TRACE("SGT[%d]->length = %zu", idx, sgt->buf[idx].length);
	SGT_TRACE("SGT[%d]->paddr  = 0x%" PRIxPA, idx, sgt->buf[idx].paddr);
	SGT_TRACE("SGT[%d]->ptr_ms   = %" PRIx32, idx, sgt->sgt[idx].v1.ptr_ms);
	SGT_TRACE("SGT[%d]->ptr_ls   = %" PRIx32, idx, sgt->sgt[idx].v1.ptr_ls);
	SGT_TRACE("SGT[%d]->len_f_e  = %" PRIx32, idx,
		  sgt->sgt[idx].v1.len_f_e);
	SGT_TRACE("SGT[%d]->offset   = %" PRIx32, idx, sgt->sgt[idx].v1.offset);
}

void sgt_entry_offset(union caamsgt *sgt, unsigned int offset)
{
	uint32_t len_f_e = 0;

	len_f_e = caam_read_val32(&sgt->v1.len_f_e);

	/* Set the new length and keep the Final bit if set */
	len_f_e = (ENTRY_LEN(len_f_e) - offset) | (len_f_e & BS_ENTRY_FINAL);

	caam_write_val32(&sgt->v1.len_f_e, len_f_e);
	caam_write_val32(&sgt->v1.offset, offset);
}

void caam_sgt_set_entry(union caamsgt *sgt, paddr_t paddr, size_t len,
			unsigned int offset, bool final_e)
{
	unsigned int len_f_e = 0;

	caam_write_val32(&sgt->v1.ptr_ls, paddr);
#if defined(CFG_CAAM_64BIT) && defined(CFG_ARM64_core)
	caam_write_val32(&sgt->v1.ptr_ms, paddr >> 32);
#else
	caam_write_val32(&sgt->v1.ptr_ms, 0);
#endif

	len_f_e = ENTRY_LEN(len);
	if (final_e)
		len_f_e |= BS_ENTRY_FINAL;

	caam_write_val32(&sgt->v1.len_f_e, len_f_e);
	caam_write_val32(&sgt->v1.offset, offset);
}
