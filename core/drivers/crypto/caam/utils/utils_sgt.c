// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2018-2019 NXP
 *
 * Brief   Scatter-Gatter Table management utilities.
 */
#include <caam_common.h>
#include <caam_io.h>
#include <caam_utils_mem.h>
#include <caam_utils_sgt.h>
#include <caam_trace.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <tee/cache.h>
#include <util.h>

#define ENTRY_LEN(len)	((len) & GENMASK_32(29, 0))
#define BS_ENTRY_EXT	BIT32(31)
#define BS_ENTRY_FINAL	BIT32(30)

void caam_sgt_cache_op(enum utee_cache_operation op, struct caamsgtbuf *insgt)
{
	unsigned int idx = 0;

	cache_operation(TEE_CACHECLEAN, (void *)insgt->sgt,
			insgt->number * sizeof(struct caamsgt));
	for (idx = 0; idx < insgt->number; idx++) {
		if (!insgt->buf[idx].nocache)
			cache_operation(op, (void *)insgt->buf[idx].data,
					insgt->buf[idx].length);
	}
}

void caam_sgt_set_entry(struct caamsgt *sgt, paddr_t paddr, size_t len,
			unsigned int offset, bool final_e, bool ext_e)
{
	unsigned int len_f_e = 0;

	caam_write_val32(&sgt->ptr_ls, paddr);
#ifdef CFG_CAAM_64BIT
	caam_write_val32(&sgt->ptr_ms, paddr >> 32);
#else
	caam_write_val32(&sgt->ptr_ms, 0);
#endif

	len_f_e = ENTRY_LEN(len);
	if (final_e)
		len_f_e |= BS_ENTRY_FINAL;
	else if (ext_e)
		len_f_e |= BS_ENTRY_EXT;

	caam_write_val32(&sgt->len_f_e, len_f_e);
	caam_write_val32(&sgt->offset, offset);
}

static void caam_sgt_fill_table(struct caambuf *buf, struct caamsgtbuf *sgt,
				int start_idx, int nb_pa)
{
	int idx = 0;

	SGT_TRACE("Create %d SGT entries", nb_pa);

	for (idx = 0; idx < nb_pa; idx++) {
		sgt->buf[idx + start_idx].data = buf[idx].data;
		sgt->buf[idx + start_idx].length = buf[idx].length;
		sgt->buf[idx + start_idx].paddr = buf[idx].paddr;
		sgt->buf[idx + start_idx].nocache = buf[idx].nocache;
		sgt->length += buf[idx].length;
		if (idx < nb_pa - 1)
			CAAM_SGT_ENTRY(&sgt->sgt[idx + start_idx],
				       sgt->buf[idx + start_idx].paddr,
				       sgt->buf[idx + start_idx].length);
		else
			CAAM_SGT_ENTRY_FINAL(&sgt->sgt[idx + start_idx],
					     sgt->buf[idx + start_idx].paddr,
					     sgt->buf[idx + start_idx].length);

		SGT_TRACE("SGT[%d]->data   = %p", idx + start_idx,
			  sgt->buf[idx + start_idx].data);
		SGT_TRACE("SGT[%d]->length = %zu", idx + start_idx,
			  sgt->buf[idx + start_idx].length);
		SGT_TRACE("SGT[%d]->paddr  = 0x%" PRIxPA, idx + start_idx,
			  sgt->buf[idx + start_idx].paddr);
		SGT_TRACE("SGT[%d]->ptr_ms   = %" PRIx32, idx + start_idx,
			  sgt->sgt[idx + start_idx].ptr_ms);
		SGT_TRACE("SGT[%d]->ptr_ls   = %" PRIx32, idx + start_idx,
			  sgt->sgt[idx + start_idx].ptr_ls);
		SGT_TRACE("SGT[%d]->len_f_e  = %" PRIx32, idx + start_idx,
			  sgt->sgt[idx + start_idx].len_f_e);
		SGT_TRACE("SGT[%d]->offset   = %" PRIx32, idx + start_idx,
			  sgt->sgt[idx + start_idx].offset);
	}
}

enum caam_status caam_sgt_build_block_data(struct caamsgtbuf *sgtbuf,
					   struct caamblock *block,
					   struct caambuf *data)
{
	enum caam_status retstatus = CAAM_FAILURE;
	int nb_pa_area = 0;
	unsigned int sgtidx = 0;
	struct caambuf *pabufs = NULL;

	/* Get the number of physical pages used by the input buffer @data */
	nb_pa_area = caam_mem_get_pa_area(data, &pabufs);
	if (nb_pa_area == -1)
		return CAAM_FAILURE;

	/*
	 * If caller provided a block buffer reference, we need a SGT object
	 * with a minimum of 2 entries. Moreover, if the data is mapped
	 * on non-contiguous physical pages, we need a SGT object with
	 * the number of physical pages + one entry for the block buffer.
	 *
	 * If caller provided a block buffer reference and data is mapped
	 * on non-contiguous physical pages, a SGT object of the
	 * number of physical page is needed.
	 *
	 * Otherwise no SGT object is needed.
	 */
	if (nb_pa_area > 1)
		sgtbuf->number = nb_pa_area;

	if (block) {
		if (nb_pa_area > 1)
			sgtbuf->number += 1;
		else
			sgtbuf->number = 2;
	}

	if (sgtbuf->number) {
		sgtbuf->sgt_type = true;
		sgtbuf->length = 0;

		SGT_TRACE("Allocate %d SGT entries", sgtbuf->number);
		retstatus = caam_sgtbuf_alloc(sgtbuf);

		if (retstatus != CAAM_NO_ERROR)
			goto exit_build_block;

		/*
		 * The first entry to create in the SGT is the
		 * block buffer if provided.
		 */
		if (block) {
			sgtbuf->buf[0].data = block->buf.data;
			sgtbuf->buf[0].length = block->filled;
			sgtbuf->buf[0].paddr = block->buf.paddr;
			sgtbuf->buf[0].nocache = block->buf.nocache;
			sgtbuf->length = sgtbuf->buf[0].length;

			CAAM_SGT_ENTRY(&sgtbuf->sgt[0], sgtbuf->buf[0].paddr,
				       sgtbuf->buf[0].length);

			sgtidx++;
		}

		/* Add the data in the SGT table */
		caam_sgt_fill_table(pabufs, sgtbuf, sgtidx, nb_pa_area);
	} else {
		/*
		 * Only the data buffer is to be used and it's not
		 * split on User Pages
		 */
		sgtbuf->sgt_type = false;
		sgtbuf->number = 1;
		sgtbuf->buf = data;
		sgtbuf->length = data->length;
	}

	retstatus = CAAM_NO_ERROR;

exit_build_block:
	if (pabufs)
		caam_free(pabufs);

	return retstatus;
}
