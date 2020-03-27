// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2018-2021 NXP
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
#include <string.h>
#include <tee/cache.h>
#include <util.h>

#define ENTRY_LEN(len)	((len) & GENMASK_32(29, 0))
#define BS_ENTRY_EXT	BIT32(31)
#define BS_ENTRY_FINAL	BIT32(30)

/*
 * Trace the SGT entry @idx of the SGT list
 *
 * @idx  Entry in the SGT list
 * @sgt  SGT list
 */
static inline void sgt_entry_trace(int idx __maybe_unused,
				   struct caamsgtbuf *sgt __maybe_unused)
{
	SGT_TRACE("SGT[%d]->data   = %p", idx, sgt->buf[idx].data);
	SGT_TRACE("SGT[%d]->length = %zu", idx, sgt->buf[idx].length);
	SGT_TRACE("SGT[%d]->paddr  = 0x%" PRIxPA, idx, sgt->buf[idx].paddr);
	SGT_TRACE("SGT[%d]->ptr_ms   = %" PRIx32, idx, sgt->sgt[idx].ptr_ms);
	SGT_TRACE("SGT[%d]->ptr_ls   = %" PRIx32, idx, sgt->sgt[idx].ptr_ls);
	SGT_TRACE("SGT[%d]->len_f_e  = %" PRIx32, idx, sgt->sgt[idx].len_f_e);
	SGT_TRACE("SGT[%d]->offset   = %" PRIx32, idx, sgt->sgt[idx].offset);
}

/*
 * Add an @offset to the SGT entry
 *
 * @sgt     [in/out] Sgt entry
 * @offset  Offset to add
 */
static void sgt_entry_offset(struct caamsgt *sgt, unsigned int offset)
{
	unsigned int len_f_e = 0;

	len_f_e = caam_read_val32(&sgt->len_f_e);

	/* Set the new length and keep the Final bit if set */
	len_f_e = (ENTRY_LEN(len_f_e) - offset) | (len_f_e & BS_ENTRY_FINAL);

	caam_write_val32(&sgt->len_f_e, len_f_e);
	caam_write_val32(&sgt->offset, offset);
}

void caam_sgt_cache_op(enum utee_cache_operation op, struct caamsgtbuf *insgt,
		       size_t length)
{
	unsigned int idx = 0;
	size_t op_size = 0;
	size_t rem_length = length;

	cache_operation(TEE_CACHECLEAN, (void *)insgt->sgt,
			insgt->number * sizeof(struct caamsgt));

	SGT_TRACE("SGT @%p %d entries", insgt, insgt->number);
	for (idx = 0; idx < insgt->number && rem_length; idx++) {
		if (insgt->sgt[idx].len_f_e & BS_ENTRY_EXT) {
			SGT_TRACE("SGT EXT @%p", insgt->buf[idx].data);
			caam_sgt_cache_op(op, (void *)insgt->buf[idx].data,
					  rem_length);

			/*
			 * Extension entry is the last entry of the
			 * current SGT, even if there are entries
			 * after, they are not used.
			 */
			break;
		}

		op_size = MIN(rem_length, insgt->buf[idx].length);
		if (!insgt->buf[idx].nocache)
			cache_operation(op, (void *)insgt->buf[idx].data,
					op_size);
		rem_length -= op_size;
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

void caam_sgt_fill_table(struct caamsgtbuf *sgt)
{
	unsigned int idx = 0;

	SGT_TRACE("Create %d SGT entries", sgt->number);

	for (; idx < sgt->number - 1; idx++) {
		CAAM_SGT_ENTRY(&sgt->sgt[idx], sgt->buf[idx].paddr,
			       sgt->buf[idx].length);
		sgt_entry_trace(idx, sgt);
	}

	CAAM_SGT_ENTRY_FINAL(&sgt->sgt[idx], sgt->buf[idx].paddr,
			     sgt->buf[idx].length);
	sgt_entry_trace(idx, sgt);
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

enum caam_status caam_sgt_derive(struct caamsgtbuf *sgt,
				 const struct caamsgtbuf *from, size_t offset,
				 size_t length)
{
	enum caam_status retstatus = CAAM_FAILURE;
	unsigned int idx = 0;
	unsigned int st_idx = 0;
	size_t off = offset;
	size_t rlength = length;

	SGT_TRACE("Derive from %p - offset %zu, %d SGT entries", from, offset,
		  from->number);

	if (from->length - offset < length) {
		SGT_TRACE("From SGT/Buffer too short (%zu)", from->length);
		return CAAM_SHORT_BUFFER;
	}

	for (; idx < from->number && off >= from->buf[idx].length; idx++)
		off -= from->buf[idx].length;

	st_idx = idx;
	sgt->number = 1;
	rlength -= MIN(rlength, from->buf[idx].length - off);

	for (idx++; idx < from->number && rlength; idx++) {
		rlength -= MIN(rlength, from->buf[idx].length);
		sgt->number++;
	}

	sgt->sgt_type = (sgt->number > 1) ? true : false;

	/* Allocate a new SGT/Buffer object */
	retstatus = caam_sgtbuf_alloc(sgt);
	SGT_TRACE("Allocate %d SGT entries ret 0x%" PRIx32, sgt->number,
		  retstatus);
	if (retstatus != CAAM_NO_ERROR)
		return retstatus;

	memcpy(sgt->buf, &from->buf[st_idx], sgt->number * sizeof(*sgt->buf));

	if (sgt->sgt_type) {
		memcpy(sgt->sgt, &from->sgt[st_idx],
		       sgt->number * sizeof(*sgt->sgt));

		/* Set the offset of the first sgt entry */
		sgt_entry_offset(sgt->sgt, off);

		/*
		 * Push the SGT Table into memory now because
		 * derived objects are not pushed.
		 */
		cache_operation(TEE_CACHECLEAN, sgt->sgt,
				sgt->number * sizeof(*sgt->sgt));

		sgt->paddr = virt_to_phys(sgt->sgt);
	} else {
		sgt->paddr = sgt->buf->paddr + off;
	}

	sgt->length = length;

	return CAAM_NO_ERROR;
}

void caam_sgtbuf_free(struct caamsgtbuf *data)
{
	if (data->sgt_type)
		caam_free(data->sgt);
	else
		caam_free(data->buf);

	data->sgt = NULL;
	data->buf = NULL;
}

enum caam_status caam_sgtbuf_alloc(struct caamsgtbuf *data)
{
	if (!data || !data->number)
		return CAAM_BAD_PARAM;

	if (data->sgt_type) {
		data->sgt =
			caam_calloc(data->number * (sizeof(struct caamsgt) +
						    sizeof(struct caambuf)));
		data->buf = (void *)(((uint8_t *)data->sgt) +
				     (data->number * sizeof(struct caamsgt)));
	} else {
		data->buf = caam_calloc(data->number * sizeof(struct caambuf));
		data->sgt = NULL;
	}

	if (!data->buf || (!data->sgt && data->sgt_type)) {
		caam_sgtbuf_free(data);
		return CAAM_OUT_MEMORY;
	}

	return CAAM_NO_ERROR;
}
