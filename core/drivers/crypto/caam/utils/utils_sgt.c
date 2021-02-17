// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2018-2019, 2021 NXP
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

void caam_sgt_cache_op(enum utee_cache_operation op, struct caamsgtbuf *insgt,
		       size_t length)
{
	unsigned int idx = 0;
	size_t op_size = 0;
	size_t rem_length = length;

	cache_operation(TEE_CACHECLEAN, (void *)insgt->sgt,
			ROUNDUP(insgt->number, CFG_CAAM_SGT_ALIGN) *
				sizeof(union caamsgt));

	SGT_TRACE("SGT @%p %d entries", insgt, insgt->number);
	for (idx = 0; idx < insgt->number && rem_length; idx++) {
		op_size = MIN(rem_length, insgt->buf[idx].length);
		if (!insgt->buf[idx].nocache)
			cache_operation(op, (void *)insgt->buf[idx].data,
					op_size);
		rem_length -= op_size;
	}
}

void caam_sgt_fill_table(struct caamsgtbuf *sgt)
{
	unsigned int idx = 0;

	SGT_TRACE("Create %d SGT entries", sgt->number);

	for (idx = 0; idx < sgt->number - 1; idx++) {
		CAAM_SGT_ENTRY(&sgt->sgt[idx], sgt->buf[idx].paddr,
			       sgt->buf[idx].length);
		sgt_entry_trace(idx, sgt);
	}

	CAAM_SGT_ENTRY_FINAL(&sgt->sgt[idx], sgt->buf[idx].paddr,
			     sgt->buf[idx].length);
	sgt_entry_trace(idx, sgt);
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
	unsigned int nb_sgt = 0;

	if (!data || !data->number)
		return CAAM_BAD_PARAM;

	if (data->sgt_type) {
		nb_sgt = ROUNDUP(data->number, CFG_CAAM_SGT_ALIGN);
		data->sgt = caam_calloc(nb_sgt * (sizeof(union caamsgt) +
						  sizeof(struct caambuf)));
		data->buf = (void *)(((uint8_t *)data->sgt) +
				     (nb_sgt * sizeof(union caamsgt)));
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
