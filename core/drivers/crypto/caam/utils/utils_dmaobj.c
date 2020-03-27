// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2020-2021 NXP
 *
 * CAAM DMA data object utilities.
 */

#include <caam_trace.h>
#include <caam_utils_dmaobj.h>
#include <caam_utils_mem.h>
#include <caam_utils_sgt.h>
#include <caam_utils_status.h>
#include <kernel/cache_helpers.h>
#include <kernel/spinlock.h>
#include <mm/core_memprot.h>
#include <string.h>
#include <tee/cache.h>

#if !defined(CFG_CAAM_64BIT) && defined(ARM64)
#define IS_DMA_OVERFLOW(addr)                                                  \
	({                                                                     \
		__typeof__(addr) _addr = (addr);                               \
		(_addr >> 32) ? 1 : 0;                                         \
	})
#else
#define IS_DMA_OVERFLOW(addr) (0)
#endif

#define MAX_BUFFER_ALLOC_SIZE ((size_t)(8 * 1024))

/*
 * Local defines used to identify Object type as:
 *  - input or output data
 *  - SGT object created because buffer is not physical contiguous
 *  - derived object (not buffer reallocation)
 *  - allocated origin buffer
 */
#define DMAOBJ_INPUT	  BIT(0)
#define DMAOBJ_OUTPUT	  BIT(1)
#define DMAOBJ_ALLOC_ORIG BIT(2)
#define DMAOBJ_DONT_COPY  BIT(3)

/*
 * DMA Buffer
 *
 * @require    DMA Buffer size require
 * @allocated  Size of the buffer allocated
 * @remind     Size available in the buffer
 * @buf        CAAM Buffer
 */
struct caamdmabuf {
	size_t require;
	size_t allocated;
	size_t remind;
	struct caambuf buf;
};

/*
 * DMA Object buffer entry
 *
 * @newbuf        True if list entry is a new DMA Buffer
 * @nodma_access  Buffer is not accessible from CAAM DMA
 * @nocopy        Buffer doesn't have to be copied back to the origin
 * @origbuf       Original buffer reference
 * @next          Pointer to next entry
 */
struct dmaentry {
	bool newbuf;
	bool nodma_access;
	bool nocopy;

	struct caambuf origbuf;

	TAILQ_ENTRY(dmaentry) next;
};

/*
 * SGT/Buffer Data currently handled
 *
 * @orig    Original buffer reference
 * @dma     DMA Buffer (new or original)
 */
struct sgtdata {
	uint8_t *orig;
	uint8_t *dma;
	size_t length;
};

/*
 * CAAM DMA private Object data
 * @type         Type of DMA Object
 * @nb_sgtbuf    Number of SGT/Buffer entries allocated
 * @dmabuf       DMA Buffer allocated
 * @sgtdata      Reference to SGT/Buffer list in used
 * @list         List of the DMA Object buffer entry
 */
struct priv_dmaobj {
	unsigned int type;
	unsigned int nb_sgtbuf;

	struct caamdmabuf dmabuf;
	struct sgtdata *sgtdata;

	TAILQ_HEAD(dmalist, dmaentry) list;
};

/*
 * Memory Allocation and Free spinlock to ensure that in case
 * of big buffer reallocation, memory used is freed
 */
static unsigned int memlock;

/*
 * Try to allocate a DMA Buffer of type input or output data of @size bytes.
 * If allocation success, set the DMA Buffer settings, else
 * return in error.
 * If the DMA Buffer is already allocated, returns in error.
 *
 * @priv  CAAM DMA object private data
 * @size  Size of the DMA Buffer to allocate
 */
static TEE_Result try_allocate_dmabuf(struct priv_dmaobj *priv, size_t size)
{
	enum caam_status retstatus = CAAM_FAILURE;

	if (priv->dmabuf.allocated) {
		caam_free_buf(&priv->dmabuf.buf);
		priv->dmabuf.allocated = 0;
	}

	if (priv->type & DMAOBJ_INPUT)
		retstatus = caam_alloc_buf(&priv->dmabuf.buf, size);
	else
		retstatus = caam_alloc_align_buf(&priv->dmabuf.buf, size);

	DMAOBJ_TRACE("Alloc %s DMA buffer (%zu) ret 0x%" PRIx32,
		     (priv->type & DMAOBJ_INPUT) ? "Input" : "Output", size,
		     retstatus);

	if (retstatus == CAAM_NO_ERROR) {
		DMAOBJ_TRACE("DMA buffer Allocation Success");
		/* Set the Object's DMA Buffer settings */
		priv->dmabuf.allocated = size;
		priv->dmabuf.remind = size;
		priv->dmabuf.buf.length = 0;
		return TEE_SUCCESS;
	}

	DMAOBJ_TRACE("DMA buffer Allocation Failure");
	return TEE_ERROR_OUT_OF_MEMORY;
}

/*
 * Allocate and initialize the CAAM DMA object's private data.
 *
 * @obj   CAAM DMA Object
 * @type  Type of the CAAM DMA Object (i.e. Input or Output)
 */
static TEE_Result allocate_private(struct caamdmaobj *obj, unsigned int type)
{
	struct priv_dmaobj *priv = NULL;

	priv = caam_calloc(sizeof(*priv));
	if (!priv)
		return TEE_ERROR_OUT_OF_MEMORY;

	obj->priv = priv;

	/* Set the object type as input */
	priv->type = type;

	TAILQ_INIT(&priv->list);

	return TEE_SUCCESS;
}

/*
 * Fill the @sgtdata object to record the current input/output data
 * handled in the DMA SGT/Buffer object.
 * Increment the SGT/Buffer length according
 *
 * @obj      CAAM DMA object
 * @sgtdata  [out] SGT Data handled
 * @entry    DMA Object buffer entry
 * @dma      DMA SGT/Buffer object
 * @offset   Start offset of the DMA Object buffer
 */
static void add_sgtdata_entry(struct caamdmaobj *obj, struct sgtdata *sgtdata,
			      struct dmaentry *entry, struct caambuf *dma,
			      size_t offset)
{
	if (entry->nocopy) {
		sgtdata->orig = 0;
		sgtdata->length = 0;
		sgtdata->dma = 0;
	} else {
		sgtdata->orig = entry->origbuf.data + offset;
		sgtdata->length = dma->length;
		sgtdata->dma = dma->data;
	}

	obj->sgtbuf.length += dma->length;
}

/*
 * Add a new DMA Buffer entry as first element of the list.
 * Return NULL if error, else the new entry in the list
 *
 * @priv    DMA Object private data
 * @orig    Original buffer reference
 */
static struct dmaentry *dmalist_add_entry_head(struct priv_dmaobj *priv,
					       struct caambuf *orig)
{
	struct dmaentry *entry = NULL;

	entry = caam_calloc(sizeof(*entry));
	if (entry) {
		/* Save the original buffer reference */
		memcpy(&entry->origbuf, orig, sizeof(entry->origbuf));
		DMAOBJ_TRACE("entry %p - insert head entry of %zu bytes", entry,
			     orig->length);
		TAILQ_INSERT_HEAD(&priv->list, entry, next);
	}

	return entry;
}

/*
 * Add a new DMA Buffer entry in the list.
 * Return NULL if error, else the new entry in the list
 *
 * @priv    DMA Object private data
 * @orig    Original buffer reference
 */
static struct dmaentry *dmalist_add_entry(struct priv_dmaobj *priv,
					  struct caambuf *orig)
{
	struct dmaentry *entry = NULL;

	entry = caam_calloc(sizeof(*entry));
	if (entry) {
		/* Save the original buffer reference */
		memcpy(&entry->origbuf, orig, sizeof(entry->origbuf));
		DMAOBJ_TRACE("entry %p - insert entry of %zu bytes", entry,
			     orig->length);
		if (TAILQ_EMPTY(&priv->list))
			TAILQ_INSERT_HEAD(&priv->list, entry, next);
		else
			TAILQ_INSERT_TAIL(&priv->list, entry, next);
	}

	return entry;
}

static struct dmaentry *dmalist_insert_before_entry(struct priv_dmaobj *priv,
						    struct dmaentry *before,
						    struct caambuf *new)
{
	struct dmaentry *entry = NULL;

	entry = caam_calloc(sizeof(*entry));
	if (entry) {
		/* Save the original buffer reference */
		memcpy(&entry->origbuf, new, sizeof(entry->origbuf));
		DMAOBJ_TRACE("entry %p - insert entry of %zu bytes", entry,
			     new->length);
		if (TAILQ_FIRST(&priv->list) == before)
			TAILQ_INSERT_HEAD(&priv->list, entry, next);
		else
			TAILQ_INSERT_BEFORE(before, entry, next);
	}

	return entry;
}

static struct dmaentry *dmalist_insert_after_entry(struct priv_dmaobj *priv,
						   struct dmaentry *after,
						   struct caambuf *new)
{
	struct dmaentry *entry = NULL;

	entry = caam_calloc(sizeof(*entry));
	if (entry) {
		/* Save the original buffer reference */
		memcpy(&entry->origbuf, new, sizeof(entry->origbuf));
		DMAOBJ_TRACE("entry %p - insert entry of %zu bytes", entry,
			     new->length);
		TAILQ_INSERT_AFTER(&priv->list, after, entry, next);
	}

	return entry;
}

/*
 * Apply the cache operation @op to the DMA Object (SGT or buffer)
 *
 * @op    Cache operation
 * @obj   CAAM DMA object
 */
static inline void dmaobj_cache_operation(enum utee_cache_operation op,
					  struct caamdmaobj *obj)
{
	if (!obj->sgtbuf.length)
		return;

	if (obj->sgtbuf.sgt_type)
		caam_sgt_cache_op(op, &obj->sgtbuf, obj->sgtbuf.length);
	else if (!obj->sgtbuf.buf->nocache)
		cache_operation(op, obj->sgtbuf.buf->data, obj->sgtbuf.length);
}

static inline void add_dma_require(struct priv_dmaobj *priv, size_t length)
{
	size_t tmp = 0;

	if (ADD_OVERFLOW(priv->dmabuf.require, length, &tmp))
		priv->dmabuf.require = SIZE_MAX;
	else
		priv->dmabuf.require = tmp;
}

/*
 * Check if the buffer start/end addresses are aligned on the cache line.
 * If not flags as start and/or end addresses not aligned, expect if the
 * maximum length @maxlen to use is inside a cache line size. In this case,
 * flags to allocate a new buffer.
 *
 * @priv    DMA Object private data
 * @maxlen  Maximum length to use
 */
static TEE_Result check_buffer_alignment(struct priv_dmaobj *priv,
					 size_t maxlen)
{
	unsigned int cacheline_size = 0;
	struct dmaentry *entry = NULL;
	struct dmaentry *new_entry = NULL;
	struct caambuf newbuf = {};
	vaddr_t va_start = 0;
	vaddr_t va_end = 0;
	vaddr_t va_end_align = 0;
	vaddr_t va_start_align = 0;
	size_t remlen = 0;
	size_t acclen = 0;

	cacheline_size = dcache_get_line_size();

	TAILQ_FOREACH(entry, &priv->list, next)
	{
		DMAOBJ_TRACE("Entry %p: start %p len %zu (%zu >= %zu)", entry,
			     entry->origbuf.data, entry->origbuf.length, acclen,
			     maxlen);

		/* No need to continue if we convert the needed length */
		if (acclen >= maxlen)
			return TEE_SUCCESS;

		acclen += entry->origbuf.length;

		if (entry->nodma_access || entry->newbuf)
			continue;

		if (entry->origbuf.length < cacheline_size) {
			/*
			 * Length of the entry is not aligned on cache size
			 * Require a full aligned buffer
			 */
			DMAOBJ_TRACE("Length %zu vs cache line %u",
				     entry->origbuf.length, cacheline_size);

			entry->newbuf = true;
			add_dma_require(priv, entry->origbuf.length);
			continue;
		}

		va_start = (vaddr_t)entry->origbuf.data;
		va_start_align = ROUNDUP(va_start, cacheline_size);

		if (va_start_align != va_start) {
			DMAOBJ_TRACE("Start 0x%" PRIxVA " vs align 0x%" PRIxVA,
				     va_start, va_start_align);

			remlen = entry->origbuf.length -
				 (va_start_align - va_start);
			if (remlen <= cacheline_size) {
				/*
				 * Start address is not aligned and the
				 * remaining length if after re-alignment
				 * is not cache size aligned.
				 * Require a full aligned buffer
				 */
				DMAOBJ_TRACE("Rem length %zu vs cache line %u",
					     remlen, cacheline_size);
				entry->newbuf = true;
				add_dma_require(priv, entry->origbuf.length);
				continue;
			}

			/*
			 * Insert a new entry to make buffer on a cache line.
			 */
			newbuf.data = entry->origbuf.data;
			newbuf.length = va_start_align - va_start;
			newbuf.paddr = entry->origbuf.paddr;
			newbuf.nocache = entry->origbuf.nocache;

			add_dma_require(priv, newbuf.length);
			new_entry = dmalist_insert_before_entry(priv, entry,
								&newbuf);
			if (!new_entry)
				return TEE_ERROR_OUT_OF_MEMORY;

			new_entry->newbuf = true;

			/*
			 * Update current entry with align address and new
			 * length.
			 */
			entry->origbuf.data = (uint8_t *)va_start_align;
			entry->origbuf.length -= newbuf.length;
			entry->origbuf.paddr += newbuf.length;

			/*
			 * Set current entry to new entry to continue
			 * the FOREACH loop from this new_entry and then
			 * verify the rest of the entry modified.
			 */
			entry = new_entry;
			acclen -= entry->origbuf.length;
			continue;
		}

		/*
		 * NOTICE:
		 * Due to the CAAM DMA behaviour on iMX8QM & iMX8QX,
		 * 4 bytes need to be add to the buffer size when aligned
		 * memory allocation is done.
		 * This is not verified here because no issue observed
		 * during all tests.
		 * This rule is respected when new DMA buffer is allocated
		 * in the utils_mem.c allocator.
		 */
		va_end = (vaddr_t)entry->origbuf.data + entry->origbuf.length;
		va_end_align = ROUNDUP(va_end, cacheline_size);

		if (va_end != va_end_align) {
			DMAOBJ_TRACE("End 0x%" PRIxVA " vs align 0x%" PRIxVA,
				     va_end, va_end_align);

			va_end_align = ROUNDDOWN(va_end, cacheline_size);
			remlen = entry->origbuf.length - va_end_align;

			if (remlen <= cacheline_size) {
				/*
				 * End address is not aligned and the remaining
				 * length if after re-alignment is not cache
				 * size aligned.
				 * Require a full aligned buffer
				 */
				DMAOBJ_TRACE("Rem length %zu vs cache line %u",
					     remlen, cacheline_size);
				entry->newbuf = true;
				add_dma_require(priv, entry->origbuf.length);
				continue;
			}

			/*
			 * Insert a new entry to make buffer on a cache line.
			 */
			newbuf.data = (uint8_t *)va_end_align;
			newbuf.length = va_end - va_end_align;
			newbuf.paddr = entry->origbuf.paddr + newbuf.length;
			newbuf.nocache = entry->origbuf.nocache;

			add_dma_require(priv, newbuf.length);

			new_entry = dmalist_insert_after_entry(priv, entry,
							       &newbuf);
			if (!new_entry)
				return TEE_ERROR_OUT_OF_MEMORY;

			new_entry->newbuf = true;

			/* Update current entry with new length */
			entry->origbuf.length -= newbuf.length;

			/*
			 * Set current entry to new entry to continue
			 * the FOREACH loop from this new_entry and then
			 * verify the rest of the entry modified.
			 */
			entry = new_entry;
			acclen -= newbuf.length;
			continue;
		}
	}

	return TEE_SUCCESS;
}

/*
 * Go through all the @orig space to extract all physical area used to
 * map the buffer.
 * If one of the physical area is not accessible by the CAAM DMA, flag it
 * to be reallocated with DMA accessible buffer.
 * If the DMA Object is an output buffer, check and flag the start/end
 * address of the buffer to be aligned on a cache line.
 *
 * @obj     CAAM DMA object
 * @orig    Original Data
 * @maxlen  Maximum length to use
 */
static TEE_Result check_buffer_boundary(struct caamdmaobj *obj,
					struct caambuf *orig, size_t maxlen)
{
	TEE_Result ret = TEE_ERROR_OUT_OF_MEMORY;
	struct priv_dmaobj *priv = obj->priv;
	struct dmaentry *entry = NULL;
	struct caambuf *pabufs = NULL;
	int nb_pa_area = -1;
	int ret_pa_area = 0;
	int idx = 0;
	paddr_t last_pa = 0;
	size_t remlen = maxlen;
	size_t tmp = 0;

	/*
	 * Get the number of physical areas used by the
	 * DMA Buffer
	 */
	nb_pa_area = caam_mem_get_pa_area(orig, &pabufs);
	DMAOBJ_TRACE("Number of pa areas = %d (for max length %zu bytes)",
		     nb_pa_area, remlen);
	if (nb_pa_area == -1)
		goto end;

	for (; idx < nb_pa_area && remlen; idx++, ret_pa_area++) {
		DMAOBJ_TRACE("Remaining length = %zu", remlen);
		if (ADD_OVERFLOW(pabufs[idx].paddr, pabufs[idx].length,
				 &last_pa))
			goto end;

		DMAOBJ_TRACE("PA 0x%" PRIxPA " = 0x%" PRIxPA " + %zu", last_pa,
			     pabufs[idx].paddr, pabufs[idx].length);

		entry = dmalist_add_entry(priv, &pabufs[idx]);
		if (!entry)
			goto end;

		if (IS_DMA_OVERFLOW(last_pa)) {
			entry->nodma_access = true;
			if (ADD_OVERFLOW(priv->dmabuf.require,
					 pabufs[idx].length, &tmp))
				priv->dmabuf.require = SIZE_MAX;
			else
				priv->dmabuf.require = tmp;
		}

		if (remlen > pabufs[idx].length)
			remlen -= pabufs[idx].length;
		else
			remlen = 0;
	}

	/*
	 * Check the buffer alignment if the buffer is cacheable and
	 * an output buffer.
	 */
	if (priv->type & DMAOBJ_OUTPUT && !orig->nocache) {
		ret = check_buffer_alignment(priv, maxlen);
		if (ret)
			goto end;
	}

	orig->length = maxlen;

	ret = TEE_SUCCESS;
end:
	caam_free(pabufs);
	return ret;
}

/*
 * Re-map a DMA entry into a CAAM DMA accessible buffer.
 * Create the SGT/Buffer entry to be used in the CAAM Descriptor
 * Record this entry in the SGT/Buffer Data to get information on current
 * working data.
 *
 * @obj         CAAM DMA object
 * @entry       DMA entry to re-map
 * @index       Index in the SGT/Buffer table
 * @off         Start offset of the DMA entry data
 */
static enum caam_status entry_sgtbuf_dmabuf(struct caamdmaobj *obj,
					    struct dmaentry *entry,
					    unsigned int index, size_t off)
{
	struct priv_dmaobj *priv = obj->priv;
	struct caambuf *sgtbuf = &obj->sgtbuf.buf[index];
	struct caamdmabuf *dmabuf = &priv->dmabuf;

	if (!priv->dmabuf.allocated)
		return CAAM_OUT_MEMORY;

	sgtbuf->data = dmabuf->buf.data + dmabuf->buf.length;
	sgtbuf->length = MIN(dmabuf->remind, entry->origbuf.length - off);
	sgtbuf->paddr = dmabuf->buf.paddr + dmabuf->buf.length;
	sgtbuf->nocache = dmabuf->buf.nocache;
	dmabuf->remind -= sgtbuf->length;
	dmabuf->buf.length += sgtbuf->length;

	if (priv->type & DMAOBJ_INPUT)
		memcpy(sgtbuf->data, &entry->origbuf.data[off], sgtbuf->length);
	else
		entry->newbuf = true;

	add_sgtdata_entry(obj, &priv->sgtdata[index], entry, sgtbuf, off);

	return CAAM_NO_ERROR;
}

/*
 * Create the SGT/Buffer entry mapping the DMA @entry.
 * Record these entry in the SGT/buffer Data to get information on current
 * working data.
 *
 * @obj         CAAM DMA object
 * @entry       DMA entry to re-map
 * @index       Index in the SGT/Buffer table
 * @off         Start offset of the DMA entry data
 */
static enum caam_status entry_sgtbuf(struct caamdmaobj *obj,
				     struct dmaentry *entry, unsigned int index,
				     size_t off)
{
	struct priv_dmaobj *priv = obj->priv;
	struct caambuf *sgtbuf = &obj->sgtbuf.buf[index];
	struct sgtdata *sgtdata = &priv->sgtdata[index];

	memcpy(sgtbuf, &entry->origbuf, sizeof(*sgtbuf));
	sgtbuf->data += off;
	sgtbuf->paddr += off;
	sgtbuf->length -= off;

	DMAOBJ_TRACE("DMA buffer %p - %zu", sgtbuf->data, sgtbuf->length);
	add_sgtdata_entry(obj, sgtdata, entry, sgtbuf, off);

	return CAAM_NO_ERROR;
}

TEE_Result caam_dmaobj_init_input(struct caamdmaobj *obj, const void *data,
				  size_t length)
{
	TEE_Result ret = TEE_ERROR_GENERIC;

	DMAOBJ_TRACE("Input object with data @%p of %zu bytes", data, length);

	if (!data || !length || !obj) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto end;
	}

	obj->orig.paddr = virt_to_phys((void *)data);
	if (!obj->orig.paddr) {
		DMAOBJ_TRACE("Object virtual address error");
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto end;
	}

	obj->orig.data = (void *)data;
	obj->orig.length = length;
	if (!caam_mem_is_cached_buf((void *)data, length))
		obj->orig.nocache = 1;

	ret = allocate_private(obj, DMAOBJ_INPUT);
	if (!ret)
		ret = check_buffer_boundary(obj, &obj->orig, obj->orig.length);

end:
	DMAOBJ_TRACE("Object returns 0x%" PRIx32, ret);
	return ret;
}

TEE_Result caam_dmaobj_input_sgtbuf(struct caamdmaobj *obj, const void *data,
				    size_t length)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	size_t size_done = length;

	ret = caam_dmaobj_init_input(obj, data, length);
	if (ret)
		return ret;

	ret = caam_dmaobj_prepare(obj, NULL, length);
	if (ret)
		return ret;

	ret = caam_dmaobj_sgtbuf_build(obj, &size_done, 0, length);
	if (ret)
		return ret;

	if (size_done != length)
		return TEE_ERROR_OUT_OF_MEMORY;

	return TEE_SUCCESS;
}

TEE_Result caam_dmaobj_init_output(struct caamdmaobj *obj, const void *data,
				   size_t length, size_t min_length)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	struct dmaentry *entry = NULL;
	struct caambuf newbuf = {};

	DMAOBJ_TRACE("Output object with data @%p of %zu bytes (%zu)", data,
		     length, min_length);

	if (!obj) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto end;
	}

	ret = allocate_private(obj, DMAOBJ_OUTPUT);
	if (ret)
		goto end;

	if (data) {
		obj->orig.paddr = virt_to_phys((void *)data);
		if (!obj->orig.paddr) {
			DMAOBJ_TRACE("Object virtual address error");
			ret = TEE_ERROR_BAD_PARAMETERS;
			goto end;
		}

		obj->orig.data = (void *)data;
		obj->orig.length = length;
		if (!caam_mem_is_cached_buf((void *)data, length))
			obj->orig.nocache = 1;

		ret = check_buffer_boundary(obj, &obj->orig,
					    MIN(min_length, obj->orig.length));
		if (ret)
			goto end;
	}

	if (length < min_length || !data) {
		DMAOBJ_TRACE("Output buffer too short need %zu bytes (+%zu)",
			     min_length, min_length - length);
		newbuf.length = min_length - length;

		entry = dmalist_add_entry(obj->priv, &newbuf);
		if (!entry) {
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto end;
		}

		entry->nocopy = true;
		entry->newbuf = true;
	}

	ret = TEE_SUCCESS;

end:
	DMAOBJ_TRACE("Object returns 0x%" PRIx32, ret);
	return ret;
}

TEE_Result caam_dmaobj_output_sgtbuf(struct caamdmaobj *obj, const void *data,
				     size_t length, size_t min_length)
{
	enum caam_status retstatus = CAAM_FAILURE;
	TEE_Result ret = TEE_ERROR_GENERIC;
	struct priv_dmaobj *priv = NULL;
	size_t size = 0;
	struct caambuf buf = {};

	if (!data && !length && min_length) {
		/*
		 * We are sure that the minimum size of the allocated
		 * buffer is a cache line, hence we know that
		 * start/end address are cache aligned.
		 * If the @min_length is less than a cache line size, we
		 * can initializing the output buffer with the cache line size
		 * to prevent end buffer misalignement so reallocate a not used
		 * buffer.
		 */
		size = MAX(min_length, dcache_get_line_size());

		/* Allocate a new cache aligned buffer */
		retstatus = caam_alloc_align_buf(&buf, size);
		DMAOBJ_TRACE("New output buffer of %zu bytes ret 0x%" PRIx32,
			     min_length, retstatus);
		if (retstatus != CAAM_NO_ERROR)
			return caam_status_to_tee_result(retstatus);

		ret = caam_dmaobj_init_output(obj, buf.data, buf.length, size);
		if (ret)
			return ret;

		/* Set the correct origin buffer length asked */
		obj->orig.length = min_length;

		/* Flag origin buffer as new allocation to free it */
		priv = obj->priv;
		priv->type |= DMAOBJ_ALLOC_ORIG;
	} else {
		ret = caam_dmaobj_init_output(obj, data, length, min_length);
		if (ret)
			return ret;
	}

	ret = caam_dmaobj_prepare(NULL, obj, min_length);
	if (ret)
		return ret;

	size = min_length;
	ret = caam_dmaobj_sgtbuf_build(obj, &size, 0, min_length);
	if (ret)
		return ret;

	if (size != min_length)
		return TEE_ERROR_OUT_OF_MEMORY;

	return TEE_SUCCESS;
}

void caam_dmaobj_cache_push(struct caamdmaobj *obj)
{
	struct priv_dmaobj *priv = NULL;
	enum utee_cache_operation op = TEE_CACHECLEAN;

	if (!obj || !obj->priv)
		return;

	priv = obj->priv;
	if (priv->type & DMAOBJ_OUTPUT)
		op = TEE_CACHEFLUSH;

	dmaobj_cache_operation(op, obj);
}

size_t caam_dmaobj_copy_to_orig(struct caamdmaobj *obj)
{
	struct priv_dmaobj *priv = NULL;
	struct sgtdata *sgtdata = NULL;
	unsigned int idx = 0;
	size_t length = 0;
	size_t dst_rlen = 0;
	size_t copy_size = 0;

	if (!obj || !obj->orig.data || !obj->priv)
		return 0;

	dmaobj_cache_operation(TEE_CACHEINVALIDATE, obj);

	priv = obj->priv;
	sgtdata = priv->sgtdata;

	dst_rlen = obj->orig.length;
	DMAOBJ_TRACE("Copy (len=%zu)", dst_rlen);

	for (; idx < obj->sgtbuf.number && sgtdata && dst_rlen;
	     idx++, sgtdata++) {
		copy_size = MIN(dst_rlen, sgtdata->length);
		if (sgtdata->orig != sgtdata->dma && sgtdata->orig) {
			copy_size = MIN(dst_rlen, sgtdata->length);
			memcpy(sgtdata->orig, sgtdata->dma, copy_size);
		}

		length += copy_size;
		dst_rlen -= copy_size;
	}

	return length;
}

size_t caam_dmaobj_copy_ltrim_to_orig(struct caamdmaobj *obj)
{
	struct priv_dmaobj *priv = NULL;
	struct sgtdata *sgtdata = NULL;
	uint8_t *dst = NULL;
	size_t off = 0;
	size_t offset = 0;
	size_t dst_rlen = 0;
	size_t copy_size = 0;
	unsigned int idx = 0;
	size_t length = 0;

	if (!obj || !obj->orig.data || !obj->priv)
		return 0;

	dmaobj_cache_operation(TEE_CACHEINVALIDATE, obj);

	priv = obj->priv;
	sgtdata = priv->sgtdata;

	for (; idx < obj->sgtbuf.number && sgtdata; idx++, sgtdata++) {
		if (!sgtdata->orig)
			continue;

		for (offset = 0; offset < sgtdata->length; off++, offset++) {
			if (sgtdata->dma[offset])
				goto do_copy;
		}
	}

do_copy:
	if (off < obj->orig.length)
		dst_rlen = obj->orig.length - off;

	dst = obj->orig.data;

	DMAOBJ_TRACE("Copy/Move Offset=%zu (len=%zu) TYPE=%d", off, dst_rlen,
		     obj->sgtbuf.sgt_type);

	if (!dst_rlen) {
		dst[0] = 0;
		return 1;
	}

	for (; idx < obj->sgtbuf.number && sgtdata && dst_rlen;
	     idx++, sgtdata++) {
		if (!sgtdata->orig)
			continue;

		if (offset) {
			copy_size = MIN(dst_rlen, sgtdata->length - offset);
			memmove(dst, &sgtdata->dma[offset], copy_size);
			offset = 0;
		} else {
			copy_size = MIN(dst_rlen, sgtdata->length);
			if (dst != sgtdata->dma)
				memmove(dst, sgtdata->dma, copy_size);
		}

		dst += copy_size;
		dst_rlen -= copy_size;
		length += copy_size;
	}

	return length;
}

void caam_dmaobj_free(struct caamdmaobj *obj)
{
	struct priv_dmaobj *priv = NULL;
	struct dmaentry *entry = NULL;
	struct dmaentry *next = NULL;
	uint32_t exceptions = 0;

	if (!obj)
		return;

	exceptions = cpu_spin_lock_xsave(&memlock);
	priv = obj->priv;
	if (!priv)
		goto end;

	DMAOBJ_TRACE("Free %s object with data @%p of %zu bytes",
		     priv->type & DMAOBJ_INPUT ? "Input" : "Output",
		     obj->orig.data, obj->orig.length);

	entry = TAILQ_FIRST(&priv->list);
	while (entry) {
		DMAOBJ_TRACE("Is type 0x%" PRIx8 " newbuf %s", priv->type,
			     entry->newbuf ? "true" : "false");

		next = TAILQ_NEXT(entry, next);

		DMAOBJ_TRACE("Free entry %p", entry);
		caam_free(entry);

		entry = next;
		DMAOBJ_TRACE("Next entry %p", entry);
	};

	if (priv->nb_sgtbuf) {
		DMAOBJ_TRACE("Free #%d SGT data %p", priv->nb_sgtbuf,
			     priv->sgtdata);
		caam_free(priv->sgtdata);

		obj->sgtbuf.number = priv->nb_sgtbuf;
		obj->sgtbuf.sgt_type = (priv->nb_sgtbuf > 1) ? true : false;
	}

	if (priv->dmabuf.allocated) {
		DMAOBJ_TRACE("Free CAAM DMA buffer");
		caam_free_buf(&priv->dmabuf.buf);
	}

	if (priv->type & DMAOBJ_ALLOC_ORIG) {
		DMAOBJ_TRACE("Free Allocated origin");
		caam_free_buf(&obj->orig);
	}

	DMAOBJ_TRACE("Free private object %p", priv);
	caam_free(priv);

end:
	if (obj->sgtbuf.number) {
		DMAOBJ_TRACE("Free #%d SGT/Buffer %p", obj->sgtbuf.number,
			     &obj->sgtbuf);
		caam_sgtbuf_free(&obj->sgtbuf);
	}

	memset(obj, 0, sizeof(*obj));

	cpu_spin_unlock_xrestore(&memlock, exceptions);
}

TEE_Result caam_dmaobj_add_first_block(struct caamdmaobj *obj,
				       struct caamblock *block)
{
	struct priv_dmaobj *priv = NULL;
	struct caambuf newbuf = {};
	struct dmaentry *entry = NULL;

	if (!obj || !obj->priv || !block)
		return TEE_ERROR_BAD_PARAMETERS;

	priv = obj->priv;

	/* Save the block buffer reference and insert it at the head list */
	newbuf.data = block->buf.data;
	newbuf.length = block->filled;
	newbuf.paddr = block->buf.paddr;
	newbuf.nocache = block->buf.nocache;

	entry = dmalist_add_entry_head(priv, &newbuf);

	if (!entry)
		return TEE_ERROR_OUT_OF_MEMORY;

	/*
	 * Block buffer added in the output DMA buffer doesn't have to
	 * be part of the output copy to origin buffer.
	 */
	if (priv->type & DMAOBJ_OUTPUT)
		entry->nocopy = true;

	return TEE_SUCCESS;
}

TEE_Result caam_dmaobj_derive_sgtbuf(struct caamdmaobj *obj,
				     const struct caamdmaobj *from,
				     size_t offset, size_t length)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	enum caam_status retstatus = CAAM_FAILURE;
	struct priv_dmaobj *priv = NULL;

	DMAOBJ_TRACE("Derive object %p - offset %zu - length %zu bytes", from,
		     offset, length);

	if (!obj || !from || !length || !from->priv) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto end;
	}

	if (!from->orig.data || !from->orig.length) {
		DMAOBJ_TRACE("No data/length to derive from");
		ret = TEE_ERROR_NO_DATA;
		goto end;
	}

	priv = from->priv;
	if (!priv->nb_sgtbuf) {
		DMAOBJ_TRACE("From SGT/Buffer not prepared");
		ret = TEE_ERROR_NO_DATA;
		goto end;
	}

	retstatus =
		caam_sgt_derive(&obj->sgtbuf, &from->sgtbuf, offset, length);

	ret = caam_status_to_tee_result(retstatus);

end:
	DMAOBJ_TRACE("Object returns 0x%" PRIx32, ret);
	return ret;
}

TEE_Result caam_dmaobj_prepare(struct caamdmaobj *input,
			       struct caamdmaobj *output, size_t min_size)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	struct priv_dmaobj *priv_input = NULL;
	struct priv_dmaobj *priv_output = NULL;
	size_t max_alloc_input = 0;
	size_t max_alloc_output = 0;
	uint32_t exceptions = 0;
	bool try_input_alloc = false;
	bool try_output_alloc = false;

	if (!input && !output) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto end;
	}

	if ((input && !input->priv) || (output && !output->priv)) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto end;
	}

	DMAOBJ_TRACE("input=%p - output=%p - min=%zu", input, output, min_size);

	if (input) {
		priv_input = input->priv;
		DMAOBJ_TRACE("Input DMA buffer size require %zu",
			     priv_input->dmabuf.require);
		max_alloc_input =
			MIN(priv_input->dmabuf.require, MAX_BUFFER_ALLOC_SIZE);
		if (max_alloc_input > 1024)
			max_alloc_input = ROUNDDOWN(max_alloc_input, 1024);

		if (max_alloc_input)
			try_input_alloc = true;
	}

	if (output) {
		priv_output = output->priv;
		DMAOBJ_TRACE("Output DMA buffer size require %zu",
			     priv_output->dmabuf.require);
		max_alloc_output =
			MIN(priv_output->dmabuf.require, MAX_BUFFER_ALLOC_SIZE);
		if (max_alloc_output > 1024)
			max_alloc_output = ROUNDDOWN(max_alloc_output, 1024);

		if (max_alloc_output)
			try_output_alloc = true;
	}

	/*
	 * If require:
	 * - Try to allocate the input big buffer.
	 * - Then Try to allocate the output big buffer.
	 *
	 * Loop while by dividing allocation size by 2 with a minimum of
	 * @min_size.
	 * If allocation with minimum size for both is failing,
	 * returns in error.
	 */
	exceptions = cpu_spin_lock_xsave(&memlock);

retry:
	DMAOBJ_TRACE("Allocation input %zu output %zu", max_alloc_input,
		     max_alloc_output);
	if (try_input_alloc) {
		ret = try_allocate_dmabuf(priv_input, max_alloc_input);
		if (!ret)
			try_input_alloc = false;
	} else {
		ret = TEE_SUCCESS;
	}

	if (try_output_alloc && !ret) {
		ret = try_allocate_dmabuf(priv_output, max_alloc_output);
		if (!ret)
			try_output_alloc = false;
	}

	if (ret) {
		if (max_alloc_input) {
			if (max_alloc_input > min_size) {
				max_alloc_input =
					MAX(min_size, max_alloc_input / 2);
				try_input_alloc = true;
			} else {
				try_input_alloc = false;
			}
		}

		if (max_alloc_output) {
			if (max_alloc_output > min_size) {
				max_alloc_output =
					MAX(min_size, max_alloc_output / 2);
				try_output_alloc = true;
			} else {
				try_output_alloc = false;
			}
		}

		if (try_input_alloc || try_output_alloc)
			goto retry;
	}

	cpu_spin_unlock_xrestore(&memlock, exceptions);
end:
	DMAOBJ_TRACE("Allocation (input %zu, output %zu) returns 0x%" PRIx32,
		     input ? max_alloc_input : 0, output ? max_alloc_output : 0,
		     ret);

	return ret;
}

TEE_Result caam_dmaobj_sgtbuf_inout_build(struct caamdmaobj *input,
					  struct caamdmaobj *output,
					  size_t *length, size_t off,
					  size_t align)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	size_t len = 0;

	DMAOBJ_TRACE("input=%p/output=%p %zu bytes (offset=%zu, align=%zu)",
		     input, output, *length, off, align);

	if (!input || !output || !length || !input->priv || !output->priv ||
	    !*length) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto end;
	}

	/*
	 * First build the input SGT/Buffer
	 */
	ret = caam_dmaobj_sgtbuf_build(input, length, off, align);
	if (ret)
		goto end;

	/*
	 * Next build the output SGT/Buffer.
	 * If returned length is not same as input, redo the input
	 * SGT/Buffer with the same length as the output.
	 */
	len = *length;
	ret = caam_dmaobj_sgtbuf_build(output, &len, off, *length);
	if (ret)
		goto end;

	if (len != *length) {
		DMAOBJ_TRACE("Retry In %zu bytes vs Out %zu bytes", *length,
			     len);

		/* Redo the input with the output length */
		*length = len;
		ret = caam_dmaobj_sgtbuf_build(input, length, off, len);
		if (!ret && *length != len) {
			DMAOBJ_TRACE("Error In %zu bytes vs Out %zu bytes",
				     *length, len);
			ret = TEE_ERROR_OUT_OF_MEMORY;
		}
	}

end:
	DMAOBJ_TRACE("Input/Output SGTBUF returns 0x%" PRIx32, ret);

	return ret;
}

TEE_Result caam_dmaobj_sgtbuf_build(struct caamdmaobj *obj, size_t *length,
				    size_t off, size_t align)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	enum caam_status retstatus = CAAM_FAILURE;
	struct priv_dmaobj *priv = NULL;
	struct dmaentry *entry = NULL;
	struct dmaentry *start_entry = NULL;
	size_t max_length = 0;
	size_t acc_length = 0;
	size_t offset = off;
	unsigned int idx = 0;
	unsigned int nb_sgt = 0;

	DMAOBJ_TRACE("obj=%p of %zu bytes (offset=%zu) - align %zu", obj,
		     *length, off, align);

	if (!obj || !obj->priv || !length || !*length) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto end;
	}

	priv = obj->priv;

	max_length = *length;
	if (priv->dmabuf.allocated && max_length > priv->dmabuf.allocated &&
	    priv->dmabuf.allocated > align)
		max_length = ROUNDDOWN(priv->dmabuf.allocated, align);

	DMAOBJ_TRACE("Prepare SGT/Buffer to do %zu of %zu", max_length,
		     *length);

	/* Find the first DMA buffer to start with */
	TAILQ_FOREACH(entry, &priv->list, next)
	{
		if (offset < entry->origbuf.length)
			break;

		offset -= entry->origbuf.length;
	}

	if (!entry) {
		DMAOBJ_TRACE("There is no DMA Object available");
		ret = TEE_ERROR_GENERIC;
		goto end;
	}

	start_entry = entry;
	DMAOBJ_TRACE("Start with %p data %p offset %zu", start_entry,
		     start_entry->origbuf.data, offset);

	acc_length = entry->origbuf.length - offset;
	nb_sgt = 1;

	/* Calculate the number of SGT entry */
	for (entry = TAILQ_NEXT(entry, next); entry && acc_length < max_length;
	     entry = TAILQ_NEXT(entry, next)) {
		acc_length += entry->origbuf.length;
		nb_sgt++;
	}

	DMAOBJ_TRACE("%d of %d SGT/Buffer entries to handle", nb_sgt,
		     priv->nb_sgtbuf);
	if (priv->nb_sgtbuf < nb_sgt) {
		if (priv->nb_sgtbuf) {
			obj->sgtbuf.number = priv->nb_sgtbuf;
			obj->sgtbuf.sgt_type =
				(priv->nb_sgtbuf > 1) ? true : false;

			caam_sgtbuf_free(&obj->sgtbuf);
			caam_free(priv->sgtdata);
			priv->nb_sgtbuf = 0;
		}

		obj->sgtbuf.number = nb_sgt;
		obj->sgtbuf.sgt_type = (nb_sgt > 1) ? true : false;

		/* Allocate a new SGT/Buffer object */
		retstatus = caam_sgtbuf_alloc(&obj->sgtbuf);
		DMAOBJ_TRACE("Allocate %d SGT entries ret 0x%" PRIx32,
			     obj->sgtbuf.number, retstatus);
		if (retstatus != CAAM_NO_ERROR) {
			ret = caam_status_to_tee_result(retstatus);
			goto end;
		}

		priv->sgtdata = caam_calloc(nb_sgt * sizeof(*priv->sgtdata));
		if (!priv->sgtdata) {
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto end;
		}

		priv->nb_sgtbuf = nb_sgt;
	} else {
		obj->sgtbuf.number = nb_sgt;
		obj->sgtbuf.sgt_type = (nb_sgt > 1) ? true : false;
	}

	/* Reset the DMA Buffer index if allocated */
	if (priv->dmabuf.allocated) {
		priv->dmabuf.remind = priv->dmabuf.allocated;
		priv->dmabuf.buf.length = 0;
	}

	obj->sgtbuf.length = 0;
	for (entry = start_entry; entry && idx < nb_sgt;
	     entry = TAILQ_NEXT(entry, next), idx++) {
		DMAOBJ_TRACE("entry %p (%d)", entry, idx);
		if (entry->nodma_access || entry->newbuf) {
			retstatus =
				entry_sgtbuf_dmabuf(obj, entry, idx, offset);
			if (retstatus != CAAM_NO_ERROR) {
				ret = caam_status_to_tee_result(retstatus);
				goto end;
			}
		} else {
			retstatus = entry_sgtbuf(obj, entry, idx, offset);
			if (retstatus != CAAM_NO_ERROR) {
				ret = caam_status_to_tee_result(retstatus);
				goto end;
			}
		}

		if (obj->sgtbuf.length >= max_length) {
			DMAOBJ_TRACE("Hold-on enough length %zu", max_length);
			obj->sgtbuf.length = max_length;
			break;
		}
		offset = 0;
	}

	if (obj->sgtbuf.sgt_type) {
		/* Build the SGT table based on the physical area list */
		caam_sgt_fill_table(&obj->sgtbuf);

		obj->sgtbuf.paddr = virt_to_phys(obj->sgtbuf.sgt);
	} else {
		obj->sgtbuf.paddr = obj->sgtbuf.buf->paddr;
	}

	*length = max_length;
	ret = TEE_SUCCESS;
end:
	DMAOBJ_TRACE("SGTBUF returns 0x%" PRIx32, ret);
	return ret;
}
