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

#define IS_DMA_OVERFLOW(addr) ((addr) > UINT32_MAX)
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
 * @link          Pointer to next entry
 */
struct dmaentry {
	bool newbuf;
	bool nodma_access;
	bool nocopy;

	struct caambuf origbuf;

	TAILQ_ENTRY(dmaentry) link;
};

/*
 * SGT/Buffer Data currently handled
 *
 * @orig    Original buffer reference
 * @dma     DMA Buffer (new or original)
 * @length  Buffer length
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
 * Memory allocation and free spinlock to ensure that in case
 * of big buffer reallocation, memory used is freed
 */
static unsigned int memlock;

/*
 * Try to allocate a DMA Buffer of type input or output data of @size bytes.
 * If allocation success, set the DMA Buffer settings, else
 * return in error.
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
		TAILQ_INSERT_HEAD(&priv->list, entry, link);
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
			TAILQ_INSERT_HEAD(&priv->list, entry, link);
		else
			TAILQ_INSERT_TAIL(&priv->list, entry, link);
	}

	return entry;
}

/*
 * Insert and allocate a DMA entry in the list before the given DMA entry.
 * Return the allocated DMA entry.
 *
 * @priv   DMA Object private data
 * @before DMA entry after the new DMA entry
 * @new    CAAM buffer of the new DMA entry
 */
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
			TAILQ_INSERT_HEAD(&priv->list, entry, link);
		else
			TAILQ_INSERT_BEFORE(before, entry, link);
	}

	return entry;
}

/*
 * Insert and allocate a DMA entry in the list after the given DMA entry.
 * Return the allocated DMA entry.
 *
 * @priv   DMA Object private data
 * @after  DMA entry before the new DMA entry
 * @new    CAAM buffer of the new DMA entry
 */
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
		TAILQ_INSERT_AFTER(&priv->list, after, entry, link);
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

/*
 * Set the required allocation size for the DMA buffer.
 *
 * @priv   DMA Object private data
 * @length Required buffer size
 */
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

	TAILQ_FOREACH(entry, &priv->list, link) {
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
		goto out;

	for (idx = 0; idx < nb_pa_area && remlen; idx++) {
		DMAOBJ_TRACE("Remaining length = %zu", remlen);
		if (ADD_OVERFLOW(pabufs[idx].paddr, pabufs[idx].length,
				 &last_pa))
			goto out;

		DMAOBJ_TRACE("PA 0x%" PRIxPA " = 0x%" PRIxPA " + %zu", last_pa,
			     pabufs[idx].paddr, pabufs[idx].length);

		entry = dmalist_add_entry(priv, &pabufs[idx]);
		if (!entry)
			goto out;

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
			goto out;
	}

	orig->length = maxlen;

	ret = TEE_SUCCESS;
out:
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
		goto out;
	}

	obj->orig.paddr = virt_to_phys((void *)data);
	if (!obj->orig.paddr) {
		DMAOBJ_TRACE("Object virtual address error");
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	obj->orig.data = (void *)data;
	obj->orig.length = length;
	if (!caam_mem_is_cached_buf((void *)data, length))
		obj->orig.nocache = 1;

	ret = allocate_private(obj, DMAOBJ_INPUT);
	if (!ret)
		ret = check_buffer_boundary(obj, &obj->orig, obj->orig.length);

out:
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

TEE_Result caam_dmaobj_init_output(struct caamdmaobj *obj, void *data,
				   size_t length, size_t min_length)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	struct dmaentry *entry = NULL;
	struct caambuf newbuf = {};

	DMAOBJ_TRACE("Output object with data @%p of %zu bytes (%zu)", data,
		     length, min_length);

	if (!obj) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	ret = allocate_private(obj, DMAOBJ_OUTPUT);
	if (ret)
		goto out;

	if (data) {
		obj->orig.paddr = virt_to_phys((void *)data);
		if (!obj->orig.paddr) {
			DMAOBJ_TRACE("Object virtual address error");
			ret = TEE_ERROR_BAD_PARAMETERS;
			goto out;
		}

		obj->orig.data = (void *)data;
		obj->orig.length = length;
		if (!caam_mem_is_cached_buf((void *)data, length))
			obj->orig.nocache = 1;

		ret = check_buffer_boundary(obj, &obj->orig,
					    MIN(min_length, obj->orig.length));
		if (ret)
			goto out;
	}

	if (length < min_length || !data) {
		DMAOBJ_TRACE("Output buffer too short need %zu bytes (+%zu)",
			     min_length, min_length - length);
		newbuf.length = min_length - length;

		entry = dmalist_add_entry(obj->priv, &newbuf);
		if (!entry) {
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto out;
		}

		/* Add the additional size in the DMA buffer length */
		add_dma_require(obj->priv, newbuf.length);

		entry->nocopy = true;
		entry->newbuf = true;
	}

	ret = TEE_SUCCESS;

out:
	DMAOBJ_TRACE("Object returns 0x%" PRIx32, ret);
	return ret;
}

TEE_Result caam_dmaobj_output_sgtbuf(struct caamdmaobj *obj, void *data,
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
	unsigned int idx = 0;
	size_t length = 0;
	size_t dst_rlen = 0;
	size_t copy_size = 0;

	if (!obj || !obj->orig.data || !obj->priv)
		return 0;

	dmaobj_cache_operation(TEE_CACHEINVALIDATE, obj);

	priv = obj->priv;

	/*
	 * The maximum data size to copy cannot exceed the output buffer size
	 * (obj->orig.length) and cannot exceed the data processed by the
	 * CAAM (obj->sgtbuf.length).
	 */
	dst_rlen = MIN(obj->orig.length, obj->sgtbuf.length);

	DMAOBJ_TRACE("Copy (len=%zu)", dst_rlen);

	for (idx = 0; idx < obj->sgtbuf.number; idx++) {
		struct sgtdata *sgtdata = priv->sgtdata + idx;

		if (!sgtdata)
			break;

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

	/* Parse the SGT data list to discard leading zeros */
	for (idx = 0; idx < obj->sgtbuf.number; idx++) {
		struct sgtdata *sgtdata = priv->sgtdata + idx;

		if (!sgtdata)
			break;

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

	/*
	 * After discarding leading zeros in the SGT data list, start the copy
	 * operation on the remaining elements of the data list.
	 * List index must not be re-initialized before entering this loop.
	 */
	for (; idx < obj->sgtbuf.number; idx++) {
		struct sgtdata *sgtdata = priv->sgtdata + idx;

		if (!sgtdata)
			break;

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
		goto out;

	DMAOBJ_TRACE("Free %s object with data @%p of %zu bytes",
		     priv->type & DMAOBJ_INPUT ? "Input" : "Output",
		     obj->orig.data, obj->orig.length);

	TAILQ_FOREACH_SAFE(entry, &priv->list, link, next) {
		DMAOBJ_TRACE("Is type 0x%" PRIx8 " newbuf %s", priv->type,
			     entry->newbuf ? "true" : "false");

		DMAOBJ_TRACE("Free entry %p", entry);
		caam_free(entry);
	}

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

out:
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
		goto out;
	}

	if (!from->orig.data || !from->orig.length) {
		DMAOBJ_TRACE("No data/length to derive from");
		ret = TEE_ERROR_NO_DATA;
		goto out;
	}

	priv = from->priv;
	if (!priv->nb_sgtbuf) {
		DMAOBJ_TRACE("From SGT/Buffer not prepared");
		ret = TEE_ERROR_NO_DATA;
		goto out;
	}

	retstatus = caam_sgt_derive(&obj->sgtbuf, &from->sgtbuf, offset,
				    length);

	ret = caam_status_to_tee_result(retstatus);

out:
	DMAOBJ_TRACE("Object returns 0x%" PRIx32, ret);
	return ret;
}

/*
 * Get the maximum allocation size for the given CAAM DMA object.
 * Return the maximum allocation size.
 *
 * @obj CAAM DMA object
 */
static size_t get_dma_max_alloc_size(struct caamdmaobj *obj)
{
	size_t alloc_size = 0;
	struct priv_dmaobj *priv = NULL;

	if (!obj)
		return 0;

	priv = obj->priv;

	DMAOBJ_TRACE("DMA buffer size require %zu", priv->dmabuf.require);
	alloc_size = MIN(priv->dmabuf.require, MAX_BUFFER_ALLOC_SIZE);
	if (alloc_size > 1024)
		alloc_size = ROUNDDOWN(alloc_size, 1024);

	return alloc_size;
}

/*
 * Allocate the CAAM DMA buffer.
 * First, try to allocate the with the maximum size. If it fails, try to
 * allocate with the same size divided by two. Try to allocate until
 * minimum size is reached. If the allocation cannot be done with the
 * minimum size, return TEE_ERROR_OUT_OF_MEMORY, TEE_SUCCESS otherwise.
 *
 * @obj       CAAM DMA object
 * @min_size  minimum size allocation
 * @size[out] successful allocation size
 */
static TEE_Result try_allocate_dmabuf_max_size(struct caamdmaobj *obj,
					       size_t min_size,
					       size_t *size)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	size_t alloc_size = 0;
	struct priv_dmaobj *priv = NULL;
	bool try_alloc = false;
	uint32_t exceptions = 0;

	alloc_size = get_dma_max_alloc_size(obj);
	if (alloc_size) {
		try_alloc = true;
	} else {
		ret = TEE_SUCCESS;
		goto out;
	}

	priv = obj->priv;

	exceptions = cpu_spin_lock_xsave(&memlock);

	while (try_alloc) {
		ret = try_allocate_dmabuf(priv, alloc_size);
		if (!ret) {
			try_alloc = false;
		} else {
			if (alloc_size > min_size)
				alloc_size = MAX(min_size, alloc_size / 2);
			else
				try_alloc = false;
		}
	}

	cpu_spin_unlock_xrestore(&memlock, exceptions);

out:
	*size = alloc_size;

	return ret;
}

TEE_Result caam_dmaobj_prepare(struct caamdmaobj *input,
			       struct caamdmaobj *output, size_t min_size)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	size_t alloc_input = 0;
	size_t alloc_output = 0;

	if (!input && !output) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	if ((input && !input->priv) || (output && !output->priv)) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	DMAOBJ_TRACE("input=%p - output=%p - min=%zu", input, output, min_size);

	ret = try_allocate_dmabuf_max_size(input, min_size, &alloc_input);
	if (ret)
		goto out;

	ret = try_allocate_dmabuf_max_size(output, min_size, &alloc_output);
	if (ret)
		goto out;

out:
	DMAOBJ_TRACE("Allocation (input %zu, output %zu) returns 0x%" PRIx32,
		     input ? alloc_input : 0, output ? alloc_output : 0,
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
		goto out;
	}

	/*
	 * First build the input SGT/Buffer
	 */
	ret = caam_dmaobj_sgtbuf_build(input, length, off, align);
	if (ret)
		goto out;

	/*
	 * Next build the output SGT/Buffer.
	 * If returned length is not same as input, redo the input
	 * SGT/Buffer with the same length as the output.
	 */
	len = *length;
	ret = caam_dmaobj_sgtbuf_build(output, &len, off, *length);
	if (ret)
		goto out;

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

out:
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
		goto out;
	}

	priv = obj->priv;

	max_length = *length;
	if (priv->dmabuf.allocated && max_length > priv->dmabuf.allocated &&
	    priv->dmabuf.allocated > align)
		max_length = ROUNDDOWN(priv->dmabuf.allocated, align);

	DMAOBJ_TRACE("Prepare SGT/Buffer to do %zu of %zu", max_length,
		     *length);

	/* Find the first DMA buffer to start with */
	TAILQ_FOREACH(entry, &priv->list, link)	{
		if (offset < entry->origbuf.length)
			break;

		offset -= entry->origbuf.length;
	}

	if (!entry) {
		DMAOBJ_TRACE("There is no DMA Object available");
		ret = TEE_ERROR_GENERIC;
		goto out;
	}

	start_entry = entry;
	DMAOBJ_TRACE("Start with %p data %p offset %zu", start_entry,
		     start_entry->origbuf.data, offset);

	acc_length = entry->origbuf.length - offset;
	nb_sgt = 1;

	/* Calculate the number of SGT entry */
	for (entry = TAILQ_NEXT(entry, link); entry && acc_length < max_length;
	     entry = TAILQ_NEXT(entry, link)) {
		acc_length += entry->origbuf.length;
		nb_sgt++;
	}

	DMAOBJ_TRACE("%d of %d SGT/Buffer entries to handle", nb_sgt,
		     priv->nb_sgtbuf);
	if (priv->nb_sgtbuf < nb_sgt) {
		if (priv->nb_sgtbuf) {
			obj->sgtbuf.number = priv->nb_sgtbuf;
			obj->sgtbuf.sgt_type = (priv->nb_sgtbuf > 1);

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
			goto out;
		}

		priv->sgtdata = caam_calloc(nb_sgt * sizeof(*priv->sgtdata));
		if (!priv->sgtdata) {
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto out;
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
	     entry = TAILQ_NEXT(entry, link), idx++) {
		DMAOBJ_TRACE("entry %p (%d)", entry, idx);
		if (entry->nodma_access || entry->newbuf) {
			retstatus = entry_sgtbuf_dmabuf(obj, entry, idx,
							offset);
			if (retstatus != CAAM_NO_ERROR) {
				ret = caam_status_to_tee_result(retstatus);
				goto out;
			}
		} else {
			retstatus = entry_sgtbuf(obj, entry, idx, offset);
			if (retstatus != CAAM_NO_ERROR) {
				ret = caam_status_to_tee_result(retstatus);
				goto out;
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

	*length = obj->sgtbuf.length;
	ret = TEE_SUCCESS;
out:
	DMAOBJ_TRACE("SGTBUF (%zu) returns 0x%" PRIx32, *length, ret);
	return ret;
}
