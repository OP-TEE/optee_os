// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2018-2021 NXP
 *
 * Brief   Memory management utilities.
 *         Primitive to allocate, free memory.
 */
#include <arm.h>
#include <caam_common.h>
#include <caam_trace.h>
#include <caam_utils_mem.h>
#include <kernel/cache_helpers.h>
#include <mm/core_memprot.h>
#include <string.h>

/*
 * CAAM Descriptor address alignment
 */
#ifdef ARM64
#define DESC_START_ALIGN	(64 / 8)
#else
#define DESC_START_ALIGN	(32 / 8)
#endif

/*
 * Check if pointer p is aligned with align
 */
#define IS_PTR_ALIGN(p, align)	(((uintptr_t)(p) & ((align) - 1)) == 0)

/*
 * Check if size is aligned with align
 */
#define IS_SIZE_ALIGN(size, align)                                             \
	({                                                                     \
		__typeof__(size) _size = (size);                               \
		__typeof__(size) _sizeup = 0;                                  \
									       \
		_sizeup = ROUNDUP(_size, align);                               \
		(_sizeup == _size) ? 1 : 0;                                    \
	})

#define MEM_TYPE_ZEROED	BIT(0) /* Buffer filled with 0's */
#define MEM_TYPE_ALIGN	BIT(1) /* Address and size aligned on a cache line */

/*
 * Allocate an area of given size in bytes
 *
 * @size   Size in bytes to allocate
 * @type   Type of area to allocate (refer to MEM_TYPE_*)
 */
static void *mem_alloc(size_t size, uint8_t type)
{
	void *ptr = NULL;
	size_t alloc_size = size;

	MEM_TRACE("alloc %zu bytes of type %" PRIu8, size, type);

	if (type & MEM_TYPE_ALIGN) {
		size_t cacheline_size = dcache_get_line_size();

		if (ROUNDUP_OVERFLOW(alloc_size, cacheline_size, &alloc_size))
			return NULL;

		ptr = memalign(cacheline_size, alloc_size);
	} else {
		ptr = malloc(alloc_size);
	}

	if (!ptr) {
		MEM_TRACE("alloc Error - NULL");
		return NULL;
	}

	if (type & MEM_TYPE_ZEROED)
		memset(ptr, 0, alloc_size);

	MEM_TRACE("alloc returned %p", ptr);
	return ptr;
}

/*
 * Free allocated area
 *
 * @ptr  area to free
 */
static void mem_free(void *ptr)
{
	if (ptr) {
		MEM_TRACE("free %p", ptr);
		free(ptr);
	}
}

/*
 * Allocate internal driver buffer aligned with a cache line.
 *
 * @buf   [out] buffer allocated
 * @size  size in bytes of the memory to allocate
 * @type  Type of area to allocate (refer to MEM_TYPE_*)
 */
static enum caam_status mem_alloc_buf(struct caambuf *buf, size_t size,
				      uint8_t type)
{
	buf->data = mem_alloc(size, type);

	if (!buf->data)
		return CAAM_OUT_MEMORY;

	buf->paddr = virt_to_phys(buf->data);
	if (!buf->paddr) {
		caam_free_buf(buf);
		return CAAM_OUT_MEMORY;
	}

	buf->length = size;
	buf->nocache = 0;
	return CAAM_NO_ERROR;
}

void *caam_calloc(size_t size)
{
	return mem_alloc(size, MEM_TYPE_ZEROED);
}

void *caam_calloc_align(size_t size)
{
	return mem_alloc(size, MEM_TYPE_ZEROED | MEM_TYPE_ALIGN);
}

void caam_free(void *ptr)
{
	mem_free(ptr);
}

uint32_t *caam_calloc_desc(uint8_t nbentries)
{
	return mem_alloc(DESC_SZBYTES(nbentries),
			 MEM_TYPE_ZEROED | MEM_TYPE_ALIGN);
}

void caam_free_desc(uint32_t **ptr)
{
	mem_free(*ptr);
	*ptr = NULL;
}

enum caam_status caam_calloc_buf(struct caambuf *buf, size_t size)
{
	return mem_alloc_buf(buf, size, MEM_TYPE_ZEROED);
}

enum caam_status caam_calloc_align_buf(struct caambuf *buf, size_t size)
{
	return mem_alloc_buf(buf, size, MEM_TYPE_ZEROED | MEM_TYPE_ALIGN);
}

enum caam_status caam_alloc_align_buf(struct caambuf *buf, size_t size)
{
	return mem_alloc_buf(buf, size, MEM_TYPE_ALIGN);
}

void caam_free_buf(struct caambuf *buf)
{
	if (buf) {
		if (buf->data) {
			caam_free(buf->data);
			buf->data = NULL;
		}

		buf->length = 0;
		buf->paddr = 0;
		buf->nocache = 0;
	}
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
	if (!data)
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

bool caam_mem_is_cached_buf(void *buf, size_t size)
{
	enum teecore_memtypes mtype = MEM_AREA_MAXTYPE;
	bool is_cached = false;

	/*
	 * First check if the buffer is a known memory area mapped
	 * with a type listed in the teecore_memtypes enum.
	 * If not mapped, this is a User Area and so assume
	 * it cacheable
	 */
	mtype = core_mmu_get_type_by_pa(virt_to_phys(buf));
	if (mtype == MEM_AREA_MAXTYPE)
		is_cached = true;
	else
		is_cached = core_vbuf_is(CORE_MEM_CACHED, buf, size);

	return is_cached;
}

enum caam_status caam_set_or_alloc_align_buf(void *orig, struct caambuf *dst,
					     size_t size, bool *realloc)
{
	uint32_t cacheline_size = 0;
	enum caam_status retstatus = CAAM_FAILURE;

	if (caam_mem_is_cached_buf(orig, size)) {
		/*
		 * Check if either orig pointer or size are aligned on the
		 * cache line size.
		 * If not, reallocate a buffer aligned on cache line.
		 */
		cacheline_size = dcache_get_line_size();
		if (!IS_PTR_ALIGN(orig, cacheline_size) ||
		    !IS_SIZE_ALIGN(size, cacheline_size)) {
			retstatus = caam_alloc_align_buf(dst, size);
			if (retstatus == CAAM_NO_ERROR)
				*realloc = true;

			return retstatus;
		}
		dst->nocache = 0;
	} else {
		dst->nocache = 1;
	}

	dst->data = orig;
	dst->paddr = virt_to_phys(dst->data);
	if (!dst->paddr)
		return CAAM_OUT_MEMORY;

	dst->length = size;

	*realloc = false;
	return CAAM_NO_ERROR;
}

enum caam_status caam_cpy_block_src(struct caamblock *block,
				    struct caambuf *src, size_t offset)
{
	enum caam_status ret = CAAM_FAILURE;
	size_t cpy_size = 0;

	if (!src->data)
		return CAAM_FAILURE;

	/* Check if the temporary buffer is allocated, else allocate it */
	if (!block->buf.data) {
		ret = caam_alloc_align_buf(&block->buf, block->max);
		if (ret != CAAM_NO_ERROR) {
			MEM_TRACE("Allocation Block buffer error");
			goto end_cpy;
		}
	}

	/* Calculate the number of bytes to copy in the block buffer */
	MEM_TRACE("Current buffer is %zu (%zu) bytes", block->filled,
		  block->max);

	cpy_size = block->max - block->filled;
	cpy_size = MIN(cpy_size, src->length - offset);

	memcpy(&block->buf.data[block->filled], &src->data[offset], cpy_size);

	block->filled += cpy_size;

	ret = CAAM_NO_ERROR;

end_cpy:
	return ret;
}

int caam_mem_get_pa_area(struct caambuf *buf, struct caambuf **out_pabufs)
{
	int nb_pa_area = 0;
	size_t len = 0;
	size_t len_tohandle = 0;
	vaddr_t va = 0;
	vaddr_t next_va = 0;
	paddr_t pa = 0;
	paddr_t next_pa = 0;
	struct caambuf *pabufs = NULL;

	MEM_TRACE("Get PA Areas of %p-%zu (out %p)", buf->data, buf->length,
		  out_pabufs);

	if (out_pabufs) {
		/*
		 * Caller asked for the extracted contiguous
		 * physical areas.
		 * Allocate maximum possible small pages
		 */
		if (buf->length > SMALL_PAGE_SIZE) {
			nb_pa_area = buf->length / SMALL_PAGE_SIZE + 1;
			if (buf->length % SMALL_PAGE_SIZE)
				nb_pa_area++;
		} else {
			nb_pa_area = 2;
		}

		pabufs = caam_calloc(nb_pa_area * sizeof(*pabufs));
		if (!pabufs)
			return -1;

		MEM_TRACE("Allocate max %d Physical Areas", nb_pa_area);
	}

	/*
	 * Go thru all the VA space to extract the contiguous
	 * physical areas
	 */
	va = (vaddr_t)buf->data;
	pa = virt_to_phys((void *)va);

	nb_pa_area = 0;
	if (pabufs) {
		pabufs[nb_pa_area].data = (uint8_t *)va;
		pabufs[nb_pa_area].paddr = pa;
		pabufs[nb_pa_area].length = 0;
		pabufs[nb_pa_area].nocache = buf->nocache;
		MEM_TRACE("Add %d PA 0x%" PRIxPA " VA 0x%" PRIxVA, nb_pa_area,
			  pa, va);
	}

	for (len = buf->length; len; len -= len_tohandle) {
		len_tohandle =
			MIN(SMALL_PAGE_SIZE - (va & SMALL_PAGE_MASK), len);
		next_va = va + len_tohandle;
		next_pa = virt_to_phys((void *)next_va);

		if (pabufs)
			pabufs[nb_pa_area].length += len_tohandle;

		if (next_pa != (pa + len_tohandle)) {
			nb_pa_area++;
			if (pabufs) {
				pabufs[nb_pa_area].data = (uint8_t *)next_va;
				pabufs[nb_pa_area].paddr = next_pa;
				pabufs[nb_pa_area].length = 0;
				pabufs[nb_pa_area].nocache = buf->nocache;
			}
			MEM_TRACE("Add %d PA 0x%" PRIxPA " VA 0x%" PRIxVA,
				  nb_pa_area, next_pa, next_va);
		}

		va = next_va;
		pa = next_pa;
	}

	if (out_pabufs)
		*out_pabufs = pabufs;

	MEM_TRACE("Nb Physical Area %d", nb_pa_area + 1);
	return nb_pa_area + 1;
}

void caam_mem_cpy_ltrim_buf(struct caambuf *dst, struct caambuf *src)
{
	size_t offset = 0;
	size_t cpy_size = 0;

	/* Calculate the offset to start the copy */
	while (!src->data[offset] && offset < src->length)
		offset++;

	if (offset >= src->length)
		offset = src->length - 1;

	cpy_size = MIN(dst->length, (src->length - offset));
	MEM_TRACE("Copy %zu of src %zu bytes (offset = %zu)", cpy_size,
		  src->length, offset);
	memcpy(dst->data, &src->data[offset], cpy_size);

	dst->length = cpy_size;
}
