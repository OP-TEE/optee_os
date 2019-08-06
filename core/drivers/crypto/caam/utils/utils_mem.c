// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2018-2019 NXP
 *
 * Brief   Memory management utilities.
 *         Primitive to allocate, free memory.
 */
#include <arm.h>
#include <caam_common.h>
#include <caam_utils_mem.h>
#include <mm/core_memprot.h>
#include <mm/tee_mmu.h>
#include <string.h>

/*
 * CAAM Descriptor address alignment
 */
#ifdef ARM64
#define DESC_START_ALIGN (64 / 8)
#else
#define DESC_START_ALIGN (32 / 8)
#endif

/*
 * Check if pointer p is aligned with align
 */
#define IS_PTR_ALIGN(p, align) (((uintptr_t)(p) & ((align) - 1)) == 0)

/*
 * Check if size is aligned with align
 */
#define IS_SIZE_ALIGN(size, align)                                             \
	({                                                                     \
		__typeof__(size) _size = (size);                               \
		__typeof__(size) _sizeup = 0;                                  \
		_sizeup = ROUNDUP(_size, align);                               \
		(_sizeup == _size) ? 1 : 0;                                    \
	})

/*
 * Recalculate the pointer p address to start on a align modulus
 * The p address is round up to the next offset (align modulus)
 */
static inline vaddr_t align_ptr(vaddr_t p, uint32_t align)
{
	return p + ((align - (p % align)) % align);
}

/*
 * Read the system cache line size.
 * Get the value from the ARM system configration register
 */
static uint32_t read_cacheline_size(void)
{
	uint32_t value = 0;
#ifdef ARM64
	value = read_ctr_el0();
#else
	value = read_ctr();
#endif
	value = CTR_WORD_SIZE
		<< ((value >> CTR_DMINLINE_SHIFT) & CTR_DMINLINE_MASK);
	MEM_TRACE("System Cache Line size = %d bytes", value);

	return value;
}

#define MEM_TYPE_ZEROED BIT(0)
#define MEM_TYPE_NORMAL BIT(1)
#define MEM_TYPE_ALIGN BIT(2)

#define MEM_TYPE_DEFAULT (MEM_TYPE_ZEROED | MEM_TYPE_NORMAL)

#define CAAM_MEM_INFO
#ifdef CAAM_MEM_INFO
struct __packed mem_info {
	void *addr;
	size_t size;
	uint8_t type;
};

#define MEM_INFO_SIZE ROUNDUP(sizeof(struct mem_info), sizeof(void *))
#define OF_MEM_INFO(p) (struct mem_info *)((uint8_t *)(p) - MEM_INFO_SIZE)

/*
 * Allocate an area of given size in bytes. Add the memory allocator
 * information in the newly allocated area.
 *
 * @size   Size in bytes to allocate
 * @type   Type of area to allocate (refer to MEM_TYPE_*)
 */
static void *mem_alloc(size_t size, uint8_t type)
{
	struct mem_info *info = NULL;
	vaddr_t ret_addr = 0;
	void *ptr = NULL;
	size_t alloc_size = 0;
	uint32_t cacheline_size = 0;

	MEM_TRACE("alloc %zu bytes of type %d", size, type);

	/*
	 * The mem_info header is added at just before the returned
	 * buffer address
	 *
	 * --------------
	 * |  mem_info  |
	 * --------------
	 * |  Buffer    |
	 * --------------
	 */
	alloc_size = size + MEM_INFO_SIZE;

	if (type & MEM_TYPE_ALIGN) {
		/*
		 * In case of the buffer must be aligned on a cache
		 * ligne, ensure that the size is aligned on a cache line
		 *
		 * Buffer address returned is moved up to a cache start offset,
		 * hence add a cache line if the alloc_size is already aligned
		 * otherwise the total buffer size will be too small
		 */
		cacheline_size = read_cacheline_size();
		alloc_size +=
			(alloc_size == cacheline_size) ? cacheline_size : 0;
		alloc_size += ROUNDUP(alloc_size, cacheline_size);
	}

	ptr = malloc(alloc_size);
	if (!ptr) {
		MEM_TRACE("alloc Error - NULL");
		return NULL;
	}

	if (type & MEM_TYPE_ZEROED)
		memset(ptr, 0, alloc_size);

	/* Calculate the return buffer address */
	ret_addr = (vaddr_t)ptr + MEM_INFO_SIZE;
	if (type & MEM_TYPE_ALIGN)
		ret_addr = align_ptr(ret_addr, cacheline_size);

	/*
	 * Add the mem_info header
	 */
	info = OF_MEM_INFO(ret_addr);
	info->addr = ptr;
	info->size = size;
	info->type = type;

	MEM_TRACE("alloc returned %p -> %p", ptr, (void *)ret_addr);

	return (void *)ret_addr;
}

/*
 * Free allocated area
 *
 * @ptr  area to free
 */
static void mem_free(void *ptr)
{
	struct mem_info *info = NULL;

	if (!ptr)
		return;

	info = OF_MEM_INFO(ptr);
	MEM_TRACE("free %p info %p", ptr, info);
	MEM_TRACE("free @%p - %zu bytes of type %d", info->addr, info->size,
		  info->type);

	free(info->addr);
}
#else
/*
 * Allocate an area of given size in bytes
 *
 * @size   Size in bytes to allocate
 * @type   Type of area to allocate (refer to MEM_TYPE_*)
 */
static inline void *mem_alloc(size_t size, uint8_t type)
{
	void *ptr = NULL;
	size_t alloc_size = size;
	uint32_t cacheline_size = 0;

	MEM_TRACE("alloc (normal) %zu bytes of type %d", size, type);

	if (type & MEM_TYPE_ALIGN) {
		cacheline_size = read_cacheline_size();
		alloc_size += ROUNDUP(alloc_size, cacheline_size);
	}

	ptr = malloc(alloc_size);
	if (!ptr) {
		MEM_TRACE("alloc (normal) Error - NULL");
		return NULL;
	}

	if (type & MEM_TYPE_ZEROED)
		memset(ptr, 0, alloc_size);

	MEM_TRACE("alloc (normal) returned %p", ptr);
	return ptr;
}

/*
 * Free allocated area
 *
 * @ptr  area to free
 */
static inline void mem_free(void *ptr)
{
	if (ptr) {
		MEM_TRACE("free (normal) %p", ptr);
		free(ptr);
	}
}
#endif

/*
 * Allocate normal memory
 *
 * @size  size in bytes of the memory to allocate
 */
void *caam_alloc(size_t size)
{
	return mem_alloc(size, MEM_TYPE_DEFAULT);
}

/*
 * Allocate memory aligned with a cache line
 *
 * @size  size in bytes of the memory to allocate
 */
void *caam_alloc_align(size_t size)
{
	return mem_alloc(size, MEM_TYPE_DEFAULT | MEM_TYPE_ALIGN);
}

/*
 * Free allocated memory
 *
 * @ptr  reference to the object to free
 */
void caam_free(void *ptr)
{
	mem_free(ptr);
}

/*
 * Allocate Job descriptor
 *
 * @nbentries  Number of descriptor entries
 */
uint32_t *caam_alloc_desc(uint8_t nbentries)
{
	return mem_alloc(DESC_SZBYTES(nbentries),
			 MEM_TYPE_DEFAULT | MEM_TYPE_ALIGN);
}

/*
 * Free descriptor
 *
 * @ptr  Reference to the descriptor to free
 */
void caam_free_desc(uint32_t **ptr)
{
	mem_free(*ptr);
	*ptr = NULL;
}

/*
 * Allocate internal driver buffer
 *
 * @size  size in bytes of the memory to allocate
 * @buf   [out] buffer allocated
 */
enum CAAM_Status caam_alloc_buf(struct caambuf *buf, size_t size)
{
	buf->data = caam_alloc(size);

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

/*
 * Allocate internal driver buffer aligned with a cache line
 *
 * @size  size in bytes of the memory to allocate
 * @buf   [out] buffer allocated
 */
enum CAAM_Status caam_alloc_align_buf(struct caambuf *buf, size_t size)
{
	buf->data = caam_alloc_align(size);

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

/*
 * Free internal driver buffer allocated memory
 *
 * @buf   Driver buffer to free
 */
void caam_free_buf(struct caambuf *buf)
{
	if (buf) {
		if (buf->data) {
			MEM_TRACE("FREE 0x%" PRIxPTR, (uintptr_t)buf->data);
			caam_free(buf->data);
			buf->data = NULL;
		}

		buf->length = 0;
		buf->paddr = 0;
		buf->nocache = 0;
	}
}

/*
 * Free data of type struct caamsgtbuf
 *
 * @data    Data sgtbuf to free
 */
void caam_sgtbuf_free(struct caamsgtbuf *data)
{
	if (data->sgt_type)
		caam_free(data->sgt);
	else
		caam_free(data->buf);
}

/*
 * Allocate data of type struct caamsgtbuf
 *
 * @data    [out] Data sgtbuf allocated
 */
enum CAAM_Status caam_sgtbuf_alloc(struct caamsgtbuf *data)
{
	if (!data)
		return CAAM_BAD_PARAM;

	if (data->sgt_type) {
		data->sgt = caam_alloc(data->number * (sizeof(struct caamsgt) +
						       sizeof(struct caambuf)));
		data->buf = (void *)(((uint8_t *)data->sgt) +
				     (data->number * sizeof(struct caamsgt)));
	} else {
		data->buf = caam_alloc(data->number * sizeof(struct caambuf));
		data->sgt = NULL;
	}

	if (!data->buf || (!data->sgt && data->sgt_type)) {
		caam_sgtbuf_free(data);
		return CAAM_OUT_MEMORY;
	}

	return CAAM_NO_ERROR;
}

/*
 * Re-Allocate a buffer if it's not aligned on a cache line and
 * if it's cacheable. If buffer is not cacheable no need to
 * reallocate.
 *
 * @orig  Buffer origin
 * @size  Size in bytes of the buffer
 * @dst   [out] CAAM Buffer object with origin or reallocated buffer
 *
 * Returns:
 * 0    if destination is the same as origin
 * 1    if reallocation of the buffer
 * (-1) if allocation error
 */
int caam_realloc_align(void *orig, struct caambuf *dst, size_t size)
{
	enum teecore_memtypes mtype = MEM_AREA_MAXTYPE;
	uint32_t isCached = false;
	uint32_t cacheline_size = 0;
	struct user_ta_ctx *utc = NULL;

	/*
	 * First check if the buffer is a known memory area mapped
	 * with a type listed in the teecore_memtypes enum.
	 * If not, this is a user area
	 */
	mtype = core_mmu_get_type_by_pa(virt_to_phys(orig));
	if (mtype == MEM_AREA_MAXTYPE) {
		/* User Area, check if cacheable */
		utc = to_user_ta_ctx(tee_mmu_get_ctx());
		isCached = tee_mmu_user_get_cache_attr(utc, orig);
		isCached = (isCached == TEE_MATTR_CACHE_CACHED) ? 1 : 0;
	} else {
		isCached = core_vbuf_is(CORE_MEM_CACHED, orig, size);
	}

	if (isCached) {
		/*
		 * Check if either orig pointer or size are aligned on the
		 * cache line size.
		 * If no, reallocate a buffer aligned on cache line
		 */
		cacheline_size = read_cacheline_size();
		if (!IS_PTR_ALIGN(orig, cacheline_size) ||
		    !IS_SIZE_ALIGN(size, cacheline_size)) {
			if (caam_alloc_align_buf(dst, size) != CAAM_NO_ERROR)
				return (-1);

			return 1;
		}
		dst->nocache = 0;
	} else {
		dst->nocache = 1;
	}

	/*
	 * Build the destination caambuf object indicating that
	 * buffer if not cacheable
	 */
	dst->data = orig;
	dst->paddr = virt_to_phys(dst->data);
	if (!dst->paddr)
		return (-1);

	dst->length = size;

	return 0;
}

/*
 * Copy source data into the block buffer
 *
 * @block  Block buffer information
 * @src    Source to copy
 * @offset Source offset to start
 * @block  [out] Block buffer filled
 */
enum CAAM_Status caam_cpy_block_src(struct caamblock *block,
				    struct caambuf *src, size_t offset)
{
	enum CAAM_Status ret;
	size_t cpy_size;

	/* Check if the temporary buffer is allocted, else allocate it */
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
	cpy_size = MIN(cpy_size, (src->length - offset));

	memcpy(&block->buf.data[block->filled], &src->data[offset], cpy_size);

	block->filled += cpy_size;

	ret = CAAM_NO_ERROR;

end_cpy:
	return ret;
}
