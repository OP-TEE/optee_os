// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018-2019 NXP
 *
 * @file    utils_mem.c
 *
 * @brief   Memory management utilities.\n
 *          Primitive to allocate, free memory.
 */

/* Global includes */
#include <arm.h>
#include <malloc.h>
#include <mm/core_memprot.h>
#include <mm/tee_mmu.h>
#include <string.h>

/* Local includes */
#include "caam_common.h"

/* Utils includes */
#include "utils_mem.h"

/**
 * @brief   Definition of some armv7 Cache Size Register fields
 */
#define CCSIDR_LINESIZE_SHIFT	0
#define CCSIDR_LINESIZE_MASK	0x7

/**
 * @brief   CAAM Descriptor address alignment
 */
#ifdef ARM64
#define DESC_START_ALIGN	(64 / 8)
#else
#define DESC_START_ALIGN	(32 / 8)
#endif

/**
 * @brief   Check if pointer \a p is aligned with \a align
 */
#define IS_PTR_ALIGN(p, align)	(((uintptr_t)(p) & (align - 1)) == 0)

/**
 * @brief   Check if size \a size is aligned with \a align
 */
#define IS_SIZE_ALIGN(size, align)	(ROUNDUP(size, align) == size)

/**
 * @brief   Align the pointer \a p to be align with \a align modulus
 */
#define PTR_ALIGN(p, align)	(p + ((align - (p % align)) % align))

/**
 * @brief   Cache line size in bytes
 */
static uint16_t cacheline_size;

/**
 * @brief   Read the system cache line size.\n
 *          Get the value from the ARM system configration register
 */
static void read_cacheline_size(void)
{
	uint32_t value;

#ifdef ARM64
	asm volatile ("mrs %0, ctr_el0" : "=r" (value));
	cacheline_size = 4 << ((value >> CTR_DMINLINE_SHIFT)
						& CTR_DMINLINE_MASK);
#else
	asm volatile ("mrc p15, 1, %0, c0, c0, 0" : "=r" (value));
	cacheline_size = 4 << (((value >> CCSIDR_LINESIZE_SHIFT)
						& CCSIDR_LINESIZE_MASK) + 2);
#endif
	MEM_TRACE("System Cache Line size = %d bytes", cacheline_size);
}

#define MEM_TYPE_ZEROED BIT(0)
#define MEM_TYPE_NORMAL BIT(1)
#define MEM_TYPE_ALIGN  BIT(2)

#define MEM_TYPE_DEFAULT	(MEM_TYPE_ZEROED | MEM_TYPE_NORMAL)

#define CAAM_MEM_INFO
#ifdef CAAM_MEM_INFO
struct __packed mem_info {
	void    *addr;
	size_t  size;
	uint8_t type;
};

#define MEM_INFO_SIZE	ROUNDUP(sizeof(struct mem_info), sizeof(void *))
#define OF_MEM_INFO(p)	(struct mem_info *)((uint8_t *)p - MEM_INFO_SIZE)

static void *mem_alloc(size_t size, uint8_t type)
{
	struct mem_info *info;
	vaddr_t         ret_addr;
	void            *ptr;
	size_t          alloc_size;

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
		alloc_size += (alloc_size == cacheline_size) ?
		    cacheline_size : 0;
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
		ret_addr = PTR_ALIGN(ret_addr, cacheline_size);

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

static void mem_free(void *ptr)
{
	struct mem_info *info;

	if (!ptr)
		return;

	info = OF_MEM_INFO(ptr);
	MEM_TRACE("free %p info %p", ptr, info);
	MEM_TRACE("free @%p - %zu bytes of type %d",
			info->addr, info->size, info->type);

	free(info->addr);
}
#else
static inline void *mem_alloc(size_t size, uint8_t type)
{
	void   *ptr;
	size_t alloc_size = size;

	MEM_TRACE("alloc (normal) %zu bytes of type %d", size, type);

	if (type & MEM_TYPE_ALIGN)
		alloc_size += ROUNDUP(alloc_size, cacheline_size);

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

static inline void mem_free(void *ptr)
{
	if (ptr) {
		MEM_TRACE("free (normal) %p", ptr);
		free(ptr);
	}
}
#endif

/**
 * @brief   Allocate normal memory and initialize it with 0s
 *
 * @param[in] size  size in bytes of the memory to allocate
 *
 * @retval  address of the memory block allocated
 * @retval  NULL if allocation error
 */
void *caam_alloc(size_t size)
{
	return mem_alloc(size, MEM_TYPE_DEFAULT);
}

/**
 * @brief   Allocate memory aligned with a cache line and initialize it
 *          with 0s
 *
 * @param[in] size  size in bytes of the memory to allocate
 *
 * @retval  address of the memory block allocated
 * @retval  NULL if allocation error
 */
void *caam_alloc_align(size_t size)
{
	return mem_alloc(size, MEM_TYPE_DEFAULT | MEM_TYPE_ALIGN);
}

/**
 * @brief   Free allocated memory
 *
 * @param[in] ptr  reference to the object to free
 *
 */
void caam_free(void *ptr)
{
	mem_free(ptr);
}

/**
 * @brief   Allocate Job descriptor and initialize it with 0s
 *
 * @param[in] nbEntries  Number of descriptor entries
 *
 * @retval  address of the memory block allocated
 * @retval  NULL if allocation error
 */
descPointer_t caam_alloc_desc(uint8_t nbEntries)
{
	return mem_alloc(DESC_SZBYTES(nbEntries),
			MEM_TYPE_DEFAULT | MEM_TYPE_ALIGN);
}

/**
 * @brief   Free descriptor
 *
 * @param[in] ptr  Reference to the descriptor to free
 *
 */
void caam_free_desc(descPointer_t *ptr)
{
	mem_free(*ptr);
	*ptr = NULL;
}

/**
 * @brief   Allocate internal driver buffer and initialize it with 0s
 *
 * @param[in/out] buf   buffer to allocate
 * @param[in]     size  size in bytes of the memory to allocate
 *
 * @retval  CAAM_NO_ERROR		Success
 * @retval  CAAM_OUT_MEMORY		Allocation error
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

	buf->length  = size;
	buf->nocache = 0;
	return CAAM_NO_ERROR;
}

/**
 * @brief   Allocate internal driver buffer aligned with a cache line
 *          and initialize it with 0s
 *
 * @param[in/out] buf   buffer to allocate
 * @param[in]     size  size in bytes of the memory to allocate
 *
 * @retval  CAAM_NO_ERROR		Success
 * @retval  CAAM_OUT_MEMORY		Allocation error
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

	buf->length  = size;
	buf->nocache = 0;
	return CAAM_NO_ERROR;
}

/**
 * @brief   Free internal driver buffer allocated memory
 *
 * @param[in/out] buf   buffer to free
 *
 */
void caam_free_buf(struct caambuf *buf)
{
	if (buf) {
		if (buf->data) {
			MEM_TRACE("FREE 0x%"PRIxPTR"", (uintptr_t)buf->data);
			caam_free(buf->data);
			buf->data = NULL;
		}

		buf->length  = 0;
		buf->paddr   = 0;
		buf->nocache = 0;
	}
}

/**
 * @brief   Free data of type struct sgtbuf
 *
 * @parm[in/out] data    Data sgtbuf to free
 */
void caam_sgtbuf_free(struct sgtbuf *data)
{
	if (data->sgt_type)
		caam_free(data->sgt);
	else
		caam_free(data->buf);
}

/**
 * @brief   Allocate data of type struct sgtbuf
 *
 * @parm[in/out] data    Data sgtbuf to fill
 *
 * @retval CAAM_NO_ERROR    Success
 * @retval CAAM_OUT_MEMORY  Allocation error
 * @retval CAAM_BAD_PARAM   Bad parameters
 */
enum CAAM_Status caam_sgtbuf_alloc(struct sgtbuf *data)
{
	if (!data)
		return CAAM_BAD_PARAM;

	if (data->sgt_type) {
		data->sgt = caam_alloc(data->number *
				(sizeof(struct sgt) + sizeof(struct caambuf)));
		data->buf = (void *)(((uint8_t *)data->sgt) +
				(data->number * sizeof(struct sgt)));
	} else {
		data->buf = caam_alloc(data->number * sizeof(struct caambuf));
		data->sgt = NULL;
	}

	if ((!data->buf) || ((!data->sgt) && (data->sgt_type))) {
		caam_sgtbuf_free(data);
		return CAAM_OUT_MEMORY;
	}

	return CAAM_NO_ERROR;
}

/**
 * @brief   Re-Allocate a buffer if it's not align on a cache line and
 *          if it's cacheable. If buffer is not cacheable no need to
 *          reallocate.
 *
 * @param[in]  orig  Buffer origin
 * @param[out] dst   CAAM Buffer object with origin or reallocated buffer
 * @param[in]  size  Size in bytes of the buffer
 *
 * @retval  0    if destination is the same as origin
 * @retval  1    if reallocation of the buffer
 * @retval  (-1) if allocation error
 */
int caam_realloc_align(void *orig, struct caambuf *dst, size_t size)
{
	enum teecore_memtypes mtype;
	uint32_t isCached;

	/*
	 * First check if the buffer is a known memory area mapped
	 * with a type listed in the teecore_memtypes enum.
	 * If not, this is a user area
	 */
	mtype = core_mmu_get_type_by_pa(virt_to_phys(orig));
	if (mtype == MEM_AREA_MAXTYPE) {
		/* User Area, check if cacheable */
		isCached = tee_mmu_user_get_cache_attr(
				to_user_ta_ctx(tee_mmu_get_ctx()), orig);
		isCached = (isCached ==	TEE_MATTR_CACHE_CACHED) ? 1 : 0;
	} else
		isCached = core_vbuf_is(CORE_MEM_CACHED, orig, size);

	if (isCached) {
		/*
		 * Check if either orig pointer or size are aligned on the
		 * cache line size.
		 * If no, reallocate a buffer aligned on cache line
		 */
		if (!IS_PTR_ALIGN(orig, cacheline_size) ||
			!IS_SIZE_ALIGN(size, cacheline_size)) {
			if (caam_alloc_align_buf(dst, size) != CAAM_NO_ERROR)
				return (-1);

			return 1;
		}
		dst->nocache = 0;
	} else
		dst->nocache = 1;

	/*
	 * Build the destination caambuf object indicating that
	 * buffer if not cacheable
	 */
	dst->data  = orig;
	dst->paddr = virt_to_phys(dst->data);
	if (!dst->paddr)
		return (-1);

	dst->length  = size;

	return 0;
}

#ifdef CFG_CRYPTO_DRIVER
/**
 * @brief   Copy source data into the block buffer
 *
 * @param[in/out] block  Block buffer
 * @param[in]     src    Source to copy
 * @param[in]     offset Source offset to start
 *
 * @retval CAAM_NO_ERROR       Success
 * @retval CAAM_OUT_MEMORY     Out of memory
 */
enum CAAM_Status caam_cpy_block_src(struct caamblock *block,
				struct drvcrypt_buf *src,
				size_t offset)
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
	MEM_TRACE("Current buffer is %d (%d) bytes", block->filled, block->max);

	cpy_size = block->max - block->filled;
	cpy_size = MIN(cpy_size, (src->length - offset));

	memcpy(&block->buf.data[block->filled], &src->data[offset], cpy_size);

	block->filled += cpy_size;

	ret = CAAM_NO_ERROR;

end_cpy:
	return ret;
}

/**
 * @brief   Copy source data into the destination buffer
 *          removing non-significant first zeros (left zeros)
 *          If all src buffer is zero, left only one zero in the
 *          destination.
 *
 * @param[in/out] dst    Destination buffer
 * @param[in]     src    Source to copy
 */
void caam_cpy_ltrim_buf(struct drvcrypt_buf *dst,
				struct caambuf *src)
{
	size_t offset = 0;
	size_t cpy_size;

	/* Calculate the offset to start the copy */
	while ((src->data[offset] == 0) && (offset < src->length))
		offset++;

	if (offset >= src->length)
		offset = src->length - 1;

	cpy_size = MIN(dst->length, (src->length - offset));
	MEM_TRACE("Copy %d of src %d bytes (offset = %d)",
			cpy_size, src->length, offset);
	memcpy(dst->data, &src->data[offset], cpy_size);

	dst->length = cpy_size;
}

#endif

/**
 * @brief   Memory utilities initialization
 *
 * @retval  CAAM_NO_ERROR   Success
 */
enum CAAM_Status caam_mem_init(void)
{
	read_cacheline_size();

	return CAAM_NO_ERROR;
}

