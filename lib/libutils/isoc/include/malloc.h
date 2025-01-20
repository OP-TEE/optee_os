/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2015-2025, Linaro Limited.
 */
#ifndef __MALLOC_H
#define __MALLOC_H

#include <malloc_flags.h>
#include <pta_stats.h>
#include <stddef.h>
#include <types_ext.h>

/*
 * Due to bget implementation, the first memory pool registered shall have
 * a min size. Choose 1kB which is reasonable.
 */
#define MALLOC_INITIAL_POOL_MIN_SIZE	1024

#define MALLOC_DEFAULT_ALIGNMENT	(sizeof(long) * 2)

void *malloc(size_t size);
void *malloc_flags(uint32_t flags, void *ptr, size_t alignment, size_t size);
void *calloc(size_t nmemb, size_t size);
void *realloc(void *ptr, size_t size);
void *memalign(size_t alignment, size_t size);
void free(void *ptr);
void free_flags(uint32_t flags, void *ptr);

#if __STDC_VERSION__ >= 201112L
void *aligned_alloc(size_t alignment, size_t size);
#endif

#ifdef ENABLE_MDBG
void *__mdbg_alloc(uint32_t flags, void *ptr, size_t alignment, size_t nmemb,
		   size_t size, const char *fname, int lineno);

void mdbg_check(int bufdump);

#define malloc(size)		__mdbg_alloc(MAF_NULL, NULL, 1, 1, \
					     (size), __FILE__, __LINE__)
#define malloc_flags(flags, ptr, align, size)	\
	__mdbg_alloc((flags), (ptr), (align), 1, (size), __FILE__, __LINE__)
#define calloc(nmemb, size)	__mdbg_alloc(MAF_ZERO_INIT, NULL, 1, (nmemb), \
					     (size), __FILE__, __LINE__)
#define realloc(ptr, size)	__mdbg_alloc(MAF_NULL, (ptr), 1, 1, \
					     (size), __FILE__, __LINE__)
#define memalign(align, size)	__mdbg_alloc(MAF_NULL, NULL, (align), 1, \
					     (size), __FILE__, __LINE__)

#if __STDC_VERSION__ >= 201112L
#define aligned_alloc(align, size) \
	__mdbg_alloc(MAF_NULL, NULL, (align), 1, (size), __FILE__, __LINE__)
#endif /* __STDC_VERSION__ */

#else

#define mdbg_check(x)        do { } while (0)

#endif

/*
 * Returns true if the supplied memory area is within a buffer
 * previously allocated (and not freed yet).
 *
 * Used internally by TAs
 */
bool malloc_buffer_is_within_alloced(void *buf, size_t len);

/*
 * Returns true if the supplied memory area is overlapping the area used
 * for heap.
 *
 * Used internally by TAs
 */
bool malloc_buffer_overlaps_heap(void *buf, size_t len);

/*
 * Adds a pool of memory to allocate from.
 */
void malloc_add_pool(void *buf, size_t len);

#ifdef CFG_WITH_STATS
/* Get/reset allocation statistics */
void malloc_get_stats(struct pta_stats_alloc *stats);
void malloc_reset_stats(void);
#endif /* CFG_WITH_STATS */

#ifdef CFG_NS_VIRTUALIZATION
#ifdef ENABLE_MDBG

void nex_mdbg_check(int bufdump);

#define nex_malloc(size)	__mdbg_alloc(MAF_NEX, NULL, 1, 1, \
					     (size), __FILE__, __LINE__)
#define nex_calloc(nmemb, size)	__mdbg_alloc(MAF_NEX | MAF_ZERO_INIT, NULL, 1, \
					     (nmemb), (size), __FILE__, \
					     __LINE__)
#define nex_realloc(ptr, size)	__mdbg_alloc(MAF_NEX, (ptr), 1, 1, \
					     (size), __FILE__, __LINE__)
#define nex_memalign(align, size) __mdbg_alloc(MAF_NEX, NULL, (align), 1, \
					       (size), __FILE__, __LINE__)
#else /* ENABLE_MDBG */

#define nex_mdbg_check(x)        do { } while (0)

void *nex_malloc(size_t size);
void *nex_calloc(size_t nmemb, size_t size);
void *nex_realloc(void *ptr, size_t size);
void *nex_memalign(size_t alignment, size_t size);

#endif /* ENABLE_MDBG */

void nex_free(void *ptr);

bool nex_malloc_buffer_is_within_alloced(void *buf, size_t len);
bool nex_malloc_buffer_overlaps_heap(void *buf, size_t len);
void nex_malloc_add_pool(void *buf, size_t len);

#ifdef CFG_WITH_STATS
/*
 * Get/reset allocation statistics
 */

void nex_malloc_get_stats(struct pta_stats_alloc *stats);
void nex_malloc_reset_stats(void);

#endif	/* CFG_WITH_STATS */
#else  /* CFG_NS_VIRTUALIZATION */

#define nex_free(ptr) free(ptr)
#define nex_malloc(size) malloc(size)
#define nex_calloc(nmemb, size) calloc(nmemb, size)
#define nex_realloc(ptr, size) realloc(ptr, size)
#define nex_memalign(alignment, size) memalign(alignment, size)
#define nex_malloc_buffer_overlaps_heap(buf, len) \
	malloc_buffer_overlaps_heap(buf, len)
#define nex_malloc_buffer_is_within_alloced(buf, len) \
	malloc_buffer_is_within_alloced(buf, len)

#endif	/* CFG_NS_VIRTUALIZATION */

struct malloc_ctx;
void *raw_memalign(size_t hdr_size, size_t ftr_size, size_t alignment,
		   size_t pl_size, struct malloc_ctx *ctx);
void *raw_malloc(size_t hdr_size, size_t ftr_size, size_t pl_size,
		 struct malloc_ctx *ctx);
void raw_free(void *ptr, struct malloc_ctx *ctx, bool wipe);
void *raw_calloc(size_t hdr_size, size_t ftr_size, size_t pl_nmemb,
		 size_t pl_size, struct malloc_ctx *ctx);
void *raw_realloc(void *ptr, size_t hdr_size, size_t ftr_size,
		  size_t pl_size, struct malloc_ctx *ctx);
size_t raw_malloc_get_ctx_size(void);
void raw_malloc_init_ctx(struct malloc_ctx *ctx);
void raw_malloc_add_pool(struct malloc_ctx *ctx, void *buf, size_t len);
bool raw_malloc_buffer_overlaps_heap(struct malloc_ctx *ctx,
				     void *buf, size_t len);
bool raw_malloc_buffer_is_within_alloced(struct malloc_ctx *ctx,
					 void *buf, size_t len);
#ifdef CFG_WITH_STATS
void raw_malloc_get_stats(struct malloc_ctx *ctx,
			  struct pta_stats_alloc *stats);
#endif

#endif /* __MALLOC_H */
