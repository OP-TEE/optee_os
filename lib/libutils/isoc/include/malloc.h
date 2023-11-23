/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */
#ifndef __MALLOC_H
#define __MALLOC_H

#include <pta_stats.h>
#include <stddef.h>
#include <types_ext.h>

/*
 * Due to bget implementation, the first memory pool registered shall have
 * a min size. Choose 1kB which is reasonable.
 */
#define MALLOC_INITIAL_POOL_MIN_SIZE	1024

void *malloc(size_t size);
void *calloc(size_t nmemb, size_t size);
void *realloc(void *ptr, size_t size);
void *memalign(size_t alignment, size_t size);
void free(void *ptr);

#if __STDC_VERSION__ >= 201112L
void *aligned_alloc(size_t alignment, size_t size);
#endif

#ifdef ENABLE_MDBG

void *mdbg_malloc(const char *fname, int lineno, size_t size);
void *mdbg_calloc(const char *fname, int lineno, size_t nmemb, size_t size);
void *mdbg_realloc(const char *fname, int lineno, void *ptr, size_t size);
void *mdbg_memalign(const char *fname, int lineno, size_t alignment,
		    size_t size);

#if __STDC_VERSION__ >= 201112L
void *mdbg_aligned_alloc(const char *fname, int lineno, size_t alignment,
			 size_t size);
#endif

void mdbg_check(int bufdump);

#define malloc(size)	mdbg_malloc(__FILE__, __LINE__, (size))
#define calloc(nmemb, size) \
		mdbg_calloc(__FILE__, __LINE__, (nmemb), (size))
#define realloc(ptr, size) \
		mdbg_realloc(__FILE__, __LINE__, (ptr), (size))
#define memalign(alignment, size) \
		mdbg_memalign(__FILE__, __LINE__, (alignment), (size))

#if __STDC_VERSION__ >= 201112L
#define aligned_alloc(alignment, size) \
		mdbg_aligned_alloc(__FILE__, __LINE__, (alignment), (size))
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

void nex_free(void *ptr);

#ifdef ENABLE_MDBG

void *nex_mdbg_malloc(const char *fname, int lineno, size_t size);
void *nex_mdbg_calloc(const char *fname, int lineno, size_t nmemb, size_t size);
void *nex_mdbg_realloc(const char *fname, int lineno, void *ptr, size_t size);
void *nex_mdbg_memalign(const char *fname, int lineno, size_t alignment,
			size_t size);

void nex_mdbg_check(int bufdump);

#define nex_malloc(size)	nex_mdbg_malloc(__FILE__, __LINE__, (size))
#define nex_calloc(nmemb, size) \
		nex_mdbg_calloc(__FILE__, __LINE__, (nmemb), (size))
#define nex_realloc(ptr, size) \
		nex_mdbg_realloc(__FILE__, __LINE__, (ptr), (size))
#define nex_memalign(alignment, size) \
		nex_mdbg_memalign(__FILE__, __LINE__, (alignment), (size))

#else /* ENABLE_MDBG */

void *nex_malloc(size_t size);
void *nex_calloc(size_t nmemb, size_t size);
void *nex_realloc(void *ptr, size_t size);
void *nex_memalign(size_t alignment, size_t size);

#define nex_mdbg_check(x)        do { } while (0)

#endif /* ENABLE_MDBG */

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
