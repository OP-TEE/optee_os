// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2022, Linaro Limited.
 */

#define PROTOTYPES

/*
 *  BGET CONFIGURATION
 *  ==================
 */
/* #define BGET_ENABLE_ALL_OPTIONS */
#ifdef BGET_ENABLE_OPTION
#define TestProg    20000	/* Generate built-in test program
				   if defined.  The value specifies
				   how many buffer allocation attempts
				   the test program should make. */
#endif


#ifdef __LP64__
#define SizeQuant   16
#endif
#ifdef __ILP32__
#define SizeQuant   8
#endif
				/* Buffer allocation size quantum:
				   all buffers allocated are a
				   multiple of this size.  This
				   MUST be a power of two. */

#ifdef BGET_ENABLE_OPTION
#define BufDump     1		/* Define this symbol to enable the
				   bpoold() function which dumps the
				   buffers in a buffer pool. */

#define BufValid    1		/* Define this symbol to enable the
				   bpoolv() function for validating
				   a buffer pool. */

#define DumpData    1		/* Define this symbol to enable the
				   bufdump() function which allows
				   dumping the contents of an allocated
				   or free buffer. */

#define BufStats    1		/* Define this symbol to enable the
				   bstats() function which calculates
				   the total free space in the buffer
				   pool, the largest available
				   buffer, and the total space
				   currently allocated. */

#define FreeWipe    1		/* Wipe free buffers to a guaranteed
				   pattern of garbage to trip up
				   miscreants who attempt to use
				   pointers into released buffers. */

#define BestFit     1		/* Use a best fit algorithm when
				   searching for space for an
				   allocation request.  This uses
				   memory more efficiently, but
				   allocation will be much slower. */

#define BECtl       1		/* Define this symbol to enable the
				   bectl() function for automatic
				   pool space control.  */
#endif

#ifdef MEM_DEBUG
#undef NDEBUG
#define DumpData    1
#define BufValid    1
#define FreeWipe    1
#endif

#ifdef CFG_WITH_STATS
#define BufStats    1
#endif

#include <compiler.h>
#include <config.h>
#include <malloc.h>
#include <memtag.h>
#include <pta_stats.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib_ext.h>
#include <stdlib.h>
#include <string.h>
#include <trace.h>
#include <util.h>

#if defined(__KERNEL__)
/* Compiling for TEE Core */
#include <kernel/asan.h>
#include <kernel/spinlock.h>
#include <kernel/unwind.h>

static void *memset_unchecked(void *s, int c, size_t n)
{
	return asan_memset_unchecked(s, c, n);
}

static __maybe_unused void *memcpy_unchecked(void *dst, const void *src,
					     size_t n)
{
	return asan_memcpy_unchecked(dst, src, n);
}

#else /*__KERNEL__*/
/* Compiling for TA */

static void *memset_unchecked(void *s, int c, size_t n)
{
	return memset(s, c, n);
}

static __maybe_unused void *memcpy_unchecked(void *dst, const void *src,
					     size_t n)
{
	return memcpy(dst, src, n);
}

#endif /*__KERNEL__*/

#include "bget.c"		/* this is ugly, but this is bget */

struct malloc_pool {
	void *buf;
	size_t len;
};

struct malloc_ctx {
	struct bpoolset poolset;
	struct malloc_pool *pool;
	size_t pool_len;
#ifdef BufStats
	struct pta_stats_alloc mstats;
#endif
#ifdef __KERNEL__
	unsigned int spinlock;
#endif
};

#ifdef __KERNEL__

static uint32_t malloc_lock(struct malloc_ctx *ctx)
{
	return cpu_spin_lock_xsave(&ctx->spinlock);
}

static void malloc_unlock(struct malloc_ctx *ctx, uint32_t exceptions)
{
	cpu_spin_unlock_xrestore(&ctx->spinlock, exceptions);
}

#else  /* __KERNEL__ */

static uint32_t malloc_lock(struct malloc_ctx *ctx __unused)
{
	return 0;
}

static void malloc_unlock(struct malloc_ctx *ctx __unused,
			  uint32_t exceptions __unused)
{
}

#endif	/* __KERNEL__ */

#define DEFINE_CTX(name) struct malloc_ctx name =		\
	{ .poolset = { .freelist = { {0, 0},			\
			{&name.poolset.freelist,		\
			 &name.poolset.freelist}}}}

static DEFINE_CTX(malloc_ctx);

#ifdef CFG_NS_VIRTUALIZATION
static __nex_data DEFINE_CTX(nex_malloc_ctx);
#endif

static void print_oom(size_t req_size __maybe_unused, void *ctx __maybe_unused)
{
#if defined(__KERNEL__) && defined(CFG_CORE_DUMP_OOM)
	EMSG("Memory allocation failed: size %zu context %p", req_size, ctx);
	print_kernel_stack();
#endif
}

/* Most of the stuff in this function is copied from bgetr() in bget.c */
static __maybe_unused bufsize bget_buf_size(void *buf)
{
	bufsize osize;          /* Old size of buffer */
	struct bhead *b;

	b = BH(((char *)buf) - sizeof(struct bhead));
	osize = -b->bsize;
#ifdef BECtl
	if (osize == 0) {
		/*  Buffer acquired directly through acqfcn. */
		struct bdhead *bd;

		bd = BDH(((char *)buf) - sizeof(struct bdhead));
		osize = bd->tsize - sizeof(struct bdhead) - bd->offs;
	} else
#endif
		osize -= sizeof(struct bhead);
	assert(osize > 0);
	return osize;
}

static void *maybe_tag_buf(uint8_t *buf, size_t hdr_size, size_t requested_size)
{
	if (!buf)
		return NULL;

	COMPILE_TIME_ASSERT(MEMTAG_GRANULE_SIZE <= SizeQuant);

	if (MEMTAG_IS_ENABLED) {
		size_t sz = ROUNDUP(requested_size, MEMTAG_GRANULE_SIZE);

		/*
		 * Allocated buffer can be larger than requested when
		 * allocating with memalign(), but we should never tag more
		 * than allocated.
		 */
		assert(bget_buf_size(buf) >= sz + hdr_size);
		return memtag_set_random_tags(buf, sz + hdr_size);
	}

#if defined(__KERNEL__)
	if (IS_ENABLED(CFG_CORE_SANITIZE_KADDRESS))
		asan_tag_access(buf, buf + hdr_size + requested_size);
#endif
	return buf;
}

static void *maybe_untag_buf(void *buf)
{
	if (!buf)
		return NULL;

	if (MEMTAG_IS_ENABLED) {
		size_t sz = 0;

		memtag_assert_tag(buf); /* Trying to catch double free early */
		sz = bget_buf_size(memtag_strip_tag(buf));
		return memtag_set_tags(buf, sz, 0);
	}

#if defined(__KERNEL__)
	if (IS_ENABLED(CFG_CORE_SANITIZE_KADDRESS))
		asan_tag_heap_free(buf, (uint8_t *)buf + bget_buf_size(buf));
#endif
	return buf;
}

static void *strip_tag(void *buf)
{
	if (MEMTAG_IS_ENABLED)
		return memtag_strip_tag(buf);
	return buf;
}

static void tag_asan_free(void *buf __maybe_unused, size_t len __maybe_unused)
{
#if defined(__KERNEL__)
	asan_tag_heap_free(buf, (uint8_t *)buf + len);
#endif
}

#ifdef BufStats

static void *raw_malloc_return_hook(void *p, size_t hdr_size,
				    size_t requested_size,
				    struct malloc_ctx *ctx)
{
	if (ctx->poolset.totalloc > ctx->mstats.max_allocated)
		ctx->mstats.max_allocated = ctx->poolset.totalloc;

	if (!p) {
		ctx->mstats.num_alloc_fail++;
		print_oom(requested_size, ctx);
		if (requested_size > ctx->mstats.biggest_alloc_fail) {
			ctx->mstats.biggest_alloc_fail = requested_size;
			ctx->mstats.biggest_alloc_fail_used =
				ctx->poolset.totalloc;
		}
	}

	return maybe_tag_buf(p, hdr_size, MAX(SizeQuant, requested_size));
}

static void gen_malloc_reset_stats(struct malloc_ctx *ctx)
{
	uint32_t exceptions = malloc_lock(ctx);

	ctx->mstats.max_allocated = 0;
	ctx->mstats.num_alloc_fail = 0;
	ctx->mstats.biggest_alloc_fail = 0;
	ctx->mstats.biggest_alloc_fail_used = 0;
	malloc_unlock(ctx, exceptions);
}

void malloc_reset_stats(void)
{
	gen_malloc_reset_stats(&malloc_ctx);
}

static void gen_malloc_get_stats(struct malloc_ctx *ctx,
				 struct pta_stats_alloc *stats)
{
	uint32_t exceptions = malloc_lock(ctx);

	raw_malloc_get_stats(ctx, stats);
	malloc_unlock(ctx, exceptions);
}

void malloc_get_stats(struct pta_stats_alloc *stats)
{
	gen_malloc_get_stats(&malloc_ctx, stats);
}

#else /* BufStats */

static void *raw_malloc_return_hook(void *p, size_t hdr_size,
				    size_t requested_size,
				    struct malloc_ctx *ctx )
{
	if (!p)
		print_oom(requested_size, ctx);

	return maybe_tag_buf(p, hdr_size, MAX(SizeQuant, requested_size));
}

#endif /* BufStats */

#ifdef BufValid
static void raw_malloc_validate_pools(struct malloc_ctx *ctx)
{
	size_t n;

	for (n = 0; n < ctx->pool_len; n++)
		bpoolv(ctx->pool[n].buf);
}
#else
static void raw_malloc_validate_pools(struct malloc_ctx *ctx __unused)
{
}
#endif

struct bpool_iterator {
	struct bfhead *next_buf;
	size_t pool_idx;
};

static void bpool_foreach_iterator_init(struct malloc_ctx *ctx,
					struct bpool_iterator *iterator)
{
	iterator->pool_idx = 0;
	iterator->next_buf = BFH(ctx->pool[0].buf);
}

static bool bpool_foreach_pool(struct bpool_iterator *iterator, void **buf,
		size_t *len, bool *isfree)
{
	struct bfhead *b = iterator->next_buf;
	bufsize bs = b->bh.bsize;

	if (bs == ESent)
		return false;

	if (bs < 0) {
		/* Allocated buffer */
		bs = -bs;

		*isfree = false;
	} else {
		/* Free Buffer */
		*isfree = true;

		/* Assert that the free list links are intact */
		assert(b->ql.blink->ql.flink == b);
		assert(b->ql.flink->ql.blink == b);
	}

	*buf = (uint8_t *)b + sizeof(struct bhead);
	*len = bs - sizeof(struct bhead);

	iterator->next_buf = BFH((uint8_t *)b + bs);
	return true;
}

static bool bpool_foreach(struct malloc_ctx *ctx,
			  struct bpool_iterator *iterator, void **buf)
{
	while (true) {
		size_t len;
		bool isfree;

		if (bpool_foreach_pool(iterator, buf, &len, &isfree)) {
			if (isfree)
				continue;
			return true;
		}

		if ((iterator->pool_idx + 1) >= ctx->pool_len)
			return false;

		iterator->pool_idx++;
		iterator->next_buf = BFH(ctx->pool[iterator->pool_idx].buf);
	}
}

/* Convenience macro for looping over all allocated buffers */
#define BPOOL_FOREACH(ctx, iterator, bp)		      \
	for (bpool_foreach_iterator_init((ctx),(iterator));   \
	     bpool_foreach((ctx),(iterator), (bp));)

void *raw_memalign(size_t hdr_size, size_t ftr_size, size_t alignment,
		   size_t pl_size, struct malloc_ctx *ctx)
{
	void *ptr = NULL;
	bufsize s;

	if (!alignment || !IS_POWER_OF_TWO(alignment))
		return NULL;

	raw_malloc_validate_pools(ctx);

	/* Compute total size, excluding the header */
	if (ADD_OVERFLOW(pl_size, ftr_size, &s))
		goto out;

	/* BGET doesn't like 0 sized allocations */
	if (!s)
		s++;

	ptr = bget(alignment, hdr_size, s, &ctx->poolset);
out:
	return raw_malloc_return_hook(ptr, hdr_size, pl_size, ctx);
}

void *raw_malloc(size_t hdr_size, size_t ftr_size, size_t pl_size,
		 struct malloc_ctx *ctx)
{
	/*
	 * Note that we're feeding SizeQ as alignment, this is the smallest
	 * alignment that bget() can use.
	 */
	return raw_memalign(hdr_size, ftr_size, SizeQ, pl_size, ctx);
}

void raw_free(void *ptr, struct malloc_ctx *ctx, bool wipe)
{
	raw_malloc_validate_pools(ctx);

	if (ptr)
		brel(maybe_untag_buf(ptr), &ctx->poolset, wipe);
}

void *raw_calloc(size_t hdr_size, size_t ftr_size, size_t pl_nmemb,
		 size_t pl_size, struct malloc_ctx *ctx)
{
	void *ptr = NULL;
	bufsize s;

	raw_malloc_validate_pools(ctx);

	/* Compute total size, excluding hdr_size */
	if (MUL_OVERFLOW(pl_nmemb, pl_size, &s))
		goto out;
	if (ADD_OVERFLOW(s, ftr_size, &s))
		goto out;

	/* BGET doesn't like 0 sized allocations */
	if (!s)
		s++;

	ptr = bgetz(0, hdr_size, s, &ctx->poolset);
out:
	return raw_malloc_return_hook(ptr, hdr_size, pl_nmemb * pl_size, ctx);
}

void *raw_realloc(void *ptr, size_t hdr_size, size_t ftr_size,
		  size_t pl_size, struct malloc_ctx *ctx)
{
	void *p = NULL;
	bufsize s;

	/* Compute total size */
	if (ADD_OVERFLOW(pl_size, hdr_size, &s))
		goto out;
	if (ADD_OVERFLOW(s, ftr_size, &s))
		goto out;

	raw_malloc_validate_pools(ctx);

	/* BGET doesn't like 0 sized allocations */
	if (!s)
		s++;

	p = bget(0, 0, s, &ctx->poolset);

	if (p && ptr) {
		void *old_ptr = maybe_untag_buf(ptr);
		bufsize old_sz = bget_buf_size(old_ptr);

		if (old_sz < s) {
			memcpy_unchecked(p, old_ptr, old_sz);
#ifndef __KERNEL__
			/* User space reallocations are always zeroed */
			memset_unchecked((uint8_t *)p + old_sz, 0, s - old_sz);
#endif
		} else {
			memcpy_unchecked(p, old_ptr, s);
		}

		brel(old_ptr, &ctx->poolset, false /*!wipe*/);
	}
out:
	return raw_malloc_return_hook(p, hdr_size, pl_size, ctx);
}

#ifdef ENABLE_MDBG

struct mdbg_hdr {
	const char *fname;
	uint16_t line;
	uint32_t pl_size;
	uint32_t magic;
#if defined(ARM64)
	uint64_t pad;
#endif
};

#define MDBG_HEADER_MAGIC	0xadadadad
#define MDBG_FOOTER_MAGIC	0xecececec

static size_t mdbg_get_ftr_size(size_t pl_size)
{
	size_t ftr_pad = ROUNDUP(pl_size, sizeof(uint32_t)) - pl_size;

	return ftr_pad + sizeof(uint32_t);
}

static uint32_t *mdbg_get_footer(struct mdbg_hdr *hdr)
{
	uint32_t *footer;

	footer = (uint32_t *)((uint8_t *)(hdr + 1) + hdr->pl_size +
			      mdbg_get_ftr_size(hdr->pl_size));
	footer--;
	return strip_tag(footer);
}

static void mdbg_update_hdr(struct mdbg_hdr *hdr, const char *fname,
		int lineno, size_t pl_size)
{
	uint32_t *footer;

	hdr->fname = fname;
	hdr->line = lineno;
	hdr->pl_size = pl_size;
	hdr->magic = MDBG_HEADER_MAGIC;

	footer = mdbg_get_footer(hdr);
	*footer = MDBG_FOOTER_MAGIC;
}

static void *gen_mdbg_malloc(struct malloc_ctx *ctx, const char *fname,
			     int lineno, size_t size)
{
	struct mdbg_hdr *hdr;
	uint32_t exceptions = malloc_lock(ctx);

	/*
	 * Check struct mdbg_hdr works with BGET_HDR_QUANTUM.
	 */
	COMPILE_TIME_ASSERT((sizeof(struct mdbg_hdr) % BGET_HDR_QUANTUM) == 0);

	hdr = raw_malloc(sizeof(struct mdbg_hdr),
			 mdbg_get_ftr_size(size), size, ctx);
	if (hdr) {
		mdbg_update_hdr(hdr, fname, lineno, size);
		hdr++;
	}

	malloc_unlock(ctx, exceptions);
	return hdr;
}

static void assert_header(struct mdbg_hdr *hdr __maybe_unused)
{
	assert(hdr->magic == MDBG_HEADER_MAGIC);
	assert(*mdbg_get_footer(hdr) == MDBG_FOOTER_MAGIC);
}

static void gen_mdbg_free(struct malloc_ctx *ctx, void *ptr, bool wipe)
{
	struct mdbg_hdr *hdr = ptr;

	if (hdr) {
		hdr--;
		assert_header(hdr);
		hdr->magic = 0;
		*mdbg_get_footer(hdr) = 0;
		raw_free(hdr, ctx, wipe);
	}
}

static void free_helper(void *ptr, bool wipe)
{
	uint32_t exceptions = malloc_lock(&malloc_ctx);

	gen_mdbg_free(&malloc_ctx, ptr, wipe);
	malloc_unlock(&malloc_ctx, exceptions);
}

static void *gen_mdbg_calloc(struct malloc_ctx *ctx, const char *fname, int lineno,
		      size_t nmemb, size_t size)
{
	struct mdbg_hdr *hdr;
	uint32_t exceptions = malloc_lock(ctx);

	hdr = raw_calloc(sizeof(struct mdbg_hdr),
			  mdbg_get_ftr_size(nmemb * size), nmemb, size,
			  ctx);
	if (hdr) {
		mdbg_update_hdr(hdr, fname, lineno, nmemb * size);
		hdr++;
	}
	malloc_unlock(ctx, exceptions);
	return hdr;
}

static void *gen_mdbg_realloc_unlocked(struct malloc_ctx *ctx, const char *fname,
				       int lineno, void *ptr, size_t size)
{
	struct mdbg_hdr *hdr = ptr;

	if (hdr) {
		hdr--;
		assert_header(hdr);
	}
	hdr = raw_realloc(hdr, sizeof(struct mdbg_hdr),
			   mdbg_get_ftr_size(size), size, ctx);
	if (hdr) {
		mdbg_update_hdr(hdr, fname, lineno, size);
		hdr++;
	}
	return hdr;
}

static void *gen_mdbg_realloc(struct malloc_ctx *ctx, const char *fname,
			      int lineno, void *ptr, size_t size)
{
	void *p;
	uint32_t exceptions = malloc_lock(ctx);

	p = gen_mdbg_realloc_unlocked(ctx, fname, lineno, ptr, size);
	malloc_unlock(ctx, exceptions);
	return p;
}

#define realloc_unlocked(ctx, ptr, size)					\
		gen_mdbg_realloc_unlocked(ctx, __FILE__, __LINE__, (ptr), (size))

static void *gen_mdbg_memalign(struct malloc_ctx *ctx, const char *fname,
			       int lineno, size_t alignment, size_t size)
{
	struct mdbg_hdr *hdr;
	uint32_t exceptions = malloc_lock(ctx);

	hdr = raw_memalign(sizeof(struct mdbg_hdr), mdbg_get_ftr_size(size),
			   alignment, size, ctx);
	if (hdr) {
		mdbg_update_hdr(hdr, fname, lineno, size);
		hdr++;
	}
	malloc_unlock(ctx, exceptions);
	return hdr;
}


static void *get_payload_start_size(void *raw_buf, size_t *size)
{
	struct mdbg_hdr *hdr = raw_buf;

	assert(bget_buf_size(hdr) >= hdr->pl_size);
	*size = hdr->pl_size;
	return hdr + 1;
}

static void gen_mdbg_check(struct malloc_ctx *ctx, int bufdump)
{
	struct bpool_iterator itr;
	void *b;
	uint32_t exceptions = malloc_lock(ctx);

	raw_malloc_validate_pools(ctx);

	BPOOL_FOREACH(ctx, &itr, &b) {
		struct mdbg_hdr *hdr = (struct mdbg_hdr *)b;

		assert_header(hdr);

		if (bufdump > 0) {
			const char *fname = hdr->fname;

			if (!fname)
				fname = "unknown";

			IMSG("buffer: %d bytes %s:%d",
				hdr->pl_size, fname, hdr->line);
		}
	}

	malloc_unlock(ctx, exceptions);
}

void *mdbg_malloc(const char *fname, int lineno, size_t size)
{
	return gen_mdbg_malloc(&malloc_ctx, fname, lineno, size);
}

void *mdbg_calloc(const char *fname, int lineno, size_t nmemb, size_t size)
{
	return gen_mdbg_calloc(&malloc_ctx, fname, lineno, nmemb, size);
}

void *mdbg_realloc(const char *fname, int lineno, void *ptr, size_t size)
{
	return gen_mdbg_realloc(&malloc_ctx, fname, lineno, ptr, size);
}

void *mdbg_memalign(const char *fname, int lineno, size_t alignment,
		    size_t size)
{
	return gen_mdbg_memalign(&malloc_ctx, fname, lineno, alignment, size);
}

#if __STDC_VERSION__ >= 201112L
void *mdbg_aligned_alloc(const char *fname, int lineno, size_t alignment,
			 size_t size)
{
	if (size % alignment)
		return NULL;

	return gen_mdbg_memalign(&malloc_ctx, fname, lineno, alignment, size);
}
#endif /* __STDC_VERSION__ */

void mdbg_check(int bufdump)
{
	gen_mdbg_check(&malloc_ctx, bufdump);
}

/*
 * Since malloc debug is enabled, malloc() and friends are redirected by macros
 * to mdbg_malloc() etc.
 * We still want to export the standard entry points in case they are referenced
 * by the application, either directly or via external libraries.
 */
#undef malloc
void *malloc(size_t size)
{
	return mdbg_malloc(__FILE__, __LINE__, size);
}

#undef calloc
void *calloc(size_t nmemb, size_t size)
{
	return mdbg_calloc(__FILE__, __LINE__, nmemb, size);
}

#undef realloc
void *realloc(void *ptr, size_t size)
{
	return mdbg_realloc(__FILE__, __LINE__, ptr, size);
}

#else /* ENABLE_MDBG */

void *malloc(size_t size)
{
	void *p;
	uint32_t exceptions = malloc_lock(&malloc_ctx);

	p = raw_malloc(0, 0, size, &malloc_ctx);
	malloc_unlock(&malloc_ctx, exceptions);
	return p;
}

static void free_helper(void *ptr, bool wipe)
{
	uint32_t exceptions = malloc_lock(&malloc_ctx);

	raw_free(ptr, &malloc_ctx, wipe);
	malloc_unlock(&malloc_ctx, exceptions);
}

void *calloc(size_t nmemb, size_t size)
{
	void *p;
	uint32_t exceptions = malloc_lock(&malloc_ctx);

	p = raw_calloc(0, 0, nmemb, size, &malloc_ctx);
	malloc_unlock(&malloc_ctx, exceptions);
	return p;
}

static void *realloc_unlocked(struct malloc_ctx *ctx, void *ptr,
			      size_t size)
{
	return raw_realloc(ptr, 0, 0, size, ctx);
}

void *realloc(void *ptr, size_t size)
{
	void *p;
	uint32_t exceptions = malloc_lock(&malloc_ctx);

	p = realloc_unlocked(&malloc_ctx, ptr, size);
	malloc_unlock(&malloc_ctx, exceptions);
	return p;
}

void *memalign(size_t alignment, size_t size)
{
	void *p;
	uint32_t exceptions = malloc_lock(&malloc_ctx);

	p = raw_memalign(0, 0, alignment, size, &malloc_ctx);
	malloc_unlock(&malloc_ctx, exceptions);
	return p;
}

#if __STDC_VERSION__ >= 201112L
void *aligned_alloc(size_t alignment, size_t size)
{
	if (size % alignment)
		return NULL;

	return memalign(alignment, size);
}
#endif /* __STDC_VERSION__ */

static void *get_payload_start_size(void *ptr, size_t *size)
{
	*size = bget_buf_size(ptr);
	return ptr;
}

#endif

void free(void *ptr)
{
	free_helper(ptr, false);
}

void free_wipe(void *ptr)
{
	free_helper(ptr, true);
}

static void gen_malloc_add_pool(struct malloc_ctx *ctx, void *buf, size_t len)
{
	uint32_t exceptions = malloc_lock(ctx);

	raw_malloc_add_pool(ctx, buf, len);
	malloc_unlock(ctx, exceptions);
}

static bool gen_malloc_buffer_is_within_alloced(struct malloc_ctx *ctx,
						void *buf, size_t len)
{
	uint32_t exceptions = malloc_lock(ctx);
	bool ret = false;

	ret = raw_malloc_buffer_is_within_alloced(ctx, buf, len);
	malloc_unlock(ctx, exceptions);

	return ret;
}

static bool gen_malloc_buffer_overlaps_heap(struct malloc_ctx *ctx,
					    void *buf, size_t len)
{
	bool ret = false;
	uint32_t exceptions = malloc_lock(ctx);

	ret = raw_malloc_buffer_overlaps_heap(ctx, buf, len);
	malloc_unlock(ctx, exceptions);
	return ret;
}

size_t raw_malloc_get_ctx_size(void)
{
	return sizeof(struct malloc_ctx);
}

void raw_malloc_init_ctx(struct malloc_ctx *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->poolset.freelist.ql.flink = &ctx->poolset.freelist;
	ctx->poolset.freelist.ql.blink = &ctx->poolset.freelist;
}

void raw_malloc_add_pool(struct malloc_ctx *ctx, void *buf, size_t len)
{
	const size_t min_len = sizeof(struct bhead) + sizeof(struct bfhead);
	uintptr_t start = (uintptr_t)buf;
	uintptr_t end = start + len;
	void *p = NULL;
	size_t l = 0;

	start = ROUNDUP(start, SizeQuant);
	end = ROUNDDOWN(end, SizeQuant);

	if (start > end || (end - start) < min_len) {
		DMSG("Skipping too small pool");
		return;
	}

	/* First pool requires a bigger size */
	if (!ctx->pool_len && (end - start) < MALLOC_INITIAL_POOL_MIN_SIZE) {
		DMSG("Skipping too small initial pool");
		return;
	}

	tag_asan_free((void *)start, end - start);
	bpool((void *)start, end - start, &ctx->poolset);
	l = ctx->pool_len + 1;
	p = realloc_unlocked(ctx, ctx->pool, sizeof(struct malloc_pool) * l);
	assert(p);
	ctx->pool = p;
	ctx->pool[ctx->pool_len].buf = (void *)start;
	ctx->pool[ctx->pool_len].len = end - start;
#ifdef BufStats
	ctx->mstats.size += ctx->pool[ctx->pool_len].len;
#endif
	ctx->pool_len = l;
}

bool raw_malloc_buffer_overlaps_heap(struct malloc_ctx *ctx,
				     void *buf, size_t len)
{
	uintptr_t buf_start = (uintptr_t)strip_tag(buf);
	uintptr_t buf_end = buf_start + len;
	size_t n = 0;

	raw_malloc_validate_pools(ctx);

	for (n = 0; n < ctx->pool_len; n++) {
		uintptr_t pool_start = (uintptr_t)strip_tag(ctx->pool[n].buf);
		uintptr_t pool_end = pool_start + ctx->pool[n].len;

		if (buf_start > buf_end || pool_start > pool_end)
			return true;	/* Wrapping buffers, shouldn't happen */

		if ((buf_start >= pool_start && buf_start < pool_end) ||
		    (buf_end > pool_start && buf_end < pool_end))
			return true;
	}

	return false;
}

bool raw_malloc_buffer_is_within_alloced(struct malloc_ctx *ctx,
					 void *buf, size_t len)
{
	struct bpool_iterator itr = { };
	void *b = NULL;
	uint8_t *start_buf = strip_tag(buf);
	uint8_t *end_buf = start_buf + len;

	raw_malloc_validate_pools(ctx);

	/* Check for wrapping */
	if (start_buf > end_buf)
		return false;

	BPOOL_FOREACH(ctx, &itr, &b) {
		uint8_t *start_b = NULL;
		uint8_t *end_b = NULL;
		size_t s = 0;

		start_b = strip_tag(get_payload_start_size(b, &s));
		end_b = start_b + s;
		if (start_buf >= start_b && end_buf <= end_b)
			return true;
	}

	return false;
}

#ifdef CFG_WITH_STATS
void raw_malloc_get_stats(struct malloc_ctx *ctx, struct pta_stats_alloc *stats)
{
	memcpy_unchecked(stats, &ctx->mstats, sizeof(*stats));
	stats->allocated = ctx->poolset.totalloc;
}
#endif

void malloc_add_pool(void *buf, size_t len)
{
	gen_malloc_add_pool(&malloc_ctx, buf, len);
}

bool malloc_buffer_is_within_alloced(void *buf, size_t len)
{
	return gen_malloc_buffer_is_within_alloced(&malloc_ctx, buf, len);
}

bool malloc_buffer_overlaps_heap(void *buf, size_t len)
{
	return gen_malloc_buffer_overlaps_heap(&malloc_ctx, buf, len);
}

#ifdef CFG_NS_VIRTUALIZATION

#ifndef ENABLE_MDBG

void *nex_malloc(size_t size)
{
	void *p;
	uint32_t exceptions = malloc_lock(&nex_malloc_ctx);

	p = raw_malloc(0, 0, size, &nex_malloc_ctx);
	malloc_unlock(&nex_malloc_ctx, exceptions);
	return p;
}

void *nex_calloc(size_t nmemb, size_t size)
{
	void *p;
	uint32_t exceptions = malloc_lock(&nex_malloc_ctx);

	p = raw_calloc(0, 0, nmemb, size, &nex_malloc_ctx);
	malloc_unlock(&nex_malloc_ctx, exceptions);
	return p;
}

void *nex_realloc(void *ptr, size_t size)
{
	void *p;
	uint32_t exceptions = malloc_lock(&nex_malloc_ctx);

	p = realloc_unlocked(&nex_malloc_ctx, ptr, size);
	malloc_unlock(&nex_malloc_ctx, exceptions);
	return p;
}

void *nex_memalign(size_t alignment, size_t size)
{
	void *p;
	uint32_t exceptions = malloc_lock(&nex_malloc_ctx);

	p = raw_memalign(0, 0, alignment, size, &nex_malloc_ctx);
	malloc_unlock(&nex_malloc_ctx, exceptions);
	return p;
}

void nex_free(void *ptr)
{
	uint32_t exceptions = malloc_lock(&nex_malloc_ctx);

	raw_free(ptr, &nex_malloc_ctx, false /* !wipe */);
	malloc_unlock(&nex_malloc_ctx, exceptions);
}

#else  /* ENABLE_MDBG */

void *nex_mdbg_malloc(const char *fname, int lineno, size_t size)
{
	return gen_mdbg_malloc(&nex_malloc_ctx, fname, lineno, size);
}

void *nex_mdbg_calloc(const char *fname, int lineno, size_t nmemb, size_t size)
{
	return gen_mdbg_calloc(&nex_malloc_ctx, fname, lineno, nmemb, size);
}

void *nex_mdbg_realloc(const char *fname, int lineno, void *ptr, size_t size)
{
	return gen_mdbg_realloc(&nex_malloc_ctx, fname, lineno, ptr, size);
}

void *nex_mdbg_memalign(const char *fname, int lineno, size_t alignment,
		size_t size)
{
	return gen_mdbg_memalign(&nex_malloc_ctx, fname, lineno, alignment, size);
}

void nex_mdbg_check(int bufdump)
{
	gen_mdbg_check(&nex_malloc_ctx, bufdump);
}

void nex_free(void *ptr)
{
	uint32_t exceptions = malloc_lock(&nex_malloc_ctx);

	gen_mdbg_free(&nex_malloc_ctx, ptr, false /* !wipe */);
	malloc_unlock(&nex_malloc_ctx, exceptions);
}

#endif	/* ENABLE_MDBG */

void nex_malloc_add_pool(void *buf, size_t len)
{
	gen_malloc_add_pool(&nex_malloc_ctx, buf, len);
}

bool nex_malloc_buffer_is_within_alloced(void *buf, size_t len)
{
	return gen_malloc_buffer_is_within_alloced(&nex_malloc_ctx, buf, len);
}

bool nex_malloc_buffer_overlaps_heap(void *buf, size_t len)
{
	return gen_malloc_buffer_overlaps_heap(&nex_malloc_ctx, buf, len);
}

#ifdef BufStats

void nex_malloc_reset_stats(void)
{
	gen_malloc_reset_stats(&nex_malloc_ctx);
}

void nex_malloc_get_stats(struct pta_stats_alloc *stats)
{
	gen_malloc_get_stats(&nex_malloc_ctx, stats);
}

#endif

#endif
