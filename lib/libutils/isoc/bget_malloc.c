/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
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


#define SizeQuant   8		/* Buffer allocation size quantum:
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

#if defined(CFG_TEE_CORE_DEBUG) && CFG_TEE_CORE_DEBUG != 0
#define BufStats    1
#endif

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <malloc.h>
#include "bget.c"		/* this is ugly, but this is bget */
#include <util.h>

struct malloc_pool {
	void *buf;
	size_t len;
};

static struct malloc_pool *malloc_pool;
static size_t malloc_pool_len;

#ifdef BufStats
static size_t max_alloc_heap;

static void raw_malloc_save_max_alloced_size(void)
{
	if (totalloc > max_alloc_heap)
		max_alloc_heap = totalloc;
}

void malloc_reset_max_allocated(void)
{
	max_alloc_heap = 0;
}

size_t malloc_get_max_allocated(void)
{
	return max_alloc_heap;
}

size_t malloc_get_allocated(void)
{
	return totalloc;
}

#else /* BufStats */

static void raw_malloc_save_max_alloced_size(void)
{
}

void malloc_reset_max_allocated(void)
{
}

size_t malloc_get_max_allocated(void)
{
	return 0;
}

size_t malloc_get_allocated(void)
{
	return 0;
}
#endif /* BufStats */

size_t malloc_get_heap_size(void)
{
	size_t n;
	size_t s = 0;

	for (n = 0; n < malloc_pool_len; n++)
		s += malloc_pool[n].len;

	return s;
}

#ifdef BufValid
static void raw_malloc_validate_pools(void)
{
	size_t n;

	for (n = 0; n < malloc_pool_len; n++)
		bpoolv(malloc_pool[n].buf);
}
#else
static void raw_malloc_validate_pools(void)
{
}
#endif

struct bpool_iterator {
	struct bfhead *next_buf;
	size_t pool_idx;
};

static void bpool_foreach_iterator_init(struct bpool_iterator *iterator)
{
	iterator->pool_idx = 0;
	iterator->next_buf = BFH(malloc_pool[0].buf);
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

static bool bpool_foreach(struct bpool_iterator *iterator, void **buf)
{
	while (true) {
		size_t len;
		bool isfree;

		if (bpool_foreach_pool(iterator, buf, &len, &isfree)) {
			if (isfree)
				continue;
			return true;
		}

		if ((iterator->pool_idx + 1) >= malloc_pool_len)
			return false;

		iterator->pool_idx++;
		iterator->next_buf = BFH(malloc_pool[iterator->pool_idx].buf);
	}
}

/* Convenience macro for looping over all allocated buffers */
#define BPOOL_FOREACH(iterator, bp) \
		for (bpool_foreach_iterator_init((iterator)); \
			bpool_foreach((iterator), (bp));)

static void *raw_malloc(size_t hdr_size, size_t ftr_size, size_t pl_size)
{
	void *ptr;
	size_t s = hdr_size + ftr_size + pl_size;

	/*
	 * Make sure that malloc has correct alignment of returned buffers.
	 * The assumption is that uintptr_t will be as wide as the largest
	 * required alignment of any type.
	 */
	COMPILE_TIME_ASSERT(SizeQuant >= sizeof(uintptr_t));

	raw_malloc_validate_pools();

	/* Check wrapping */
	if (s < pl_size)
		return NULL;

	/* BGET doesn't like 0 sized allocations */
	if (!s)
		s++;

	ptr = bget(s);
	raw_malloc_save_max_alloced_size();
	return ptr;
}

static void raw_free(void *ptr)
{
	raw_malloc_validate_pools();

	if (ptr)
		brel(ptr);
}

static void *raw_calloc(size_t hdr_size, size_t ftr_size, size_t pl_nmemb,
		size_t pl_size)
{
	size_t s = hdr_size + ftr_size + pl_nmemb * pl_size;
	void *ptr;

	raw_malloc_validate_pools();

	/* Check wrapping */
	if (s < pl_nmemb || s < pl_size)
		return NULL;

	/* BGET doesn't like 0 sized allocations */
	if (!s)
		s++;

	ptr = bgetz(s);
	raw_malloc_save_max_alloced_size();
	return ptr;
}

static void *raw_realloc(void *ptr, size_t hdr_size, size_t ftr_size,
		size_t pl_size)
{
	size_t s = hdr_size + ftr_size + pl_size;
	void *p;

	raw_malloc_validate_pools();

	/* Check wrapping */
	if (s < pl_size)
		return NULL;

	/* BGET doesn't like 0 sized allocations */
	if (!s)
		s++;

	p = bgetr(ptr, s);
	raw_malloc_save_max_alloced_size();
	return p;
}

static void create_free_block(struct bfhead *bf, bufsize size, struct bhead *bn)
{
	assert(BH((char *)bf + size) == bn);
	assert(bn->bsize < 0); /* Next block should be allocated */
	/* Next block shouldn't already have free block in front */
	assert(bn->prevfree == 0);

	/* Create the free buf header */
	bf->bh.bsize = size;
	bf->bh.prevfree = 0;

	/* Update next block to point to the new free buf header */
	bn->prevfree = size;

	/* Insert the free buffer on the free list */
	assert(freelist.ql.blink->ql.flink == &freelist);
	assert(freelist.ql.flink->ql.blink == &freelist);
	bf->ql.flink = &freelist;
	bf->ql.blink = freelist.ql.blink;
	freelist.ql.blink = bf;
	bf->ql.blink->ql.flink = bf;
}

static void brel_before(char *orig_buf, char *new_buf)
{
	struct bfhead *bf;
	struct bhead *b;
	bufsize size;
	bufsize orig_size;

	assert(orig_buf < new_buf);
	/* There has to be room for the freebuf header */
	size = (bufsize)(new_buf - orig_buf);
	assert(size >= (SizeQ + sizeof(struct bhead)));

	/* Point to head of original buffer */
	bf = BFH(orig_buf - sizeof(struct bhead));
	orig_size = -bf->bh.bsize; /* negative since it's an allocated buffer */

	/* Point to head of the becoming new allocated buffer */
	b = BH(new_buf - sizeof(struct bhead));

	if (bf->bh.prevfree != 0) {
		/* Previous buffer is free, consolidate with that buffer */
		struct bfhead *bfp;

		/* Update the previous free buffer */
		bfp = BFH((char *)bf - bf->bh.prevfree);
		assert(bfp->bh.bsize == bf->bh.prevfree);
		bfp->bh.bsize += size;

		/* Make a new allocated buffer header */
		b->prevfree = bfp->bh.bsize;
		/* Make it negative since it's an allocated buffer */
		b->bsize = -(orig_size - size);
	} else {
		/*
		 * Previous buffer is allocated, create a new buffer and
		 * insert on the free list.
		 */

		/* Make it negative since it's an allocated buffer */
		b->bsize = -(orig_size - size);

		create_free_block(bf, size, b);
	}

#ifdef BufStats
	totalloc -= size;
	assert(totalloc >= 0);
#endif
}

static void brel_after(char *buf, bufsize size)
{
	struct bhead *b = BH(buf - sizeof(struct bhead));
	struct bhead *bn;
	bufsize new_size = size;
	bufsize free_size;

	/* Select the size in the same way as in bget() */
	if (new_size < SizeQ)
		new_size = SizeQ;
#ifdef SizeQuant
#if SizeQuant > 1
	new_size = (new_size + (SizeQuant - 1)) & (~(SizeQuant - 1));
#endif
#endif
	new_size += sizeof(struct bhead);
	assert(new_size <= -b->bsize);

	/*
	 * Check if there's enough space at the end of the buffer to be
	 * able to free anything.
	 */
	free_size = -b->bsize - new_size;
	if (free_size < SizeQ + sizeof(struct bhead))
		return;

	bn = BH((char *)b - b->bsize);
	/*
	 * Set the new size of the buffer;
	 */
	b->bsize = -new_size;
	if (bn->bsize > 0) {
		/* Next buffer is free, consolidate with that buffer */
		struct bfhead *bfn = BFH(bn);
		struct bfhead *nbf = BFH((char *)b + new_size);
		struct bhead *bnn = BH((char *)bn + bn->bsize);

		assert(bfn->bh.prevfree == 0);
		assert(bnn->prevfree == bfn->bh.bsize);

		/* Construct the new free header */
		nbf->bh.prevfree = 0;
		nbf->bh.bsize = bfn->bh.bsize + free_size;

		/* Update the buffer after this to point to this header */
		bnn->prevfree += free_size;

		/*
		 * Unlink the previous free buffer and link the new free
		 * buffer.
		 */
		assert(bfn->ql.blink->ql.flink == bfn);
		assert(bfn->ql.flink->ql.blink == bfn);

		/* Assing blink and flink from old free buffer */
		nbf->ql.blink = bfn->ql.blink;
		nbf->ql.flink = bfn->ql.flink;

		/* Replace the old free buffer with the new one */
		nbf->ql.blink->ql.flink = nbf;
		nbf->ql.flink->ql.blink = nbf;
	} else {
		/* New buffer is allocated, create a new free buffer */
		create_free_block(BFH((char *)b + new_size), free_size, bn);
	}

#ifdef BufStats
	totalloc -= free_size;
	assert(totalloc >= 0);
#endif

}

static void *raw_memalign(size_t hdr_size, size_t ftr_size, size_t alignment,
		size_t size)
{
	size_t s;
	uintptr_t b;

	raw_malloc_validate_pools();

	if (!IS_POWER_OF_TWO(alignment))
		return NULL;

	/*
	 * Normal malloc with headers always returns something SizeQuant
	 * aligned.
	 */
	if (alignment <= SizeQuant)
		return raw_malloc(hdr_size, ftr_size, size);

	s = hdr_size + ftr_size + alignment + size +
	    SizeQ + sizeof(struct bhead);

	/* Check wapping */
	if (s < alignment || s < size)
		return NULL;

	b = (uintptr_t)bget(s);
	if (!b)
		return NULL;

	if ((b + hdr_size) & (alignment - 1)) {
		/*
		 * Returned buffer is not aligned as requested if the
		 * hdr_size is added. Find an offset into the buffer
		 * that is far enough in to the buffer to be able to free
		 * what's in front.
		 */
		uintptr_t p;

		/*
		 * Find the point where the buffer including supplied
		 * header size should start.
		 */
		p = b + hdr_size + alignment;
		p &= ~(alignment - 1);
		p -= hdr_size;
		if ((p - b) < (SizeQ + sizeof(struct bhead)))
			p += alignment;
		assert((p + hdr_size + ftr_size + size) <= (b + s));

		/* Free the front part of the buffer */
		brel_before((void *)b, (void *)p);

		/* Set the new start of the buffer */
		b = p;
	}

	/*
	 * Since b is now aligned, release what we don't need at the end of
	 * the buffer.
	 */
	brel_after((void *)b, hdr_size + ftr_size + size);

	raw_malloc_save_max_alloced_size();

	return (void *)b;
}

/* Most of the stuff in this function is copied from bgetr() in bget.c */
static bufsize bget_buf_size(void *buf)
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
		osize = bd->tsize - sizeof(struct bdhead);
	} else
#endif
		osize -= sizeof(struct bhead);
	assert(osize > 0);
	return osize;
}

#ifdef ENABLE_MDBG

struct mdbg_hdr {
	const char *fname;
	uint16_t line;
	bool ignore;
	uint32_t pl_size;
	uint32_t magic;
};

#define MDBG_HEADER_MAGIC	0xadadadad
#define MDBG_FOOTER_MAGIC	0xecececec

/* TODO make this a per thread variable */
static enum mdbg_mode mdbg_mode = MDBG_MODE_DYNAMIC;

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
	return footer;
}

static void mdbg_update_hdr(struct mdbg_hdr *hdr, const char *fname,
		int lineno, size_t pl_size)
{
	uint32_t *footer;

	hdr->fname = fname;
	hdr->line = lineno;
	hdr->pl_size = pl_size;
	hdr->magic = MDBG_HEADER_MAGIC;
	hdr->ignore = mdbg_mode == MDBG_MODE_STATIC;

	footer = mdbg_get_footer(hdr);
	*footer = MDBG_FOOTER_MAGIC;
}

void *mdbg_malloc(const char *fname, int lineno, size_t size)
{
	struct mdbg_hdr *hdr;

	COMPILE_TIME_ASSERT(sizeof(struct mdbg_hdr) == sizeof(uint32_t) * 4);

	hdr = raw_malloc(sizeof(struct mdbg_hdr),
			  mdbg_get_ftr_size(size), size);
	if (hdr) {
		mdbg_update_hdr(hdr, fname, lineno, size);
		hdr++;
	}
	return hdr;
}

static void assert_header(struct mdbg_hdr *hdr)
{
	assert(hdr->magic == MDBG_HEADER_MAGIC);
	assert(*mdbg_get_footer(hdr) == MDBG_FOOTER_MAGIC);
}

void mdbg_free(void *ptr)
{
	struct mdbg_hdr *hdr = ptr;

	if (hdr) {
		hdr--;
		assert_header(hdr);
		hdr->magic = 0;
		*mdbg_get_footer(hdr) = 0;
		raw_free(hdr);
	}
}

void *mdbg_calloc(const char *fname, int lineno, size_t nmemb, size_t size)
{
	struct mdbg_hdr *hdr;

	hdr = raw_calloc(sizeof(struct mdbg_hdr),
			  mdbg_get_ftr_size(nmemb * size), nmemb, size);
	if (hdr) {
		mdbg_update_hdr(hdr, fname, lineno, nmemb * size);
		hdr++;
	}
	return hdr;
}

void *mdbg_realloc(const char *fname, int lineno, void *ptr, size_t size)
{
	struct mdbg_hdr *hdr = ptr;

	if (hdr) {
		hdr--;
		assert_header(hdr);
	}
	hdr = raw_realloc(hdr, sizeof(struct mdbg_hdr),
			   mdbg_get_ftr_size(size), size);
	if (hdr) {
		mdbg_update_hdr(hdr, fname, lineno, size);
		hdr++;
	}
	return hdr;
}

void *mdbg_memalign(const char *fname, int lineno, size_t alignment,
		size_t size)
{
	struct mdbg_hdr *hdr;

	hdr = raw_memalign(sizeof(struct mdbg_hdr), mdbg_get_ftr_size(size),
			   alignment, size);
	if (hdr) {
		mdbg_update_hdr(hdr, fname, lineno, size);
		hdr++;
	}
	return hdr;
}


static void *get_payload_start_size(void *raw_buf, size_t *size)
{
	struct mdbg_hdr *hdr = raw_buf;

	assert(bget_buf_size(hdr) >= hdr->pl_size);
	*size = hdr->pl_size;
	return hdr + 1;
}

void mdbg_check(int bufdump)
{
	struct bpool_iterator itr;
	void *b;

	raw_malloc_validate_pools();

	BPOOL_FOREACH(&itr, &b) {
		struct mdbg_hdr *hdr = (struct mdbg_hdr *)b;

		assert_header(hdr);

		if (bufdump > 0 || !hdr->ignore) {
			const char *fname = hdr->fname;

			if (!fname)
				fname = "unknown";

			DMSG("%s buffer: %d bytes %s:%d\n",
				hdr->ignore ? "Ignore" : "Orphaned",
				hdr->pl_size, fname, hdr->line);
		}
	}

}

enum mdbg_mode mdbg_set_mode(enum mdbg_mode mode)
{
	enum mdbg_mode old_mode = mdbg_mode;

	mdbg_mode = mode;
	return old_mode;
}

#else

void *malloc(size_t size)
{
	return raw_malloc(0, 0, size);
}

void free(void *ptr)
{
	raw_free(ptr);
}

void *calloc(size_t nmemb, size_t size)
{
	return raw_calloc(0, 0, nmemb, size);
}

void *realloc(void *ptr, size_t size)
{
	return raw_realloc(ptr, 0, 0, size);
}

void *memalign(size_t alignment, size_t size)
{
	return raw_memalign(0, 0, alignment, size);
}

static void *get_payload_start_size(void *ptr, size_t *size)
{
	*size = bget_buf_size(ptr);
	return ptr;
}

#endif



void malloc_init(void *buf, size_t len)
{
	/* Must not be called twice */
	assert(!malloc_pool);

	malloc_add_pool(buf, len);
}

void malloc_add_pool(void *buf, size_t len)
{
	void *p;
	size_t l;
	uintptr_t start = (uintptr_t)buf;
	uintptr_t end = start + len;
	enum mdbg_mode old_mode = mdbg_set_mode(MDBG_MODE_STATIC);

	start = ROUNDUP(start, SizeQuant);
	end = ROUNDDOWN(end, SizeQuant);
	assert(start < end);

	bpool((void *)start, end - start);

	l = malloc_pool_len + 1;
	p = realloc(malloc_pool, sizeof(struct malloc_pool) * l);
	assert(p);
	malloc_pool = p;
	malloc_pool[malloc_pool_len].buf = (void *)start;
	malloc_pool[malloc_pool_len].len = end - start;
	malloc_pool_len = l;
	mdbg_set_mode(old_mode);
}

bool malloc_buffer_is_within_alloced(void *buf, size_t len)
{
	struct bpool_iterator itr;
	void *b;
	uint8_t *start_buf = buf;
	uint8_t *end_buf = start_buf + len;

	raw_malloc_validate_pools();

	/* Check for wrapping */
	if (start_buf > end_buf)
		return false;

	BPOOL_FOREACH(&itr, &b) {
		uint8_t *start_b;
		uint8_t *end_b;
		size_t s;

		start_b = get_payload_start_size(b, &s);
		end_b = start_b + s;

		if (start_buf >= start_b && end_buf <= end_b)
			return true;
	}
	return false;
}

bool malloc_buffer_overlaps_heap(void *buf, size_t len)
{
	uintptr_t buf_start = (uintptr_t) buf;
	uintptr_t buf_end = buf_start + len;
	size_t n;

	raw_malloc_validate_pools();

	for (n = 0; n < malloc_pool_len; n++) {
		uintptr_t pool_start = (uintptr_t)malloc_pool[n].buf;
		uintptr_t pool_end = pool_start + malloc_pool[n].len;

		if (buf_start > buf_end || pool_start > pool_end)
			return true;	/* Wrapping buffers, shouldn't happen */

		if (buf_end > pool_start || buf_start < pool_end)
			return true;
	}

	return false;
}
