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

#define SizeQuant   4		/* Buffer allocation size quantum:
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

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include "bget_malloc.h"
#include "bget.c"		/* this is ugly, but this is bget */
#include <utee_syscalls.h>

static void *malloc_heap_buf;
static size_t malloc_heap_len;

void *calloc(size_t nmemb, size_t size)
{
	return bget_malloc_with_flags(nmemb * size, 0);
}

void free(void *ptr)
{
#ifdef BufValid
	bpoolv(malloc_heap_buf);
#endif

	if (ptr != NULL) {
		uint32_t *flags = ptr;

		flags--;
		brel(flags);
	}
}

void *malloc(size_t size)
{
	return bget_malloc_with_flags(size, 0);
}

void *bget_malloc_with_flags(size_t size, uint32_t flags)
{
	uint32_t *f;
	size_t s = size + sizeof(uint32_t);

#ifdef BufValid
	bpoolv(malloc_heap_buf);
#endif

	/* Check wrapping */
	if (s < size)
		return NULL;

	f = bget(s);
	if (f == NULL)
		return NULL;

	*f = flags;
	f++;
	if (flags == 0)
		memset(f, 0, size);
	return f;
}

/* Most of the stuff in this function is copied from bgetr() in bget.c */
static bufsize bget_buf_size(void *buf)
{
	bufsize osize;		/* Old size of buffer */
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

void *realloc(void *ptr, size_t size)
{
	uint32_t *flags = ptr;
	size_t s;

	/*
	 * beause gcc incorrectly assumes this is an uninitialized variable
	 * not really needed as oszie is only used when memset_required is true
	 */
	bufsize osize = 0;
	bool memset_required = false;

	if (ptr == NULL)
		return malloc(size);

	/* increase to include flags word */
	s = size + sizeof(uint32_t);

	/* Check wrapping */
	if (s < size)
		return NULL;

	/* decrease to point beginning of allocated buffer */
	flags--;
	if (*flags != 0) {
		osize = bget_buf_size(flags);
		if (osize < s)
			memset_required = true;
	}

	flags = bgetr(flags, s);
	if (flags == NULL)
		return NULL;

	if (memset_required)
		memset((uint8_t *)flags + osize, 0, s - osize);

	flags++;
	return flags;
}

void bget_malloc_add_heap(void *buf, size_t len)
{
	/* Must not be called twice */
	if (malloc_heap_buf != NULL)
		utee_panic(0);

	malloc_heap_buf = buf;
	malloc_heap_len = len;
	bpool(buf, len);
}

bool bget_malloc_buffer_is_within_alloced(void *buf, size_t len)
{
	/* A lot of the code is copied from bpoolv() */
	struct bfhead *b = BFH(buf);
	uint8_t *ebuf = (uint8_t *)buf + len;

	/* Check for wrapping */
	if ((uint8_t *)buf > ebuf)
		return false;

	while (b->bh.bsize != ESent) {
		bufsize bs = b->bh.bsize;

		if (bs < 0) {
			/* bs < 0 -> We're in an alloced buffer */
			uint8_t *b_data;

			bs = -bs;
			b_data = (uint8_t *)b + sizeof(struct bhead);

			if ((uint8_t *)buf >= b_data && ebuf < (b_data + bs))
				return true;
		} else {
			if (bs == 0)
				return false;
		}
		b = BFH(((char *)b) + bs);
	}

	return false;
}

bool bget_malloc_buffer_overlaps_heap(void *buf, size_t len)
{
	uintptr_t buf_start = (uintptr_t) buf;
	uintptr_t buf_end = buf_start + len;
	uintptr_t heap_start = (uintptr_t) malloc_heap_buf;
	uintptr_t heap_end = heap_start + malloc_heap_len;

	if (buf_start > buf_end || heap_start > heap_end)
		return true;	/* Wrapping buffers, shouldn't happen */

	if (buf_end > heap_start || buf_start < heap_end)
		return true;

	return false;
}
