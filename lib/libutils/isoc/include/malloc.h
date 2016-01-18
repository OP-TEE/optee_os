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
#ifndef MALLOC_H
#define MALLOC_H

#include <stddef.h>
#include <types_ext.h>

void free(void *ptr);

#ifdef ENABLE_MDBG

void *mdbg_malloc(const char *fname, int lineno, size_t size);
void *mdbg_calloc(const char *fname, int lineno, size_t nmemb, size_t size);
void *mdbg_realloc(const char *fname, int lineno, void *ptr, size_t size);
void *mdbg_memalign(const char *fname, int lineno, size_t alignment,
		size_t size);

void mdbg_check(int bufdump);

#define malloc(size)	mdbg_malloc(__FILE__, __LINE__, (size))
#define calloc(nmemb, size) \
		mdbg_calloc(__FILE__, __LINE__, (nmemb), (size))
#define realloc(ptr, size) \
		mdbg_realloc(__FILE__, __LINE__, (ptr), (size))
#define memalign(alignment, size) \
		mdbg_memalign(__FILE__, __LINE__, (alignment), (size))

#else

void *malloc(size_t size);
void *calloc(size_t nmemb, size_t size);
void *realloc(void *ptr, size_t size);
void *memalign(size_t alignment, size_t size);

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

/* get malloc stats: curr allocated heap and max allocated heap since boot */
void malloc_reset_max_allocated(void);
size_t malloc_get_max_allocated(void);
size_t malloc_get_allocated(void);
size_t malloc_get_heap_size(void);

#endif /* MALLOC_H */
