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

enum mdbg_mode {
	MDBG_MODE_STATIC,
	MDBG_MODE_DYNAMIC
};

/*
 * ENABLE_MDBG: malloc debug support
 *
 * When enabled, malloc, calloc, realloc and free are redirected from SLA
 * to routines that trace memory callers (filename/line) and provide few other
 * memory alloc debug features. calloc and realloc are routed to basic malloc.
 *
 * memalign and other standard mem alloc APIs are not handled by mdbg.
 *
 * If ENABLE_MDBG is not set, malloc.c acts as a wrapper to redirect std
 * malloc apis to the apis of the embedded malloc library (SLA, dlmalloc,...).
 */
#ifdef ENABLE_MDBG

/* define mdbg 'malloc' routine and redirect std apis to these. */
void *mdbg_malloc(const char *fname, int lineno, unsigned nbytes);
void *mdbg_calloc(const char *fname, int lineno, unsigned nelem,
		  unsigned elsize);
#ifdef MDBG_REALLOC_ENABLED
void *mdbg_realloc(const char *fname, int lineno, void *ptr, unsigned size);
#endif

void mdbg_free(void *fp);
void mdbg_dump(int bufdump);
enum mdbg_mode mdbg_set_mode(enum mdbg_mode mode);
void mdbg_check(void);

/* Redefine standard memory allocator calls to use our routines instead. */
#define free           mdbg_free
#define malloc(x)      mdbg_malloc(__FILE__, __LINE__, (x))
#define calloc(n, e)    mdbg_calloc(__FILE__, __LINE__, (n), (e))
#define realloc(p, x)   mdbg_realloc(__FILE__, __LINE__, (p), (x))

#else

/* mdbg not enabled: simple define standard apis */
void *calloc(size_t nmemb, size_t size);
void free(void *ptr);
void *malloc(size_t size);
void *realloc(void *ptr, size_t size);

#define mdbg_check()        do { } while (0)
#define mdbg_dump(x)        do { } while (0)
static inline enum mdbg_mode mdbg_set_mode(enum mdbg_mode mode)
{
	return mode;
}

#endif /* ENABLE_MDBG */

/* other standard malloc apis */
void *memalign(size_t align, size_t size);
void *valloc(size_t size);
void *pvalloc(size_t size);

/* entry point for malloc init in case some inits are required */
void malloc_init(void *start, size_t size);

#endif /* MALLOC_H */
