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

#ifndef TEE_MM_H
#define TEE_MM_H

#include <stdint.h>
#include <stdbool.h>

#include "tee_mm_unpg.h"

/*-----------------------------------------------------------------------------
 * Init managed memory area
 *---------------------------------------------------------------------------*/
bool tee_mm_init(tee_mm_pool_t *pool, uint32_t lo, uint32_t hi, uint8_t shift,
		 uint32_t flags);

/*-----------------------------------------------------------------------------
 * Kill managed memory area
 *---------------------------------------------------------------------------*/
void tee_mm_final(tee_mm_pool_t *pool);

/*-----------------------------------------------------------------------------
 * Allocates size number of bytes in the paged virtual address space
 * Returns a handle to the memory. The handle is used as an input to
 * the tee_mm_free function.
 *---------------------------------------------------------------------------*/
tee_mm_entry_t *tee_mm_alloc(tee_mm_pool_t *pool, uint32_t size);

/* Allocate supplied memory range if it's free */
tee_mm_entry_t *tee_mm_alloc2(tee_mm_pool_t *pool, tee_vaddr_t base,
			      size_t size);

/*-----------------------------------------------------------------------------
 * Frees the entry in the paged virtual address space pointed to by the
 * input parameter p
 *---------------------------------------------------------------------------*/
void tee_mm_free(tee_mm_entry_t *p);

/*-----------------------------------------------------------------------------
 * Returns size in sections or pages
 *---------------------------------------------------------------------------*/
static inline uint32_t tee_mm_get_size(tee_mm_entry_t *p)
{
	return p->size;
}

/*-----------------------------------------------------------------------------
 * Returns offset from start of area in sections or pages
 *---------------------------------------------------------------------------*/
static inline uint32_t tee_mm_get_offset(tee_mm_entry_t *p)
{
	return p->offset;
}

/* Return size of the mm entry in bytes */
size_t tee_mm_get_bytes(const tee_mm_entry_t *mm);

bool tee_mm_addr_is_within_range(tee_mm_pool_t *pool, uint32_t addr);

bool tee_mm_is_empty(tee_mm_pool_t *pool);

#endif
