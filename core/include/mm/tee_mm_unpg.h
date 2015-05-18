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

#ifndef TEE_MM_UNPG_H
#define TEE_MM_UNPG_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/* Define to indicate default pool initiation */
#define TEE_MM_POOL_NO_FLAGS            0
/* Flag to indicate that memory is allocated from hi address to low address */
#define TEE_MM_POOL_HI_ALLOC            (1u << 0)

struct _tee_mm_entry_t {
	struct _tee_mm_pool_t *pool;
	struct _tee_mm_entry_t *next;
	uint32_t offset;	/* offset in pages/sections */
	uint32_t size;		/* size in pages/sections */
};
typedef struct _tee_mm_entry_t tee_mm_entry_t;

struct _tee_mm_pool_t {
	tee_mm_entry_t *entry;
	uint32_t lo;		/* low boundery pf the pool */
	uint32_t hi;		/* high boundery pf the pool */
	uint32_t flags;		/* Config flags for the pool */
	uint8_t shift;		/* size shift */
};
typedef struct _tee_mm_pool_t tee_mm_pool_t;

/* Physical Public DDR pool */
extern tee_mm_pool_t tee_mm_pub_ddr;

/* Physical Secure DDR pool */
extern tee_mm_pool_t tee_mm_sec_ddr;

/* Virtual eSRAM pool */
extern tee_mm_pool_t tee_mm_vcore;

/*
 * Returns a pointer to the mm covering the supplied address,
 * if no mm is found NULL is returned.
 */
tee_mm_entry_t *tee_mm_find(const tee_mm_pool_t *pool, uint32_t addr);

/*-----------------------------------------------------------------------------
 * Validates that a address (addr) is part of the secure virtual memory
 * Returns false if not valid, true if valid
 * NOTE: This function is executed in abort mode. Pls take care of stack usage
 *---------------------------------------------------------------------------*/
static inline bool tee_mm_validate(const tee_mm_pool_t *pool, uint32_t addr)
{
	return tee_mm_find(pool, addr) != NULL;
}

/*-----------------------------------------------------------------------------
 * Returns virtual address of start of allocated memory for the mm entry.
 *---------------------------------------------------------------------------*/
uintptr_t tee_mm_get_smem(const tee_mm_entry_t *mm);

#endif
