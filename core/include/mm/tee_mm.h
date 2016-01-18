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
#include <kernel/tee_common_unpg.h>

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
#ifdef CFG_WITH_STATS
	size_t max_allocated;
#endif
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

/*
 * Validates that an address (addr) is part of the secure virtual memory
 * Returns false if not valid, true if valid
 * NOTE: This function is executed in abort mode.
 *       Please take care of stack usage
 */
static inline bool tee_mm_validate(const tee_mm_pool_t *pool, uint32_t addr)
{
	return tee_mm_find(pool, addr) != 0;
}

/*
 * Returns a virtual address to the start of the allocated memory
 * for the mm entry.
 */
uintptr_t tee_mm_get_smem(const tee_mm_entry_t *mm);

/* Init managed memory area */
bool tee_mm_init(tee_mm_pool_t *pool, uint32_t lo, uint32_t hi, uint8_t shift,
		 uint32_t flags);

/* Kill managed memory area*/
void tee_mm_final(tee_mm_pool_t *pool);

/*
 * Allocates size number of bytes in the paged virtual address space
 * Returns a handle to the memory. The handle is used as an input to
 * the tee_mm_free function.
 */
tee_mm_entry_t *tee_mm_alloc(tee_mm_pool_t *pool, uint32_t size);

/* Allocate supplied memory range if it's free */
tee_mm_entry_t *tee_mm_alloc2(tee_mm_pool_t *pool, tee_vaddr_t base,
			      size_t size);

/*
 * Frees the entry in the paged virtual address space pointed to by the
 * input parameter p
 */
void tee_mm_free(tee_mm_entry_t *p);

/* Returns size in sections or pages */
static inline uint32_t tee_mm_get_size(tee_mm_entry_t *p)
{
	return p->size;
}

/* Returns offset from start of area in sections or pages */
static inline uint32_t tee_mm_get_offset(tee_mm_entry_t *p)
{
	return p->offset;
}

/* Return size of the mm entry in bytes */
size_t tee_mm_get_bytes(const tee_mm_entry_t *mm);

bool tee_mm_addr_is_within_range(tee_mm_pool_t *pool, uint32_t addr);

bool tee_mm_is_empty(tee_mm_pool_t *pool);

#ifdef CFG_WITH_STATS
#define TEE_MM_POOL_DESC_LENGTH 32
struct tee_mm_pool_stats {
	char desc[TEE_MM_POOL_DESC_LENGTH];
	uint32_t allocated;
	uint32_t max_allocated;
	uint32_t size;
};
void tee_mm_get_pool_stats(tee_mm_pool_t *pool, struct tee_mm_pool_stats *stats,
			   bool reset);
#endif

#endif
