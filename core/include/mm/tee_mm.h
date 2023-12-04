/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#ifndef __MM_TEE_MM_H
#define __MM_TEE_MM_H

#include <malloc.h>
#include <pta_stats.h>
#include <types_ext.h>

/* Define to indicate default pool initiation */
#define TEE_MM_POOL_NO_FLAGS            0
/* Flag to indicate that memory is allocated from hi address to low address */
#define TEE_MM_POOL_HI_ALLOC            (1u << 0)
/* Flag to indicate that pool should use nex_malloc instead of malloc */
#define TEE_MM_POOL_NEX_MALLOC             (1u << 1)

struct _tee_mm_entry_t {
	struct _tee_mm_pool_t *pool;
	struct _tee_mm_entry_t *next;
	uint32_t offset;	/* offset in pages/sections */
	uint32_t size;		/* size in pages/sections */
};
typedef struct _tee_mm_entry_t tee_mm_entry_t;

struct _tee_mm_pool_t {
	tee_mm_entry_t *entry;
	paddr_t lo;		/* low boundary of the pool */
	paddr_size_t size;	/* pool size */
	uint32_t flags;		/* Config flags for the pool */
	uint8_t shift;		/* size shift */
	unsigned int lock;
#ifdef CFG_WITH_STATS
	size_t max_allocated;
#endif
};
typedef struct _tee_mm_pool_t tee_mm_pool_t;

/* Physical Secure DDR pool */
extern tee_mm_pool_t tee_mm_sec_ddr;

/* Virtual eSRAM pool */
extern tee_mm_pool_t tee_mm_vcore;

/* Shared memory pool */
extern tee_mm_pool_t tee_mm_shm;

/*
 * Returns a pointer to the mm covering the supplied address,
 * if no mm is found NULL is returned.
 */
tee_mm_entry_t *tee_mm_find(const tee_mm_pool_t *pool, paddr_t addr);

/*
 * Validates that an address (addr) is part of the secure virtual memory
 * Returns false if not valid, true if valid
 * NOTE: This function is executed in abort mode.
 *       Please take care of stack usage
 */
static inline bool tee_mm_validate(const tee_mm_pool_t *pool, paddr_t addr)
{
	return tee_mm_find(pool, addr) != 0;
}

/*
 * Returns a virtual address to the start of the allocated memory
 * for the mm entry.
 */
uintptr_t tee_mm_get_smem(const tee_mm_entry_t *mm);

/* Init managed memory area */
bool tee_mm_init(tee_mm_pool_t *pool, paddr_t lo, paddr_size_t size,
		 uint8_t shift, uint32_t flags);

/* Kill managed memory area*/
void tee_mm_final(tee_mm_pool_t *pool);

/*
 * Allocates size number of bytes in the paged virtual address space
 * Returns a handle to the memory. The handle is used as an input to
 * the tee_mm_free function.
 */
tee_mm_entry_t *tee_mm_alloc(tee_mm_pool_t *pool, size_t size);

/* Allocate supplied memory range if it's free */
tee_mm_entry_t *tee_mm_alloc2(tee_mm_pool_t *pool, paddr_t base, size_t size);

/*
 * Frees the entry in the paged virtual address space pointed to by the
 * input parameter p
 */
void tee_mm_free(tee_mm_entry_t *p);

/* Returns size in sections or pages */
static inline size_t tee_mm_get_size(tee_mm_entry_t *p)
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

bool tee_mm_addr_is_within_range(const tee_mm_pool_t *pool, paddr_t addr);

bool tee_mm_is_empty(tee_mm_pool_t *pool);

#ifdef CFG_WITH_STATS
void tee_mm_get_pool_stats(tee_mm_pool_t *pool, struct pta_stats_alloc *stats,
			   bool reset);
#endif

#endif
