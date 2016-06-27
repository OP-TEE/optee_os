/*
 * Copyright (c) 2016, Linaro Limited
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

#ifndef MM_TEE_PAGER_H
#define MM_TEE_PAGER_H

#include <kernel/abort.h>
#include <kernel/panic.h>
#include <mm/tee_mm.h>
#include <trace.h>

/*
 * Reference to translation table used to map the virtual memory range
 * covered by the pager.
 */
extern struct core_mmu_table_info tee_pager_tbl_info;

/*
 * tee_pager_init() - Initialized the pager
 * @mm_alias:	The alias area where all physical pages managed by the
 *		pager are aliased
 *
 * Panics if called twice or some other error occurs.
 */
void tee_pager_init(tee_mm_entry_t *mm_alias);

/*
 * tee_pager_add_core_area() - Adds a pageable core area
 * @base:	base of covered memory area
 * @size:	size of covered memory area
 * @flags:	describes attributes of mapping
 * @store:	backing store for the memory area
 * @hashes:	hashes of the pages in the backing store
 *
 * TEE_MATTR_PW		- read-write mapping else read-only mapping
 * TEE_MATTR_PX		- executable mapping
 * TEE_MATTR_LOCKED	- on demand locked mapping, requires TEE_MATTR_PW,
 *			  will only be unmapped by a call to
 *			  tee_pager_release_phys()
 *
 * !TEE_MATTR_PW requires store and hashes to be !NULL while
 * TEE_MATTR_PW requires store and hashes to be NULL.
 *
 * Invalid use of flags or non-page aligned base or size or size == 0 will
 * cause a panic.
 *
 * Return true on success or false if area can't be added.
 */
bool tee_pager_add_core_area(vaddr_t base, size_t size, uint32_t flags,
			const void *store, const void *hashes);

/*
 * Adds physical pages to the pager to use. The supplied virtual address range
 * is searched for mapped physical pages and unmapped pages are ignored.
 *
 * vaddr is the first virtual address
 * npages is the number of pages to add
 */
void tee_pager_add_pages(vaddr_t vaddr, size_t npages, bool unmap);

/*
 * tee_pager_alloc() - Allocate read-write virtual memory from pager.
 * @size:	size of memory in bytes
 * @flags:	flags for allocation
 *
 * Allocates read-write memory from pager, all flags but the optional
 * TEE_MATTR_LOCKED is ignored.
 *
 * @return NULL on failure or a pointer to the virtual memory on success.
 */
void *tee_pager_alloc(size_t size, uint32_t flags);

/*
 * tee_pager_release_phys() - Release physical pages used for mapping
 * @addr:	virtual address of first page to release
 * @size:	number of bytes to release
 *
 * Only pages completely covered by the supplied range are affected.  This
 * function only supplies a hint to the pager that the physical page can be
 * reused. The caller can't expect a released memory range to hold a
 * specific bit pattern when used next time.
 *
 * Note that the virtual memory allocation is still valid after this
 * function has returned, it's just the content that may or may not have
 * changed.
 */
#ifdef CFG_WITH_PAGER
void tee_pager_release_phys(void *addr, size_t size);
#else
static inline void tee_pager_release_phys(void *addr __unused,
			size_t size __unused)
{
}
#endif

/*
 * Statistics on the pager
 */
struct tee_pager_stats {
	size_t hidden_hits;
	size_t ro_hits;
	size_t rw_hits;
	size_t zi_released;
	size_t npages;		/* number of load pages */
	size_t npages_all;	/* number of pages */
};

#ifdef CFG_WITH_PAGER
void tee_pager_get_stats(struct tee_pager_stats *stats);
bool tee_pager_handle_fault(struct abort_info *ai);
#else /*CFG_WITH_PAGER*/
static inline bool tee_pager_handle_fault(struct abort_info *ai __unused)
{
	return false;
}

static inline void tee_pager_get_stats(struct tee_pager_stats *stats)
{
	memset(stats, 0, sizeof(struct tee_pager_stats));
}
#endif /*CFG_WITH_PAGER*/

#endif /*MM_TEE_PAGER_H*/
