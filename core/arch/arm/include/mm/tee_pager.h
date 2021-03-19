/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016-2021, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#ifndef MM_TEE_PAGER_H
#define MM_TEE_PAGER_H

#include <kernel/abort.h>
#include <kernel/panic.h>
#include <kernel/user_ta.h>
#include <mm/core_mmu.h>
#include <mm/tee_mm.h>
#include <string.h>
#include <trace.h>

enum tee_pager_area_type {
	PAGER_AREA_TYPE_RO,
	PAGER_AREA_TYPE_RW,
	PAGER_AREA_TYPE_LOCK,
};

struct tee_pager_area {
	struct fobj *fobj;
	size_t fobj_pgoffs;
	enum tee_pager_area_type type;
	uint32_t flags;
	vaddr_t base;
	size_t size;
	struct pgt *pgt;
	TAILQ_ENTRY(tee_pager_area) link;
	TAILQ_ENTRY(tee_pager_area) fobj_link;
};

TAILQ_HEAD(tee_pager_area_head, tee_pager_area);

/*
 * tee_pager_early_init() - Perform early initialization of pager
 *
 * Panics if some error occurs
 */
void tee_pager_early_init(void);

/*
 * tee_pager_get_table_info() - Fills in table info for address mapped in
 * translation table managed by the pager.
 * @va:		address to look up
 * @ti:		filled in table info
 *
 * Returns true if address is in the pager translation tables else false
 */
bool tee_pager_get_table_info(vaddr_t va, struct core_mmu_table_info *ti);

/*
 * tee_pager_phys_to_virt() - Translate physical address to virtual address
 * looking in the pager page tables
 * @pa:	address to translate
 *
 * Returns found virtual address or NULL on error
 */
void *tee_pager_phys_to_virt(paddr_t pa);

/*
 * tee_pager_set_alias_area() - Initialize pager alias area
 * @mm_alias:	The alias area where all physical pages managed by the
 *		pager are aliased
 *
 * Panics if called twice or some other error occurs.
 */
void tee_pager_set_alias_area(tee_mm_entry_t *mm_alias);

/*
 * tee_pager_init_iv_area() - Inialized pager area for tags IVs used by RW
 *			      paged fobjs
 * @fobj:	fobj backing the area
 *
 * Panics if called twice or some other error occurs.
 *
 * Returns virtual address of start of IV area.
 */
vaddr_t tee_pager_init_iv_area(struct fobj *fobj);

/*
 * tee_pager_generate_authenc_key() - Generates authenc key for r/w paging
 *
 * Needs to draw random from RNG, panics if some error occurs.
 */
#ifdef CFG_WITH_PAGER
void tee_pager_generate_authenc_key(void);
#else
static inline void tee_pager_generate_authenc_key(void)
{
}
#endif

/*
 * tee_pager_add_core_area() - Adds a pageable core area
 * @base:	base of covered memory area
 * @type:	type of memory area
 * @fobj:	fobj backing the area
 *
 * Non-page aligned base or size will cause a panic.
 */
void tee_pager_add_core_area(vaddr_t base, enum tee_pager_area_type type,
			     struct fobj *fobj);

/*
 * tee_pager_add_um_area() - Adds a pageable user ta area
 * @uctx:	user mode context of the area
 * @base:	base of covered memory area
 * @fobj:	fobj of the store backing the memory area
 *
 * The mapping is created suitable to initialize the memory content while
 * loading the TA. Once the TA is properly loaded the areas should be
 * finalized with tee_pager_set_um_area_attr() to get more strict settings.
 *
 * Return TEE_SUCCESS on success, anything else if the area can't be added
 */
#ifdef CFG_PAGED_USER_TA
TEE_Result tee_pager_add_um_area(struct user_mode_ctx *uctx, vaddr_t base,
				 struct fobj *fobj, uint32_t prot);
#else
static inline TEE_Result
tee_pager_add_um_area(struct user_mode_ctx *uctx __unused,
		      vaddr_t base __unused, struct fobj *fobj __unused,
		      uint32_t prot __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}
#endif

/*
 * tee_pager_set_um_area_attr() - Set attributes of a initialized memory area
 * @uctx:	user mode context of the area
 * @base:	base of covered memory area
 * @size:	size of covered memory area
 * @flags:	TEE_MATTR_U* flags describing permissions of the area
 *
 * Return true on success of false if the area can't be updated
 */
#ifdef CFG_PAGED_USER_TA
bool tee_pager_set_um_area_attr(struct user_mode_ctx *uctx, vaddr_t base,
				size_t size, uint32_t flags);
#else
static inline bool
tee_pager_set_um_area_attr(struct user_mode_ctx *uctx __unused,
			   vaddr_t base __unused, size_t size __unused,
			   uint32_t flags __unused)
{
	return false;
}
#endif

#ifdef CFG_PAGED_USER_TA
void tee_pager_rem_um_region(struct user_mode_ctx *uctx, vaddr_t base,
			     size_t size);
#else
static inline void tee_pager_rem_um_region(struct user_mode_ctx *uctx __unused,
					   vaddr_t base __unused,
					   size_t size __unused)
{
}
#endif

#ifdef CFG_PAGED_USER_TA
TEE_Result tee_pager_split_um_region(struct user_mode_ctx *uctx, vaddr_t va);
#else
static inline TEE_Result
tee_pager_split_um_region(struct user_mode_ctx *uctx __unused,
			  vaddr_t va __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

#endif
#ifdef CFG_PAGED_USER_TA
void tee_pager_merge_um_region(struct user_mode_ctx *uctx, vaddr_t va,
			       size_t len);
#else
static inline void
tee_pager_merge_um_region(struct user_mode_ctx *uctx __unused,
			  vaddr_t va __unused, size_t len __unused)
{
}
#endif

/*
 * tee_pager_rem_uma_areas() - Remove all user ta areas
 * @uctx:	user mode context
 *
 * This function is called when a user mode context is teared down.
 */
#ifdef CFG_PAGED_USER_TA
void tee_pager_rem_um_areas(struct user_mode_ctx *uctx);
#else
static inline void tee_pager_rem_um_areas(struct user_mode_ctx *uctx __unused)
{
}
#endif

/*
 * tee_pager_assign_um_tables() - Assigns translation table to a user ta
 * @uctx:	user mode context
 *
 * This function is called to assign translation tables for the pageable
 * areas of a user TA.
 */
#ifdef CFG_PAGED_USER_TA
void tee_pager_assign_um_tables(struct user_mode_ctx *uctx);
#else
static inline void
tee_pager_assign_um_tables(struct user_mode_ctx *uctx __unused)
{
}
#endif

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
 *
 * @return NULL on failure or a pointer to the virtual memory on success.
 */
void *tee_pager_alloc(size_t size);

#ifdef CFG_PAGED_USER_TA
/*
 * tee_pager_pgt_save_and_release_entries() - Save dirty pages to backing store
 * and remove physical page from translation table
 * @pgt: page table descriptor
 *
 * This function is called when a translation table needs to be recycled
 */
void tee_pager_pgt_save_and_release_entries(struct pgt *pgt);
#endif

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

void tee_pager_invalidate_fobj(struct fobj *fobj);

#endif /*MM_TEE_PAGER_H*/
