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

#include <sys/queue.h>
#include <kernel/abort.h>
#include <kernel/panic.h>
#include <kernel/tee_misc.h>
#include <kernel/tee_ta_manager.h>
#include <kernel/thread.h>
#include <kernel/tz_proc.h>
#include <mm/core_memprot.h>
#include <mm/tee_mm.h>
#include <mm/tee_mmu_defs.h>
#include <mm/tee_pager.h>
#include <types_ext.h>
#include <stdlib.h>
#include <tee_api_defines.h>
#include <tee/tee_cryp_provider.h>
#include <trace.h>
#include <utee_defines.h>
#include <util.h>
#include <keep.h>
#include "pager_private.h"

#define PAGER_AE_KEY_BITS	256

struct pager_rw_pstate {
	uint64_t iv;
	uint8_t tag[PAGER_AES_GCM_TAG_LEN];
};

struct tee_pager_area {
	union {
		const uint8_t *hashes;
		struct pager_rw_pstate *rwp;
	} u;
	uint8_t *store;
	uint32_t flags;
	vaddr_t base;
	size_t size;
	TAILQ_ENTRY(tee_pager_area) link;
};

static TAILQ_HEAD(tee_pager_area_head, tee_pager_area) tee_pager_area_head =
	TAILQ_HEAD_INITIALIZER(tee_pager_area_head);

#define INVALID_PGIDX	UINT_MAX

/*
 * struct tee_pager_pmem - Represents a physical page used for paging.
 *
 * @pgidx	an index of the entry in tee_pager_tbl_info.
 * @va_alias	Virtual address where the physical page always is aliased.
 *		Used during remapping of the page when the content need to
 *		be updated before it's available at the new location.
 * @area	a pointer to the pager area
 */
struct tee_pager_pmem {
	unsigned pgidx;
	void *va_alias;
	struct tee_pager_area *area;
	TAILQ_ENTRY(tee_pager_pmem) link;
};

/* The list of physical pages. The first page in the list is the oldest */
TAILQ_HEAD(tee_pager_pmem_head, tee_pager_pmem);

static struct tee_pager_pmem_head tee_pager_pmem_head =
	TAILQ_HEAD_INITIALIZER(tee_pager_pmem_head);

static struct tee_pager_pmem_head tee_pager_lock_pmem_head =
	TAILQ_HEAD_INITIALIZER(tee_pager_lock_pmem_head);

static uint8_t pager_ae_key[PAGER_AE_KEY_BITS / 8];

/* number of pages hidden */
#define TEE_PAGER_NHIDE (tee_pager_npages / 3)

/* Number of registered physical pages, used hiding pages. */
static size_t tee_pager_npages;

#ifdef CFG_WITH_STATS
static struct tee_pager_stats pager_stats;

static inline void incr_ro_hits(void)
{
	pager_stats.ro_hits++;
}

static inline void incr_rw_hits(void)
{
	pager_stats.rw_hits++;
}

static inline void incr_hidden_hits(void)
{
	pager_stats.hidden_hits++;
}

static inline void incr_zi_released(void)
{
	pager_stats.zi_released++;
}

static inline void incr_npages_all(void)
{
	pager_stats.npages_all++;
}

static inline void set_npages(void)
{
	pager_stats.npages = tee_pager_npages;
}

void tee_pager_get_stats(struct tee_pager_stats *stats)
{
	*stats = pager_stats;

	pager_stats.hidden_hits = 0;
	pager_stats.ro_hits = 0;
	pager_stats.rw_hits = 0;
	pager_stats.zi_released = 0;
}

#else /* CFG_WITH_STATS */
static inline void incr_ro_hits(void) { }
static inline void incr_rw_hits(void) { }
static inline void incr_hidden_hits(void) { }
static inline void incr_zi_released(void) { }
static inline void incr_npages_all(void) { }
static inline void set_npages(void) { }

void tee_pager_get_stats(struct tee_pager_stats *stats)
{
	memset(stats, 0, sizeof(struct tee_pager_stats));
}
#endif /* CFG_WITH_STATS */

struct core_mmu_table_info tee_pager_tbl_info;
static struct core_mmu_table_info pager_alias_tbl_info;

static unsigned pager_lock = SPINLOCK_UNLOCK;

/* Defines the range of the alias area */
static tee_mm_entry_t *pager_alias_area;
/*
 * Physical pages are added in a stack like fashion to the alias area,
 * @pager_alias_next_free gives the address of next free entry if
 * @pager_alias_next_free is != 0
 */
static uintptr_t pager_alias_next_free;

static void set_alias_area(tee_mm_entry_t *mm)
{
	struct core_mmu_table_info *ti = &pager_alias_tbl_info;
	size_t tbl_va_size;
	unsigned idx;
	unsigned last_idx;
	vaddr_t smem = tee_mm_get_smem(mm);
	size_t nbytes = tee_mm_get_bytes(mm);

	DMSG("0x%" PRIxVA " - 0x%" PRIxVA, smem, smem + nbytes);

	TEE_ASSERT(!pager_alias_area);
	if (!ti->num_entries && !core_mmu_find_table(smem, UINT_MAX, ti)) {
		DMSG("Can't find translation table");
		panic();
	}
	if ((1 << ti->shift) != SMALL_PAGE_SIZE) {
		DMSG("Unsupported page size in translation table %u",
		     1 << ti->shift);
		panic();
	}

	tbl_va_size = (1 << ti->shift) * ti->num_entries;
	if (!core_is_buffer_inside(smem, nbytes,
				   ti->va_base, tbl_va_size)) {
		DMSG("area 0x%" PRIxVA " len 0x%zx doesn't fit it translation table 0x%" PRIxVA " len 0x%zx",
			smem, nbytes, ti->va_base, tbl_va_size);
		panic();
	}

	TEE_ASSERT(!(smem & SMALL_PAGE_MASK));
	TEE_ASSERT(!(nbytes & SMALL_PAGE_MASK));

	pager_alias_area = mm;
	pager_alias_next_free = smem;

	/* Clear all mapping in the alias area */
	idx = core_mmu_va2idx(ti, smem);
	last_idx = core_mmu_va2idx(ti, smem + nbytes);
	for (; idx < last_idx; idx++)
		core_mmu_set_entry(ti, idx, 0, 0);

	/* TODO only invalidate entries touched above */
	core_tlb_maintenance(TLBINV_UNIFIEDTLB, 0);
}

static void generate_ae_key(void)
{
	TEE_Result res;

	res = rng_generate(pager_ae_key, sizeof(pager_ae_key));
	TEE_ASSERT(res == TEE_SUCCESS);
}

void tee_pager_init(tee_mm_entry_t *mm_alias)
{
	set_alias_area(mm_alias);
	generate_ae_key();
}

static void *pager_add_alias_page(paddr_t pa)
{
	unsigned idx;
	struct core_mmu_table_info *ti = &pager_alias_tbl_info;
	uint32_t attr = TEE_MATTR_VALID_BLOCK | TEE_MATTR_GLOBAL |
			(TEE_MATTR_CACHE_CACHED << TEE_MATTR_CACHE_SHIFT) |
			TEE_MATTR_SECURE | TEE_MATTR_PRW;

	DMSG("0x%" PRIxPA, pa);

	TEE_ASSERT(pager_alias_next_free && ti->num_entries);
	idx = core_mmu_va2idx(ti, pager_alias_next_free);
	core_mmu_set_entry(ti, idx, pa, attr);
	pager_alias_next_free += SMALL_PAGE_SIZE;
	if (pager_alias_next_free >= (tee_mm_get_smem(pager_alias_area) +
				      tee_mm_get_bytes(pager_alias_area)))
		pager_alias_next_free = 0;
	return (void *)core_mmu_idx2va(ti, idx);
}

static struct tee_pager_area *alloc_area(vaddr_t base, size_t size,
			uint32_t flags, const void *store, const void *hashes)
{
	struct tee_pager_area *area = calloc(1, sizeof(*area));
	tee_mm_entry_t *mm_store = NULL;

	if (!area)
		return NULL;

	if (flags & TEE_MATTR_PW) {
		if (flags & TEE_MATTR_LOCKED)
			goto out;
		mm_store = tee_mm_alloc(&tee_mm_sec_ddr, size);
		if (!mm_store)
			goto bad;
		area->store = phys_to_virt(tee_mm_get_smem(mm_store),
					   MEM_AREA_TA_RAM);
		if (!area->store)
			goto bad;
		area->u.rwp = calloc(size / SMALL_PAGE_SIZE,
				     sizeof(struct pager_rw_pstate));
		if (!area->u.rwp)
			goto bad;
	} else {
		area->store = (void *)store;
		area->u.hashes = hashes;
	}
out:
	area->base = base;
	area->size = size;
	area->flags = flags;
	return area;
bad:
	tee_mm_free(mm_store);
	free(area->u.rwp);
	free(area);
	return NULL;
}

static void area_insert_tail(struct tee_pager_area *area)
{
	uint32_t exceptions = thread_mask_exceptions(THREAD_EXCP_ALL);

	cpu_spin_lock(&pager_lock);

	TAILQ_INSERT_TAIL(&tee_pager_area_head, area, link);

	cpu_spin_unlock(&pager_lock);
	thread_set_exceptions(exceptions);
}
KEEP_PAGER(area_insert_tail);

bool tee_pager_add_core_area(vaddr_t base, size_t size, uint32_t flags,
			const void *store, const void *hashes)
{
	struct tee_pager_area *area;
	size_t tbl_va_size;
	struct core_mmu_table_info *ti = &tee_pager_tbl_info;

	DMSG("0x%" PRIxPTR " - 0x%" PRIxPTR " : flags 0x%x, store %p, hashes %p",
		base, base + size, flags, store, hashes);

	TEE_ASSERT(!(base & SMALL_PAGE_MASK) &&
			size && !(size & SMALL_PAGE_MASK));

	if (!(flags & TEE_MATTR_PW))
		TEE_ASSERT(store && hashes);
	else if (flags & TEE_MATTR_PW)
		TEE_ASSERT(!store && !hashes);
	else
		panic();


	tbl_va_size = (1 << ti->shift) * ti->num_entries;
	if (!core_is_buffer_inside(base, size, ti->va_base, tbl_va_size)) {
		DMSG("area 0x%" PRIxPTR " len 0x%zx doesn't fit it translation table 0x%" PRIxVA " len 0x%zx",
			base, size, ti->va_base, tbl_va_size);
		return false;
	}

	area = alloc_area(base, size, flags, store, hashes);
	if (!area)
		return false;

	area_insert_tail(area);
	return true;
}

static struct tee_pager_area *tee_pager_find_area(vaddr_t va)
{
	struct tee_pager_area *area;

	TAILQ_FOREACH(area, &tee_pager_area_head, link) {
		if (core_is_buffer_inside(va, 1, area->base, area->size))
			return area;
	}
	return NULL;
}

static uint32_t get_area_mattr(struct tee_pager_area *area)
{
	return TEE_MATTR_VALID_BLOCK | TEE_MATTR_GLOBAL |
	       TEE_MATTR_CACHE_CACHED << TEE_MATTR_CACHE_SHIFT |
	       TEE_MATTR_SECURE | TEE_MATTR_PR |
	       (area->flags & TEE_MATTR_PRWX);
}

static paddr_t get_pmem_pa(struct tee_pager_pmem *pmem)
{
	paddr_t pa;
	unsigned idx;

	idx = core_mmu_va2idx(&pager_alias_tbl_info, (vaddr_t)pmem->va_alias);
	core_mmu_get_entry(&pager_alias_tbl_info, idx, &pa, NULL);
	return pa;
}

static bool decrypt_page(struct pager_rw_pstate *rwp, const void *src,
			void *dst)
{
	struct pager_aes_gcm_iv iv = {
		{ (vaddr_t)rwp, rwp->iv >> 32, rwp->iv }
	};

	return pager_aes_gcm_decrypt(pager_ae_key, sizeof(pager_ae_key),
				     &iv, rwp->tag, src, dst, SMALL_PAGE_SIZE);
}

static void encrypt_page(struct pager_rw_pstate *rwp, void *src, void *dst)
{
	struct pager_aes_gcm_iv iv;

	assert((rwp->iv + 1) > rwp->iv);
	rwp->iv++;
	/*
	 * IV is constructed as recommended in section "8.2.1 Deterministic
	 * Construction" of "Recommendation for Block Cipher Modes of
	 * Operation: Galois/Counter Mode (GCM) and GMAC",
	 * http://csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf
	 */
	iv.iv[0] = (vaddr_t)rwp;
	iv.iv[1] = rwp->iv >> 32;
	iv.iv[2] = rwp->iv;

	if (!pager_aes_gcm_encrypt(pager_ae_key, sizeof(pager_ae_key),
				   &iv, rwp->tag, src, dst, SMALL_PAGE_SIZE))
		panic();
}

static void tee_pager_load_page(struct tee_pager_area *area, vaddr_t page_va,
			void *va_alias)
{
	size_t idx = (page_va - area->base) >> SMALL_PAGE_SHIFT;
	const void *stored_page = area->store + idx * SMALL_PAGE_SIZE;

	if (!(area->flags & TEE_MATTR_PW)) {
		const void *hash = area->u.hashes + idx * TEE_SHA256_HASH_SIZE;

		memcpy(va_alias, stored_page, SMALL_PAGE_SIZE);
		incr_ro_hits();

		if (hash_sha256_check(hash, va_alias, SMALL_PAGE_SIZE) !=
				TEE_SUCCESS) {
			EMSG("PH 0x%" PRIxVA " failed", page_va);
			panic();
		}
	} else if (area->flags & TEE_MATTR_LOCKED) {
		FMSG("Zero init %p %#" PRIxVA, va_alias, page_va);
		memset(va_alias, 0, SMALL_PAGE_SIZE);
	} else {
		FMSG("Restore %p %#" PRIxVA " iv %#" PRIx64,
			va_alias, page_va, area->u.rwp[idx].iv);
		if (!area->u.rwp[idx].iv)
			memset(va_alias, 0, SMALL_PAGE_SIZE);
		else if (!decrypt_page(&area->u.rwp[idx], stored_page,
				       va_alias)) {
			EMSG("PH 0x%" PRIxVA " failed", page_va);
			panic();
		}
		incr_rw_hits();
	}
}

static void tee_pager_save_page(struct tee_pager_pmem *pmem, uint32_t attr)
{
	struct core_mmu_table_info *ti = &tee_pager_tbl_info;
	const uint32_t dirty_bits = TEE_MATTR_PW | TEE_MATTR_UW |
				    TEE_MATTR_HIDDEN_DIRTY_BLOCK;

	assert(!(pmem->area->flags & TEE_MATTR_LOCKED));

	if (attr & dirty_bits) {
		size_t idx = pmem->pgidx - core_mmu_va2idx(ti,
							   pmem->area->base);
		void *stored_page = pmem->area->store + idx * SMALL_PAGE_SIZE;

		assert(pmem->area->flags & TEE_MATTR_PW);
		encrypt_page(&pmem->area->u.rwp[idx], pmem->va_alias,
			     stored_page);
		FMSG("Saved %#" PRIxVA " iv %#" PRIx64,
			core_mmu_idx2va(ti, pmem->pgidx),
			pmem->area->u.rwp[idx].iv);
	}
}

static bool tee_pager_unhide_page(vaddr_t page_va)
{
	struct core_mmu_table_info *ti = &tee_pager_tbl_info;
	struct tee_pager_pmem *pmem;

	TAILQ_FOREACH(pmem, &tee_pager_pmem_head, link) {
		paddr_t pa;
		uint32_t attr;

		if (pmem->pgidx == INVALID_PGIDX)
			continue;

		core_mmu_get_entry(ti, pmem->pgidx,
				   &pa, &attr);

		if (!(attr &
		     (TEE_MATTR_HIDDEN_BLOCK | TEE_MATTR_HIDDEN_DIRTY_BLOCK)))
			continue;

		if (core_mmu_va2idx(ti, page_va) == pmem->pgidx) {
			uint32_t a = get_area_mattr(pmem->area);

			/* page is hidden, show and move to back */
			assert(pa == get_pmem_pa(pmem));
			/*
			 * If it's not a dirty block, then it should be
			 * read only.
			 */
			if (!(attr & TEE_MATTR_HIDDEN_DIRTY_BLOCK))
				a &= ~(TEE_MATTR_PW | TEE_MATTR_UW);
			else
				FMSG("Unhide %#" PRIxVA, page_va);
			core_mmu_set_entry(ti, pmem->pgidx, pa, a);

			TAILQ_REMOVE(&tee_pager_pmem_head, pmem, link);
			TAILQ_INSERT_TAIL(&tee_pager_pmem_head, pmem, link);

			/* TODO only invalidate entry touched above */
			core_tlb_maintenance(TLBINV_UNIFIEDTLB, 0);

			incr_hidden_hits();
			return true;
		}
	}

	return false;
}

static void tee_pager_hide_pages(void)
{
	struct core_mmu_table_info *ti = &tee_pager_tbl_info;
	struct tee_pager_pmem *pmem;
	size_t n = 0;

	TAILQ_FOREACH(pmem, &tee_pager_pmem_head, link) {
		paddr_t pa;
		uint32_t attr;
		uint32_t a;

		if (n >= TEE_PAGER_NHIDE)
			break;
		n++;

		/*
		 * we cannot hide pages when pmem->area is not defined as
		 * unhide requires pmem->area to be defined
		 */
		if (!pmem->area)
			continue;

		core_mmu_get_entry(ti, pmem->pgidx, &pa, &attr);
		if (!(attr & TEE_MATTR_VALID_BLOCK))
			continue;

		assert(pa == get_pmem_pa(pmem));
		if (attr & (TEE_MATTR_PW | TEE_MATTR_UW)){
			a = TEE_MATTR_HIDDEN_DIRTY_BLOCK;
			FMSG("Hide %#" PRIxVA,
			     ti->va_base + pmem->pgidx * SMALL_PAGE_SIZE);
		} else
			a = TEE_MATTR_HIDDEN_BLOCK;
		core_mmu_set_entry(ti, pmem->pgidx, pa, a);

	}

	/* TODO only invalidate entries touched above */
	core_tlb_maintenance(TLBINV_UNIFIEDTLB, 0);
}

/*
 * Find mapped pmem, hide and move to pageble pmem.
 * Return false if page was not mapped, and true if page was mapped.
 */
static bool tee_pager_release_one_phys(vaddr_t page_va)
{
	struct core_mmu_table_info *ti = &tee_pager_tbl_info;
	struct tee_pager_pmem *pmem;
	unsigned pgidx;
	paddr_t pa;
	uint32_t attr;

	pgidx = core_mmu_va2idx(ti, page_va);
	core_mmu_get_entry(ti, pgidx, &pa, &attr);

	FMSG("%" PRIxVA " : %" PRIxPA "|%x", page_va, pa, attr);

	TAILQ_FOREACH(pmem, &tee_pager_lock_pmem_head, link) {
		if (pmem->pgidx != pgidx)
			continue;

		assert(pa == get_pmem_pa(pmem));
		core_mmu_set_entry(ti, pgidx, 0, 0);
		TAILQ_REMOVE(&tee_pager_lock_pmem_head, pmem, link);
		pmem->area = NULL;
		pmem->pgidx = INVALID_PGIDX;
		tee_pager_npages++;
		set_npages();
		TAILQ_INSERT_HEAD(&tee_pager_pmem_head, pmem, link);
		incr_zi_released();
		return true;
	}

	return false;
}

/* Finds the oldest page and unmats it from its old virtual address */
static struct tee_pager_pmem *tee_pager_get_page(uint32_t next_area_flags)
{
	struct core_mmu_table_info *ti = &tee_pager_tbl_info;
	struct tee_pager_pmem *pmem;

	pmem = TAILQ_FIRST(&tee_pager_pmem_head);
	if (!pmem) {
		EMSG("No pmem entries");
		return NULL;
	}
	if (pmem->pgidx != INVALID_PGIDX) {
		uint32_t a;

		core_mmu_get_entry(ti, pmem->pgidx, NULL, &a);
		core_mmu_set_entry(ti, pmem->pgidx, 0, 0);
		/* TODO only invalidate entries touched above */
		core_tlb_maintenance(TLBINV_UNIFIEDTLB, 0);
		tee_pager_save_page(pmem, a);
	}

	TAILQ_REMOVE(&tee_pager_pmem_head, pmem, link);
	pmem->pgidx = INVALID_PGIDX;
	pmem->area = NULL;
	if (next_area_flags & TEE_MATTR_LOCKED) {
		/* Move page to lock list */
		TEE_ASSERT(tee_pager_npages > 0);
		tee_pager_npages--;
		set_npages();
		TAILQ_INSERT_TAIL(&tee_pager_lock_pmem_head, pmem, link);
	} else {
		/* move page to back */
		TAILQ_INSERT_TAIL(&tee_pager_pmem_head, pmem, link);
	}

	return pmem;
}

static bool pager_update_permissions(struct tee_pager_area *area,
			struct abort_info *ai)
{
	struct core_mmu_table_info *ti = &tee_pager_tbl_info;
	unsigned pgidx = core_mmu_va2idx(ti, ai->va);
	uint32_t attr;
	paddr_t pa;

	core_mmu_get_entry(ti, pgidx, &pa, &attr);

	/* Not mapped */
	if (!(attr & TEE_MATTR_VALID_BLOCK))
		return false;

	/* Not readable, should not happen */
	if (!(attr & TEE_MATTR_PR)) {
		abort_print_error(ai);
		panic();
	}

	switch (core_mmu_get_fault_type(ai->fault_descr)) {
	case CORE_MMU_FAULT_TRANSLATION:
	case CORE_MMU_FAULT_READ_PERMISSION:
		if (ai->abort_type == ABORT_TYPE_PREFETCH &&
		    !(attr & TEE_MATTR_PX)) {
			/* Attempting to execute from an NOX page */
			abort_print_error(ai);
			panic();
		}
		/* Since the page is mapped now it's OK */
		return true;
	case CORE_MMU_FAULT_WRITE_PERMISSION:
		if (!(area->flags & TEE_MATTR_PW)) {
			/* Attempting to write to an RO page */
			abort_print_error(ai);
			panic();
		}
		if (!(attr & TEE_MATTR_PW)) {
			FMSG("Dirty %p", (void *)(ai->va & ~SMALL_PAGE_MASK));
			core_mmu_set_entry(ti, pgidx, pa, attr | TEE_MATTR_PW);
			/* TODO only invalidate entry above */
			core_tlb_maintenance(TLBINV_UNIFIEDTLB, 0);
		}
		/* Since permissions has been updated now it's OK */
		return true;
	default:
		/* Some fault we can't deal with */
		abort_print_error(ai);
		panic();
	}

}

#ifdef CFG_TEE_CORE_DEBUG
static void stat_handle_fault(void)
{
	static size_t num_faults;
	static size_t min_npages = SIZE_MAX;
	static size_t total_min_npages = SIZE_MAX;

	num_faults++;
	if ((num_faults % 1024) == 0 || tee_pager_npages < total_min_npages) {
		DMSG("nfaults %zu npages %zu (min %zu)",
		     num_faults, tee_pager_npages, min_npages);
		min_npages = tee_pager_npages; /* reset */
	}
	if (tee_pager_npages < min_npages)
		min_npages = tee_pager_npages;
	if (tee_pager_npages < total_min_npages)
		total_min_npages = tee_pager_npages;
}
#else
static void stat_handle_fault(void)
{
}
#endif

bool tee_pager_handle_fault(struct abort_info *ai)
{
	struct core_mmu_table_info *ti = &tee_pager_tbl_info;
	struct tee_pager_area *area;
	vaddr_t page_va = ai->va & ~SMALL_PAGE_MASK;
	uint32_t exceptions;
	bool ret;

#ifdef TEE_PAGER_DEBUG_PRINT
	abort_print(ai);
#endif

	/*
	 * We're updating pages that can affect several active CPUs at a
	 * time below. We end up here because a thread tries to access some
	 * memory that isn't available. We have to be careful when making
	 * that memory available as other threads may succeed in accessing
	 * that address the moment after we've made it available.
	 *
	 * That means that we can't just map the memory and populate the
	 * page, instead we use the aliased mapping to populate the page
	 * and once everything is ready we map it.
	 */
	exceptions = thread_mask_exceptions(THREAD_EXCP_IRQ);
	cpu_spin_lock(&pager_lock);

	stat_handle_fault();

	/* check if the access is valid */
	area = tee_pager_find_area(ai->va);
	if (!area) {
		EMSG("Invalid addr 0x%" PRIxVA, ai->va);
		ret = false;
		goto out;
	}

	if (!tee_pager_unhide_page(page_va)) {
		struct tee_pager_pmem *pmem = NULL;
		uint32_t attr;

		/*
		 * The page wasn't hidden, but some other core may have
		 * updated the table entry before we got here or we need
		 * to make a read-only page read-write (dirty).
		 */
		if (pager_update_permissions(area, ai)) {
			/*
			 * Kind of access is OK with the mapping, we're
			 * done here because the fault has already been
			 * dealt with by another core.
			 */
			ret = true;
			goto out;
		}

		pmem = tee_pager_get_page(area->flags);
		if (!pmem) {
			abort_print(ai);
			panic();
		}

		/* load page code & data */
		tee_pager_load_page(area, page_va, pmem->va_alias);

		/*
		 * We've updated the page using the aliased mapping and
		 * some cache maintenence is now needed if it's an
		 * executable page.
		 *
		 * Since the d-cache is a Physically-indexed,
		 * physically-tagged (PIPT) cache we can clean the aliased
		 * address instead of the real virtual address.
		 *
		 * The i-cache can also be PIPT, but may be something else
		 * to, to keep it simple we invalidate the entire i-cache.
		 * As a future optimization we may invalidate only the
		 * aliased area if it a PIPT cache else the entire cache.
		 */
		if (area->flags & TEE_MATTR_PX) {
			/*
			 * Doing these operations to LoUIS (Level of
			 * unification, Inner Shareable) would be enough
			 */
			cache_maintenance_l1(DCACHE_AREA_CLEAN,
				pmem->va_alias, SMALL_PAGE_SIZE);

			cache_maintenance_l1(ICACHE_INVALIDATE, NULL, 0);
		}

		pmem->area = area;
		pmem->pgidx = core_mmu_va2idx(ti, ai->va);
		attr = get_area_mattr(area) & ~(TEE_MATTR_PW | TEE_MATTR_UW);
		core_mmu_set_entry(ti, pmem->pgidx, get_pmem_pa(pmem), attr);

		FMSG("Mapped 0x%" PRIxVA " -> 0x%" PRIxPA,
		     core_mmu_idx2va(ti, pmem->pgidx), get_pmem_pa(pmem));

	}

	tee_pager_hide_pages();
	ret = true;
out:
	cpu_spin_unlock(&pager_lock);
	thread_unmask_exceptions(exceptions);
	return ret;
}

void tee_pager_add_pages(vaddr_t vaddr, size_t npages, bool unmap)
{
	struct core_mmu_table_info *ti = &tee_pager_tbl_info;
	size_t n;

	DMSG("0x%" PRIxVA " - 0x%" PRIxVA " : %d",
	     vaddr, vaddr + npages * SMALL_PAGE_SIZE, (int)unmap);

	/* setup memory */
	for (n = 0; n < npages; n++) {
		struct tee_pager_pmem *pmem;
		tee_vaddr_t va = vaddr + n * SMALL_PAGE_SIZE;
		unsigned pgidx = core_mmu_va2idx(ti, va);
		paddr_t pa;
		uint32_t attr;

		core_mmu_get_entry(ti, pgidx, &pa, &attr);

		/* Ignore unmapped pages/blocks */
		if (!(attr & TEE_MATTR_VALID_BLOCK))
			continue;

		pmem = malloc(sizeof(struct tee_pager_pmem));
		if (pmem == NULL) {
			EMSG("Can't allocate memory");
			panic();
		}

		pmem->va_alias = pager_add_alias_page(pa);

		if (unmap) {
			pmem->area = NULL;
			pmem->pgidx = INVALID_PGIDX;
			core_mmu_set_entry(ti, pgidx, 0, 0);
		} else {
			/*
			 * The page is still mapped, let's assign the area
			 * and update the protection bits accordingly.
			 */
			pmem->area = tee_pager_find_area(va);
			pmem->pgidx = pgidx;
			assert(pa == get_pmem_pa(pmem));
			core_mmu_set_entry(ti, pgidx, pa,
					   get_area_mattr(pmem->area));
		}

		tee_pager_npages++;
		incr_npages_all();
		set_npages();
		TAILQ_INSERT_TAIL(&tee_pager_pmem_head, pmem, link);
	}

	/* Invalidate secure TLB */
	core_tlb_maintenance(TLBINV_UNIFIEDTLB, 0);
}

void tee_pager_release_phys(void *addr, size_t size)
{
	bool unmaped = false;
	vaddr_t va = (vaddr_t)addr;
	vaddr_t begin = ROUNDUP(va, SMALL_PAGE_SIZE);
	vaddr_t end = ROUNDDOWN(va + size, SMALL_PAGE_SIZE);
	uint32_t exceptions = thread_mask_exceptions(THREAD_EXCP_ALL);

	cpu_spin_lock(&pager_lock);

	for (va = begin; va < end; va += SMALL_PAGE_SIZE)
		unmaped |= tee_pager_release_one_phys(va);

	/* Invalidate secure TLB */
	if (unmaped)
		core_tlb_maintenance(TLBINV_UNIFIEDTLB, 0);

	cpu_spin_unlock(&pager_lock);
	thread_set_exceptions(exceptions);
}
KEEP_PAGER(tee_pager_release_phys);

void *tee_pager_alloc(size_t size, uint32_t flags)
{
	tee_mm_entry_t *mm;
	uint32_t f = TEE_MATTR_PRW | (flags & TEE_MATTR_LOCKED);

	if (!size)
		return NULL;

	mm = tee_mm_alloc(&tee_mm_vcore, ROUNDUP(size, SMALL_PAGE_SIZE));
	if (!mm)
		return NULL;

	tee_pager_add_core_area(tee_mm_get_smem(mm), tee_mm_get_bytes(mm),
				f, NULL, NULL);

	return (void *)tee_mm_get_smem(mm);
}
