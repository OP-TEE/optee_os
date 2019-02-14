// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#include <arm.h>
#include <assert.h>
#include <crypto/crypto.h>
#include <crypto/internal_aes-gcm.h>
#include <io.h>
#include <keep.h>
#include <kernel/abort.h>
#include <kernel/asan.h>
#include <kernel/panic.h>
#include <kernel/spinlock.h>
#include <kernel/tee_misc.h>
#include <kernel/tee_ta_manager.h>
#include <kernel/thread.h>
#include <kernel/tlb_helpers.h>
#include <mm/core_memprot.h>
#include <mm/tee_mm.h>
#include <mm/tee_pager.h>
#include <stdlib.h>
#include <sys/queue.h>
#include <tee_api_defines.h>
#include <trace.h>
#include <types_ext.h>
#include <utee_defines.h>
#include <util.h>

#define PAGER_AE_KEY_BITS	256

struct pager_aes_gcm_iv {
	uint32_t iv[3];
};

#define PAGER_AES_GCM_TAG_LEN	16

struct pager_rw_pstate {
	uint64_t iv;
	uint8_t tag[PAGER_AES_GCM_TAG_LEN];
};

enum area_type {
	AREA_TYPE_RO,
	AREA_TYPE_RW,
	AREA_TYPE_LOCK,
};

struct tee_pager_area {
	union {
		const uint8_t *hashes;
		struct pager_rw_pstate *rwp;
	} u;
	uint8_t *store;
	enum area_type type;
	uint32_t flags;
	vaddr_t base;
	size_t size;
	struct pgt *pgt;
	TAILQ_ENTRY(tee_pager_area) link;
};

TAILQ_HEAD(tee_pager_area_head, tee_pager_area);

static struct tee_pager_area_head tee_pager_area_head =
	TAILQ_HEAD_INITIALIZER(tee_pager_area_head);

#define INVALID_PGIDX	UINT_MAX

/*
 * struct tee_pager_pmem - Represents a physical page used for paging.
 *
 * @pgidx	an index of the entry in area->ti.
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

static struct internal_aes_gcm_key pager_ae_key;

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

#define TBL_NUM_ENTRIES	(CORE_MMU_PGDIR_SIZE / SMALL_PAGE_SIZE)
#define TBL_LEVEL	CORE_MMU_PGDIR_LEVEL
#define TBL_SHIFT	SMALL_PAGE_SHIFT

#define EFFECTIVE_VA_SIZE \
	(ROUNDUP(TEE_RAM_VA_START + TEE_RAM_VA_SIZE, \
		 CORE_MMU_PGDIR_SIZE) - \
	 ROUNDDOWN(TEE_RAM_VA_START, CORE_MMU_PGDIR_SIZE))

static struct pager_table {
	struct pgt pgt;
	struct core_mmu_table_info tbl_info;
} pager_tables[EFFECTIVE_VA_SIZE / CORE_MMU_PGDIR_SIZE];

static unsigned pager_spinlock = SPINLOCK_UNLOCK;

/* Defines the range of the alias area */
static tee_mm_entry_t *pager_alias_area;
/*
 * Physical pages are added in a stack like fashion to the alias area,
 * @pager_alias_next_free gives the address of next free entry if
 * @pager_alias_next_free is != 0
 */
static uintptr_t pager_alias_next_free;

#ifdef CFG_TEE_CORE_DEBUG
#define pager_lock(ai) pager_lock_dldetect(__func__, __LINE__, ai)

static uint32_t pager_lock_dldetect(const char *func, const int line,
				    struct abort_info *ai)
{
	uint32_t exceptions = thread_mask_exceptions(THREAD_EXCP_ALL);
	unsigned int retries = 0;
	unsigned int reminder = 0;

	while (!cpu_spin_trylock(&pager_spinlock)) {
		retries++;
		if (!retries) {
			/* wrapped, time to report */
			trace_printf(func, line, TRACE_ERROR, true,
				     "possible spinlock deadlock reminder %u",
				     reminder);
			if (reminder < UINT_MAX)
				reminder++;
			if (ai)
				abort_print(ai);
		}
	}

	return exceptions;
}
#else
static uint32_t pager_lock(struct abort_info __unused *ai)
{
	return cpu_spin_lock_xsave(&pager_spinlock);
}
#endif

static uint32_t pager_lock_check_stack(size_t stack_size)
{
	if (stack_size) {
		int8_t buf[stack_size];
		size_t n;

		/*
		 * Make sure to touch all pages of the stack that we expect
		 * to use with this lock held. We need to take eventual
		 * page faults before the lock is taken or we'll deadlock
		 * the pager. The pages that are populated in this way will
		 * eventually be released at certain save transitions of
		 * the thread.
		 */
		for (n = 0; n < stack_size; n += SMALL_PAGE_SIZE)
			io_write8((vaddr_t)buf + n, 1);
		io_write8((vaddr_t)buf + stack_size - 1, 1);
	}

	return pager_lock(NULL);
}

static void pager_unlock(uint32_t exceptions)
{
	cpu_spin_unlock_xrestore(&pager_spinlock, exceptions);
}

void *tee_pager_phys_to_virt(paddr_t pa)
{
	struct core_mmu_table_info ti;
	unsigned idx;
	uint32_t a;
	paddr_t p;
	vaddr_t v;
	size_t n;

	/*
	 * Most addresses are mapped lineary, try that first if possible.
	 */
	if (!tee_pager_get_table_info(pa, &ti))
		return NULL; /* impossible pa */
	idx = core_mmu_va2idx(&ti, pa);
	core_mmu_get_entry(&ti, idx, &p, &a);
	if ((a & TEE_MATTR_VALID_BLOCK) && p == pa)
		return (void *)core_mmu_idx2va(&ti, idx);

	n = 0;
	idx = core_mmu_va2idx(&pager_tables[n].tbl_info, TEE_RAM_VA_START);
	while (true) {
		while (idx < TBL_NUM_ENTRIES) {
			v = core_mmu_idx2va(&pager_tables[n].tbl_info, idx);
			if (v >= (TEE_RAM_VA_START + TEE_RAM_VA_SIZE))
				return NULL;

			core_mmu_get_entry(&pager_tables[n].tbl_info,
					   idx, &p, &a);
			if ((a & TEE_MATTR_VALID_BLOCK) && p == pa)
				return (void *)v;
			idx++;
		}

		n++;
		if (n >= ARRAY_SIZE(pager_tables))
			return NULL;
		idx = 0;
	}

	return NULL;
}

static struct pager_table *find_pager_table_may_fail(vaddr_t va)
{
	size_t n;
	const vaddr_t mask = CORE_MMU_PGDIR_MASK;

	n = ((va & ~mask) - pager_tables[0].tbl_info.va_base) >>
	    CORE_MMU_PGDIR_SHIFT;
	if (n >= ARRAY_SIZE(pager_tables))
		return NULL;

	assert(va >= pager_tables[n].tbl_info.va_base &&
	       va <= (pager_tables[n].tbl_info.va_base | mask));

	return pager_tables + n;
}

static struct pager_table *find_pager_table(vaddr_t va)
{
	struct pager_table *pt = find_pager_table_may_fail(va);

	assert(pt);
	return pt;
}

bool tee_pager_get_table_info(vaddr_t va, struct core_mmu_table_info *ti)
{
	struct pager_table *pt = find_pager_table_may_fail(va);

	if (!pt)
		return false;

	*ti = pt->tbl_info;
	return true;
}

static struct core_mmu_table_info *find_table_info(vaddr_t va)
{
	return &find_pager_table(va)->tbl_info;
}

static struct pgt *find_core_pgt(vaddr_t va)
{
	return &find_pager_table(va)->pgt;
}

void tee_pager_set_alias_area(tee_mm_entry_t *mm)
{
	struct pager_table *pt;
	unsigned idx;
	vaddr_t smem = tee_mm_get_smem(mm);
	size_t nbytes = tee_mm_get_bytes(mm);
	vaddr_t v;

	DMSG("0x%" PRIxVA " - 0x%" PRIxVA, smem, smem + nbytes);

	assert(!pager_alias_area);
	pager_alias_area = mm;
	pager_alias_next_free = smem;

	/* Clear all mapping in the alias area */
	pt = find_pager_table(smem);
	idx = core_mmu_va2idx(&pt->tbl_info, smem);
	while (pt <= (pager_tables + ARRAY_SIZE(pager_tables) - 1)) {
		while (idx < TBL_NUM_ENTRIES) {
			v = core_mmu_idx2va(&pt->tbl_info, idx);
			if (v >= (smem + nbytes))
				goto out;

			core_mmu_set_entry(&pt->tbl_info, idx, 0, 0);
			idx++;
		}

		pt++;
		idx = 0;
	}

out:
	tlbi_mva_range(smem, nbytes, SMALL_PAGE_SIZE);
}

void tee_pager_generate_authenc_key(void)
{
	uint8_t key[PAGER_AE_KEY_BITS / 8];

	if (crypto_rng_read(key, sizeof(key)) != TEE_SUCCESS)
		panic("failed to generate random");
	if (internal_aes_gcm_expand_enc_key(key, sizeof(key),
					    &pager_ae_key))
		panic("failed to expand key");
}

static size_t tbl_usage_count(struct core_mmu_table_info *ti)
{
	size_t n;
	paddr_t pa;
	size_t usage = 0;

	for (n = 0; n < ti->num_entries; n++) {
		core_mmu_get_entry(ti, n, &pa, NULL);
		if (pa)
			usage++;
	}
	return usage;
}

static void area_get_entry(struct tee_pager_area *area, size_t idx,
			   paddr_t *pa, uint32_t *attr)
{
	assert(area->pgt);
	assert(idx < TBL_NUM_ENTRIES);
	core_mmu_get_entry_primitive(area->pgt->tbl, TBL_LEVEL, idx, pa, attr);
}

static void area_set_entry(struct tee_pager_area *area, size_t idx,
			   paddr_t pa, uint32_t attr)
{
	assert(area->pgt);
	assert(idx < TBL_NUM_ENTRIES);
	core_mmu_set_entry_primitive(area->pgt->tbl, TBL_LEVEL, idx, pa, attr);
}

static size_t area_va2idx(struct tee_pager_area *area, vaddr_t va)
{
	return (va - (area->base & ~CORE_MMU_PGDIR_MASK)) >> SMALL_PAGE_SHIFT;
}

static vaddr_t area_idx2va(struct tee_pager_area *area, size_t idx)
{
	return (idx << SMALL_PAGE_SHIFT) + (area->base & ~CORE_MMU_PGDIR_MASK);
}

void tee_pager_early_init(void)
{
	size_t n;

	/*
	 * Note that this depends on add_pager_vaspace() adding vaspace
	 * after end of memory.
	 */
	for (n = 0; n < ARRAY_SIZE(pager_tables); n++) {
		if (!core_mmu_find_table(NULL, TEE_RAM_VA_START +
					 n * CORE_MMU_PGDIR_SIZE, UINT_MAX,
					 &pager_tables[n].tbl_info))
			panic("can't find mmu tables");

		if (pager_tables[n].tbl_info.shift != TBL_SHIFT)
			panic("Unsupported page size in translation table");
		assert(pager_tables[n].tbl_info.num_entries == TBL_NUM_ENTRIES);
		assert(pager_tables[n].tbl_info.level == TBL_LEVEL);

		pager_tables[n].pgt.tbl = pager_tables[n].tbl_info.table;
		pgt_set_used_entries(&pager_tables[n].pgt,
				tbl_usage_count(&pager_tables[n].tbl_info));
	}
}

static void *pager_add_alias_page(paddr_t pa)
{
	unsigned idx;
	struct core_mmu_table_info *ti;
	/* Alias pages mapped without write permission: runtime will care */
	uint32_t attr = TEE_MATTR_VALID_BLOCK |
			(TEE_MATTR_CACHE_CACHED << TEE_MATTR_CACHE_SHIFT) |
			TEE_MATTR_SECURE | TEE_MATTR_PR;

	DMSG("0x%" PRIxPA, pa);

	ti = find_table_info(pager_alias_next_free);
	idx = core_mmu_va2idx(ti, pager_alias_next_free);
	core_mmu_set_entry(ti, idx, pa, attr);
	pgt_inc_used_entries(find_core_pgt(pager_alias_next_free));
	pager_alias_next_free += SMALL_PAGE_SIZE;
	if (pager_alias_next_free >= (tee_mm_get_smem(pager_alias_area) +
				      tee_mm_get_bytes(pager_alias_area)))
		pager_alias_next_free = 0;
	return (void *)core_mmu_idx2va(ti, idx);
}

static struct tee_pager_area *alloc_area(struct pgt *pgt,
					 vaddr_t base, size_t size,
					 uint32_t flags, const void *store,
					 const void *hashes)
{
	struct tee_pager_area *area = calloc(1, sizeof(*area));
	enum area_type at;
	tee_mm_entry_t *mm_store = NULL;

	if (!area)
		return NULL;

	if (flags & (TEE_MATTR_PW | TEE_MATTR_UW)) {
		if (flags & TEE_MATTR_LOCKED) {
			at = AREA_TYPE_LOCK;
			goto out;
		}
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
		at = AREA_TYPE_RW;
	} else {
		area->store = (void *)store;
		area->u.hashes = hashes;
		at = AREA_TYPE_RO;
	}
out:
	area->pgt = pgt;
	area->base = base;
	area->size = size;
	area->flags = flags;
	area->type = at;
	return area;
bad:
	tee_mm_free(mm_store);
	free(area->u.rwp);
	free(area);
	return NULL;
}

static void area_insert_tail(struct tee_pager_area *area)
{
	uint32_t exceptions = pager_lock_check_stack(8);

	TAILQ_INSERT_TAIL(&tee_pager_area_head, area, link);

	pager_unlock(exceptions);
}
KEEP_PAGER(area_insert_tail);

void tee_pager_add_core_area(vaddr_t base, size_t size, uint32_t flags,
			     const void *store, const void *hashes)
{
	struct tee_pager_area *area;
	vaddr_t b = base;
	size_t s = size;
	size_t s2;


	DMSG("0x%" PRIxPTR " - 0x%" PRIxPTR " : flags 0x%x, store %p, hashes %p",
		base, base + size, flags, store, hashes);

	if (base & SMALL_PAGE_MASK || size & SMALL_PAGE_MASK || !size) {
		EMSG("invalid pager area [%" PRIxVA " +0x%zx]", base, size);
		panic();
	}

	if (!(flags & TEE_MATTR_PW) && (!store || !hashes))
		panic("write pages cannot provide store or hashes");

	if ((flags & TEE_MATTR_PW) && (store || hashes))
		panic("non-write pages must provide store and hashes");

	while (s) {
		s2 = MIN(CORE_MMU_PGDIR_SIZE - (b & CORE_MMU_PGDIR_MASK), s);
		area = alloc_area(find_core_pgt(b), b, s2, flags,
				  (const uint8_t *)store + b - base,
				  (const uint8_t *)hashes + (b - base) /
							SMALL_PAGE_SIZE *
							TEE_SHA256_HASH_SIZE);
		if (!area)
			panic("alloc_area");
		area_insert_tail(area);
		b += s2;
		s -= s2;
	}
}

static struct tee_pager_area *find_area(struct tee_pager_area_head *areas,
					vaddr_t va)
{
	struct tee_pager_area *area;

	if (!areas)
		return NULL;

	TAILQ_FOREACH(area, areas, link) {
		if (core_is_buffer_inside(va, 1, area->base, area->size))
			return area;
	}
	return NULL;
}

#ifdef CFG_PAGED_USER_TA
static struct tee_pager_area *find_uta_area(vaddr_t va)
{
	struct tee_ta_ctx *ctx = thread_get_tsd()->ctx;

	if (!ctx || !is_user_ta_ctx(ctx))
		return NULL;
	return find_area(to_user_ta_ctx(ctx)->areas, va);
}
#else
static struct tee_pager_area *find_uta_area(vaddr_t va __unused)
{
	return NULL;
}
#endif /*CFG_PAGED_USER_TA*/


static uint32_t get_area_mattr(uint32_t area_flags)
{
	uint32_t attr = TEE_MATTR_VALID_BLOCK | TEE_MATTR_SECURE |
			TEE_MATTR_CACHE_CACHED << TEE_MATTR_CACHE_SHIFT |
			(area_flags & (TEE_MATTR_PRWX | TEE_MATTR_URWX));

	return attr;
}

static paddr_t get_pmem_pa(struct tee_pager_pmem *pmem)
{
	struct core_mmu_table_info *ti;
	paddr_t pa;
	unsigned idx;

	ti = find_table_info((vaddr_t)pmem->va_alias);
	idx = core_mmu_va2idx(ti, (vaddr_t)pmem->va_alias);
	core_mmu_get_entry(ti, idx, &pa, NULL);
	return pa;
}

static bool decrypt_page(struct pager_rw_pstate *rwp, const void *src,
			void *dst)
{
	struct pager_aes_gcm_iv iv = {
		{ (vaddr_t)rwp, rwp->iv >> 32, rwp->iv }
	};
	size_t tag_len = sizeof(rwp->tag);

	return !internal_aes_gcm_dec(&pager_ae_key, &iv, sizeof(iv),
				     NULL, 0, src, SMALL_PAGE_SIZE, dst,
				     rwp->tag, tag_len);
}

static void encrypt_page(struct pager_rw_pstate *rwp, void *src, void *dst)
{
	struct pager_aes_gcm_iv iv;
	size_t tag_len = sizeof(rwp->tag);

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

	if (internal_aes_gcm_enc(&pager_ae_key, &iv, sizeof(iv), NULL, 0,
				 src, SMALL_PAGE_SIZE, dst, rwp->tag, &tag_len))
		panic("gcm failed");
}

static void tee_pager_load_page(struct tee_pager_area *area, vaddr_t page_va,
			void *va_alias)
{
	size_t idx = (page_va - area->base) >> SMALL_PAGE_SHIFT;
	const void *stored_page = area->store + idx * SMALL_PAGE_SIZE;
	struct core_mmu_table_info *ti;
	uint32_t attr_alias;
	paddr_t pa_alias;
	unsigned int idx_alias;

	/* Insure we are allowed to write to aliased virtual page */
	ti = find_table_info((vaddr_t)va_alias);
	idx_alias = core_mmu_va2idx(ti, (vaddr_t)va_alias);
	core_mmu_get_entry(ti, idx_alias, &pa_alias, &attr_alias);
	if (!(attr_alias & TEE_MATTR_PW)) {
		attr_alias |= TEE_MATTR_PW;
		core_mmu_set_entry(ti, idx_alias, pa_alias, attr_alias);
		tlbi_mva_allasid((vaddr_t)va_alias);
	}

	asan_tag_access(va_alias, (uint8_t *)va_alias + SMALL_PAGE_SIZE);
	switch (area->type) {
	case AREA_TYPE_RO:
		{
			const void *hash = area->u.hashes +
					   idx * TEE_SHA256_HASH_SIZE;

			memcpy(va_alias, stored_page, SMALL_PAGE_SIZE);
			incr_ro_hits();

			if (hash_sha256_check(hash, va_alias,
					      SMALL_PAGE_SIZE) != TEE_SUCCESS) {
				EMSG("PH 0x%" PRIxVA " failed", page_va);
				panic();
			}
		}
		/* Forbid write to aliases for read-only (maybe exec) pages */
		attr_alias &= ~TEE_MATTR_PW;
		core_mmu_set_entry(ti, idx_alias, pa_alias, attr_alias);
		tlbi_mva_allasid((vaddr_t)va_alias);
		break;
	case AREA_TYPE_RW:
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
		break;
	case AREA_TYPE_LOCK:
		FMSG("Zero init %p %#" PRIxVA, va_alias, page_va);
		memset(va_alias, 0, SMALL_PAGE_SIZE);
		break;
	default:
		panic();
	}
	asan_tag_no_access(va_alias, (uint8_t *)va_alias + SMALL_PAGE_SIZE);
}

static void tee_pager_save_page(struct tee_pager_pmem *pmem, uint32_t attr)
{
	const uint32_t dirty_bits = TEE_MATTR_PW | TEE_MATTR_UW |
				    TEE_MATTR_HIDDEN_DIRTY_BLOCK;

	if (pmem->area->type == AREA_TYPE_RW && (attr & dirty_bits)) {
		size_t offs = pmem->area->base & CORE_MMU_PGDIR_MASK;
		size_t idx = pmem->pgidx - (offs >> SMALL_PAGE_SHIFT);
		void *stored_page = pmem->area->store + idx * SMALL_PAGE_SIZE;

		assert(pmem->area->flags & (TEE_MATTR_PW | TEE_MATTR_UW));
		asan_tag_access(pmem->va_alias,
				(uint8_t *)pmem->va_alias + SMALL_PAGE_SIZE);
		encrypt_page(&pmem->area->u.rwp[idx], pmem->va_alias,
			     stored_page);
		asan_tag_no_access(pmem->va_alias,
				   (uint8_t *)pmem->va_alias + SMALL_PAGE_SIZE);
		FMSG("Saved %#" PRIxVA " iv %#" PRIx64,
			pmem->area->base + idx * SMALL_PAGE_SIZE,
			pmem->area->u.rwp[idx].iv);
	}
}

#ifdef CFG_PAGED_USER_TA
static void free_area(struct tee_pager_area *area)
{
	tee_mm_free(tee_mm_find(&tee_mm_sec_ddr,
				virt_to_phys(area->store)));
	if (area->type == AREA_TYPE_RW)
		free(area->u.rwp);
	free(area);
}

static bool pager_add_uta_area(struct user_ta_ctx *utc, vaddr_t base,
			       size_t size)
{
	struct tee_pager_area *area;
	uint32_t flags;
	vaddr_t b = base;
	size_t s = ROUNDUP(size, SMALL_PAGE_SIZE);

	if (!utc->areas) {
		utc->areas = malloc(sizeof(*utc->areas));
		if (!utc->areas)
			return false;
		TAILQ_INIT(utc->areas);
	}

	flags = TEE_MATTR_PRW | TEE_MATTR_URWX;

	while (s) {
		size_t s2;

		if (find_area(utc->areas, b))
			return false;

		s2 = MIN(CORE_MMU_PGDIR_SIZE - (b & CORE_MMU_PGDIR_MASK), s);

		/* Table info will be set when the context is activated. */
		area = alloc_area(NULL, b, s2, flags, NULL, NULL);
		if (!area)
			return false;
		TAILQ_INSERT_TAIL(utc->areas, area, link);
		b += s2;
		s -= s2;
	}

	return true;
}

bool tee_pager_add_uta_area(struct user_ta_ctx *utc, vaddr_t base, size_t size)
{
	struct thread_specific_data *tsd = thread_get_tsd();
	struct tee_pager_area *area;
	struct core_mmu_table_info dir_info = { NULL };

	if (&utc->ctx != tsd->ctx) {
		/*
		 * Changes are to an utc that isn't active. Just add the
		 * areas page tables will be dealt with later.
		 */
		return pager_add_uta_area(utc, base, size);
	}

	/*
	 * Assign page tables before adding areas to be able to tell which
	 * are newly added and should be removed in case of failure.
	 */
	tee_pager_assign_uta_tables(utc);
	if (!pager_add_uta_area(utc, base, size)) {
		struct tee_pager_area *next_a;

		/* Remove all added areas */
		TAILQ_FOREACH_SAFE(area, utc->areas, link, next_a) {
			if (!area->pgt) {
				TAILQ_REMOVE(utc->areas, area, link);
				free_area(area);
			}
		}
		return false;
	}

	/*
	 * Assign page tables to the new areas and make sure that the page
	 * tables are registered in the upper table.
	 */
	tee_pager_assign_uta_tables(utc);
	core_mmu_get_user_pgdir(&dir_info);
	TAILQ_FOREACH(area, utc->areas, link) {
		paddr_t pa;
		size_t idx;
		uint32_t attr;

		idx = core_mmu_va2idx(&dir_info, area->pgt->vabase);
		core_mmu_get_entry(&dir_info, idx, &pa, &attr);

		/*
		 * Check if the page table already is used, if it is, it's
		 * already registered.
		 */
		if (area->pgt->num_used_entries) {
			assert(attr & TEE_MATTR_TABLE);
			assert(pa == virt_to_phys(area->pgt->tbl));
			continue;
		}

		attr = TEE_MATTR_SECURE | TEE_MATTR_TABLE;
		pa = virt_to_phys(area->pgt->tbl);
		assert(pa);
		/*
		 * Note that the update of the table entry is guaranteed to
		 * be atomic.
		 */
		core_mmu_set_entry(&dir_info, idx, pa, attr);
	}

	return true;
}

static void init_tbl_info_from_pgt(struct core_mmu_table_info *ti,
				   struct pgt *pgt)
{
	assert(pgt);
	ti->table = pgt->tbl;
	ti->va_base = pgt->vabase;
	ti->level = TBL_LEVEL;
	ti->shift = TBL_SHIFT;
	ti->num_entries = TBL_NUM_ENTRIES;
}

static void transpose_area(struct tee_pager_area *area, struct pgt *new_pgt,
			   vaddr_t new_base)
{
	uint32_t exceptions = pager_lock_check_stack(64);

	/*
	 * If there's no pgt assigned to the old area there's no pages to
	 * deal with either, just update with a new pgt and base.
	 */
	if (area->pgt) {
		struct core_mmu_table_info old_ti;
		struct core_mmu_table_info new_ti;
		struct tee_pager_pmem *pmem;

		init_tbl_info_from_pgt(&old_ti, area->pgt);
		init_tbl_info_from_pgt(&new_ti, new_pgt);


		TAILQ_FOREACH(pmem, &tee_pager_pmem_head, link) {
			vaddr_t va;
			paddr_t pa;
			uint32_t attr;

			if (pmem->area != area)
				continue;
			core_mmu_get_entry(&old_ti, pmem->pgidx, &pa, &attr);
			core_mmu_set_entry(&old_ti, pmem->pgidx, 0, 0);

			assert(pa == get_pmem_pa(pmem));
			assert(attr);
			assert(area->pgt->num_used_entries);
			area->pgt->num_used_entries--;

			va = core_mmu_idx2va(&old_ti, pmem->pgidx);
			va = va - area->base + new_base;
			pmem->pgidx = core_mmu_va2idx(&new_ti, va);
			core_mmu_set_entry(&new_ti, pmem->pgidx, pa, attr);
			new_pgt->num_used_entries++;
		}
	}

	area->pgt = new_pgt;
	area->base = new_base;
	pager_unlock(exceptions);
}
KEEP_PAGER(transpose_area);

void tee_pager_transfer_uta_region(struct user_ta_ctx *src_utc,
				   vaddr_t src_base,
				   struct user_ta_ctx *dst_utc,
				   vaddr_t dst_base, struct pgt **dst_pgt,
				   size_t size)
{
	struct tee_pager_area *area;
	struct tee_pager_area *next_a;

	TAILQ_FOREACH_SAFE(area, src_utc->areas, link, next_a) {
		vaddr_t new_area_base;
		size_t new_idx;

		if (!core_is_buffer_inside(area->base, area->size,
					  src_base, size))
			continue;

		TAILQ_REMOVE(src_utc->areas, area, link);

		new_area_base = dst_base + (src_base - area->base);
		new_idx = (new_area_base - dst_pgt[0]->vabase) /
			  CORE_MMU_PGDIR_SIZE;
		assert((new_area_base & ~CORE_MMU_PGDIR_MASK) ==
		       dst_pgt[new_idx]->vabase);
		transpose_area(area, dst_pgt[new_idx], new_area_base);

		/*
		 * Assert that this will not cause any conflicts in the new
		 * utc.  This should already be guaranteed, but a bug here
		 * could be tricky to find.
		 */
		assert(!find_area(dst_utc->areas, area->base));
		TAILQ_INSERT_TAIL(dst_utc->areas, area, link);
	}
}

static void rem_area(struct tee_pager_area_head *area_head,
		     struct tee_pager_area *area)
{
	struct tee_pager_pmem *pmem;
	uint32_t exceptions;

	exceptions = pager_lock_check_stack(64);

	TAILQ_REMOVE(area_head, area, link);

	TAILQ_FOREACH(pmem, &tee_pager_pmem_head, link) {
		if (pmem->area == area) {
			area_set_entry(area, pmem->pgidx, 0, 0);
			tlbi_mva_allasid(area_idx2va(area, pmem->pgidx));
			pgt_dec_used_entries(area->pgt);
			pmem->area = NULL;
			pmem->pgidx = INVALID_PGIDX;
		}
	}

	pager_unlock(exceptions);
	free_area(area);
}
KEEP_PAGER(rem_area);

void tee_pager_rem_uta_region(struct user_ta_ctx *utc, vaddr_t base,
			      size_t size)
{
	struct tee_pager_area *area;
	struct tee_pager_area *next_a;
	size_t s = ROUNDUP(size, SMALL_PAGE_SIZE);

	TAILQ_FOREACH_SAFE(area, utc->areas, link, next_a) {
		if (core_is_buffer_inside(area->base, area->size, base, s))
			rem_area(utc->areas, area);
	}
}

void tee_pager_rem_uta_areas(struct user_ta_ctx *utc)
{
	struct tee_pager_area *area;

	if (!utc->areas)
		return;

	while (true) {
		area = TAILQ_FIRST(utc->areas);
		if (!area)
			break;
		TAILQ_REMOVE(utc->areas, area, link);
		free_area(area);
	}

	free(utc->areas);
}

bool tee_pager_set_uta_area_attr(struct user_ta_ctx *utc, vaddr_t base,
				 size_t size, uint32_t flags)
{
	bool ret;
	vaddr_t b = base;
	size_t s = size;
	size_t s2;
	struct tee_pager_area *area = find_area(utc->areas, b);
	uint32_t exceptions;
	struct tee_pager_pmem *pmem;
	paddr_t pa;
	uint32_t a;
	uint32_t f;

	f = (flags & TEE_MATTR_URWX) | TEE_MATTR_UR | TEE_MATTR_PR;
	if (f & TEE_MATTR_UW)
		f |= TEE_MATTR_PW;
	f = get_area_mattr(f);

	exceptions = pager_lock_check_stack(SMALL_PAGE_SIZE);

	while (s) {
		s2 = MIN(CORE_MMU_PGDIR_SIZE - (b & CORE_MMU_PGDIR_MASK), s);
		if (!area || area->base != b || area->size != s2) {
			ret = false;
			goto out;
		}
		b += s2;
		s -= s2;

		TAILQ_FOREACH(pmem, &tee_pager_pmem_head, link) {
			if (pmem->area != area)
				continue;
			area_get_entry(pmem->area, pmem->pgidx, &pa, &a);
			if (a & TEE_MATTR_VALID_BLOCK)
				assert(pa == get_pmem_pa(pmem));
			else
				pa = get_pmem_pa(pmem);
			if (a == f)
				continue;
			area_set_entry(pmem->area, pmem->pgidx, 0, 0);
			tlbi_mva_allasid(area_idx2va(pmem->area, pmem->pgidx));
			if (!(flags & TEE_MATTR_UW))
				tee_pager_save_page(pmem, a);

			area_set_entry(pmem->area, pmem->pgidx, pa, f);
			/*
			 * Make sure the table update is visible before
			 * continuing.
			 */
			dsb_ishst();

			if (flags & TEE_MATTR_UX) {
				void *va = (void *)area_idx2va(pmem->area,
							       pmem->pgidx);

				cache_op_inner(DCACHE_AREA_CLEAN, va,
						SMALL_PAGE_SIZE);
				cache_op_inner(ICACHE_AREA_INVALIDATE, va,
						SMALL_PAGE_SIZE);
			}
		}

		area->flags = f;
		area = TAILQ_NEXT(area, link);
	}

	ret = true;
out:
	pager_unlock(exceptions);
	return ret;
}
KEEP_PAGER(tee_pager_set_uta_area_attr);
#endif /*CFG_PAGED_USER_TA*/

static bool tee_pager_unhide_page(vaddr_t page_va)
{
	struct tee_pager_pmem *pmem;

	TAILQ_FOREACH(pmem, &tee_pager_pmem_head, link) {
		paddr_t pa;
		uint32_t attr;

		if (pmem->pgidx == INVALID_PGIDX)
			continue;

		area_get_entry(pmem->area, pmem->pgidx, &pa, &attr);

		if (!(attr &
		     (TEE_MATTR_HIDDEN_BLOCK | TEE_MATTR_HIDDEN_DIRTY_BLOCK)))
			continue;

		if (area_va2idx(pmem->area, page_va) == pmem->pgidx) {
			uint32_t a = get_area_mattr(pmem->area->flags);

			/* page is hidden, show and move to back */
			if (pa != get_pmem_pa(pmem))
				panic("unexpected pa");

			/*
			 * If it's not a dirty block, then it should be
			 * read only.
			 */
			if (!(attr & TEE_MATTR_HIDDEN_DIRTY_BLOCK))
				a &= ~(TEE_MATTR_PW | TEE_MATTR_UW);
			else
				FMSG("Unhide %#" PRIxVA, page_va);

			if (page_va == 0x8000a000)
				FMSG("unhide %#" PRIxVA " a %#" PRIX32,
					page_va, a);
			area_set_entry(pmem->area, pmem->pgidx, pa, a);
			/*
			 * Note that TLB invalidation isn't needed since
			 * there wasn't a valid mapping before. We should
			 * use a barrier though, to make sure that the
			 * change is visible.
			 */
			dsb_ishst();

			TAILQ_REMOVE(&tee_pager_pmem_head, pmem, link);
			TAILQ_INSERT_TAIL(&tee_pager_pmem_head, pmem, link);
			incr_hidden_hits();
			return true;
		}
	}

	return false;
}

static void tee_pager_hide_pages(void)
{
	struct tee_pager_pmem *pmem;
	size_t n = 0;

	TAILQ_FOREACH(pmem, &tee_pager_pmem_head, link) {
		paddr_t pa;
		uint32_t attr;
		uint32_t a;

		if (n >= TEE_PAGER_NHIDE)
			break;
		n++;

		/* we cannot hide pages when pmem->area is not defined. */
		if (!pmem->area)
			continue;

		area_get_entry(pmem->area, pmem->pgidx, &pa, &attr);
		if (!(attr & TEE_MATTR_VALID_BLOCK))
			continue;

		assert(pa == get_pmem_pa(pmem));
		if (attr & (TEE_MATTR_PW | TEE_MATTR_UW)){
			a = TEE_MATTR_HIDDEN_DIRTY_BLOCK;
			FMSG("Hide %#" PRIxVA,
			     area_idx2va(pmem->area, pmem->pgidx));
		} else
			a = TEE_MATTR_HIDDEN_BLOCK;

		area_set_entry(pmem->area, pmem->pgidx, pa, a);
		tlbi_mva_allasid(area_idx2va(pmem->area, pmem->pgidx));
	}
}

/*
 * Find mapped pmem, hide and move to pageble pmem.
 * Return false if page was not mapped, and true if page was mapped.
 */
static bool tee_pager_release_one_phys(struct tee_pager_area *area,
				       vaddr_t page_va)
{
	struct tee_pager_pmem *pmem;
	unsigned pgidx;
	paddr_t pa;
	uint32_t attr;

	pgidx = area_va2idx(area, page_va);
	area_get_entry(area, pgidx, &pa, &attr);

	FMSG("%" PRIxVA " : %" PRIxPA "|%x", page_va, pa, attr);

	TAILQ_FOREACH(pmem, &tee_pager_lock_pmem_head, link) {
		if (pmem->area != area || pmem->pgidx != pgidx)
			continue;

		assert(pa == get_pmem_pa(pmem));
		area_set_entry(area, pgidx, 0, 0);
		pgt_dec_used_entries(area->pgt);
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
static struct tee_pager_pmem *tee_pager_get_page(struct tee_pager_area *area)
{
	struct tee_pager_pmem *pmem;

	pmem = TAILQ_FIRST(&tee_pager_pmem_head);
	if (!pmem) {
		EMSG("No pmem entries");
		return NULL;
	}
	if (pmem->pgidx != INVALID_PGIDX) {
		uint32_t a;

		assert(pmem->area && pmem->area->pgt);
		area_get_entry(pmem->area, pmem->pgidx, NULL, &a);
		area_set_entry(pmem->area, pmem->pgidx, 0, 0);
		pgt_dec_used_entries(pmem->area->pgt);
		tlbi_mva_allasid(area_idx2va(pmem->area, pmem->pgidx));
		tee_pager_save_page(pmem, a);
	}

	TAILQ_REMOVE(&tee_pager_pmem_head, pmem, link);
	pmem->pgidx = INVALID_PGIDX;
	pmem->area = NULL;
	if (area->type == AREA_TYPE_LOCK) {
		/* Move page to lock list */
		if (tee_pager_npages <= 0)
			panic("running out of page");
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
			struct abort_info *ai, bool *handled)
{
	unsigned int pgidx = area_va2idx(area, ai->va);
	uint32_t attr;
	paddr_t pa;

	*handled = false;

	area_get_entry(area, pgidx, &pa, &attr);

	/* Not mapped */
	if (!(attr & TEE_MATTR_VALID_BLOCK))
		return false;

	/* Not readable, should not happen */
	if (abort_is_user_exception(ai)) {
		if (!(attr & TEE_MATTR_UR))
			return true;
	} else {
		if (!(attr & TEE_MATTR_PR)) {
			abort_print_error(ai);
			panic();
		}
	}

	switch (core_mmu_get_fault_type(ai->fault_descr)) {
	case CORE_MMU_FAULT_TRANSLATION:
	case CORE_MMU_FAULT_READ_PERMISSION:
		if (ai->abort_type == ABORT_TYPE_PREFETCH) {
			/* Check attempting to execute from an NOX page */
			if (abort_is_user_exception(ai)) {
				if (!(attr & TEE_MATTR_UX))
					return true;
			} else {
				if (!(attr & TEE_MATTR_PX)) {
					abort_print_error(ai);
					panic();
				}
			}
		}
		/* Since the page is mapped now it's OK */
		break;
	case CORE_MMU_FAULT_WRITE_PERMISSION:
		/* Check attempting to write to an RO page */
		if (abort_is_user_exception(ai)) {
			if (!(area->flags & TEE_MATTR_UW))
				return true;
			if (!(attr & TEE_MATTR_UW)) {
				FMSG("Dirty %p",
				     (void *)(ai->va & ~SMALL_PAGE_MASK));
				area_set_entry(area, pgidx, pa,
					       get_area_mattr(area->flags));
				tlbi_mva_allasid(ai->va & ~SMALL_PAGE_MASK);
			}

		} else {
			if (!(area->flags & TEE_MATTR_PW)) {
				abort_print_error(ai);
				panic();
			}
			if (!(attr & TEE_MATTR_PW)) {
				FMSG("Dirty %p",
				     (void *)(ai->va & ~SMALL_PAGE_MASK));
				area_set_entry(area, pgidx, pa,
					       get_area_mattr(area->flags));
				tlbi_mva_allasid(ai->va & ~SMALL_PAGE_MASK);
			}
		}
		/* Since permissions has been updated now it's OK */
		break;
	default:
		/* Some fault we can't deal with */
		if (abort_is_user_exception(ai))
			return true;
		abort_print_error(ai);
		panic();
	}
	*handled = true;
	return true;
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
	exceptions = pager_lock(ai);

	stat_handle_fault();

	/* check if the access is valid */
	if (abort_is_user_exception(ai)) {
		area = find_uta_area(ai->va);

	} else {
		area = find_area(&tee_pager_area_head, ai->va);
		if (!area)
			area = find_uta_area(ai->va);
	}
	if (!area || !area->pgt) {
		ret = false;
		goto out;
	}

	if (!tee_pager_unhide_page(page_va)) {
		struct tee_pager_pmem *pmem = NULL;
		uint32_t attr;
		paddr_t pa;

		/*
		 * The page wasn't hidden, but some other core may have
		 * updated the table entry before we got here or we need
		 * to make a read-only page read-write (dirty).
		 */
		if (pager_update_permissions(area, ai, &ret)) {
			/*
			 * Nothing more to do with the abort. The problem
			 * could already have been dealt with from another
			 * core or if ret is false the TA will be paniced.
			 */
			goto out;
		}

		pmem = tee_pager_get_page(area);
		if (!pmem) {
			abort_print(ai);
			panic();
		}

		/* load page code & data */
		tee_pager_load_page(area, page_va, pmem->va_alias);


		pmem->area = area;
		pmem->pgidx = area_va2idx(area, ai->va);
		attr = get_area_mattr(area->flags) &
			~(TEE_MATTR_PW | TEE_MATTR_UW);
		pa = get_pmem_pa(pmem);

		/*
		 * We've updated the page using the aliased mapping and
		 * some cache maintenence is now needed if it's an
		 * executable page.
		 *
		 * Since the d-cache is a Physically-indexed,
		 * physically-tagged (PIPT) cache we can clean either the
		 * aliased address or the real virtual address. In this
		 * case we choose the real virtual address.
		 *
		 * The i-cache can also be PIPT, but may be something else
		 * too like VIPT. The current code requires the caches to
		 * implement the IVIPT extension, that is:
		 * "instruction cache maintenance is required only after
		 * writing new data to a physical address that holds an
		 * instruction."
		 *
		 * To portably invalidate the icache the page has to
		 * be mapped at the final virtual address but not
		 * executable.
		 */
		if (area->flags & (TEE_MATTR_PX | TEE_MATTR_UX)) {
			uint32_t mask = TEE_MATTR_PX | TEE_MATTR_UX |
					TEE_MATTR_PW | TEE_MATTR_UW;

			/* Set a temporary read-only mapping */
			area_set_entry(pmem->area, pmem->pgidx, pa,
				       attr & ~mask);
			tlbi_mva_allasid(page_va);

			/*
			 * Doing these operations to LoUIS (Level of
			 * unification, Inner Shareable) would be enough
			 */
			cache_op_inner(DCACHE_AREA_CLEAN, (void *)page_va,
				       SMALL_PAGE_SIZE);
			cache_op_inner(ICACHE_AREA_INVALIDATE, (void *)page_va,
				       SMALL_PAGE_SIZE);

			/* Set the final mapping */
			area_set_entry(area, pmem->pgidx, pa, attr);
			tlbi_mva_allasid(page_va);
		} else {
			area_set_entry(area, pmem->pgidx, pa, attr);
			/*
			 * No need to flush TLB for this entry, it was
			 * invalid. We should use a barrier though, to make
			 * sure that the change is visible.
			 */
			dsb_ishst();
		}
		pgt_inc_used_entries(area->pgt);

		FMSG("Mapped 0x%" PRIxVA " -> 0x%" PRIxPA, page_va, pa);

	}

	tee_pager_hide_pages();
	ret = true;
out:
	pager_unlock(exceptions);
	return ret;
}

void tee_pager_add_pages(vaddr_t vaddr, size_t npages, bool unmap)
{
	size_t n;

	DMSG("0x%" PRIxVA " - 0x%" PRIxVA " : %d",
	     vaddr, vaddr + npages * SMALL_PAGE_SIZE, (int)unmap);

	/* setup memory */
	for (n = 0; n < npages; n++) {
		struct core_mmu_table_info *ti;
		struct tee_pager_pmem *pmem;
		vaddr_t va = vaddr + n * SMALL_PAGE_SIZE;
		unsigned int pgidx;
		paddr_t pa;
		uint32_t attr;

		ti = find_table_info(va);
		pgidx = core_mmu_va2idx(ti, va);
		/*
		 * Note that we can only support adding pages in the
		 * valid range of this table info, currently not a problem.
		 */
		core_mmu_get_entry(ti, pgidx, &pa, &attr);

		/* Ignore unmapped pages/blocks */
		if (!(attr & TEE_MATTR_VALID_BLOCK))
			continue;

		pmem = malloc(sizeof(struct tee_pager_pmem));
		if (!pmem)
			panic("out of mem");

		pmem->va_alias = pager_add_alias_page(pa);

		if (unmap) {
			pmem->area = NULL;
			pmem->pgidx = INVALID_PGIDX;
			core_mmu_set_entry(ti, pgidx, 0, 0);
			pgt_dec_used_entries(find_core_pgt(va));
		} else {
			/*
			 * The page is still mapped, let's assign the area
			 * and update the protection bits accordingly.
			 */
			pmem->area = find_area(&tee_pager_area_head, va);
			assert(pmem->area->pgt == find_core_pgt(va));
			pmem->pgidx = pgidx;
			assert(pa == get_pmem_pa(pmem));
			area_set_entry(pmem->area, pgidx, pa,
				       get_area_mattr(pmem->area->flags));
		}

		tee_pager_npages++;
		incr_npages_all();
		set_npages();
		TAILQ_INSERT_TAIL(&tee_pager_pmem_head, pmem, link);
	}

	/*
	 * As this is done at inits, invalidate all TLBs once instead of
	 * targeting only the modified entries.
	 */
	tlbi_all();
}

#ifdef CFG_PAGED_USER_TA
static struct pgt *find_pgt(struct pgt *pgt, vaddr_t va)
{
	struct pgt *p = pgt;

	while (p && (va & ~CORE_MMU_PGDIR_MASK) != p->vabase)
		p = SLIST_NEXT(p, link);
	return p;
}

void tee_pager_assign_uta_tables(struct user_ta_ctx *utc)
{
	struct tee_pager_area *area;
	struct pgt *pgt = SLIST_FIRST(&thread_get_tsd()->pgt_cache);

	TAILQ_FOREACH(area, utc->areas, link) {
		if (!area->pgt)
			area->pgt = find_pgt(pgt, area->base);
		else
			assert(area->pgt == find_pgt(pgt, area->base));
		if (!area->pgt)
			panic();
	}
}

static void pager_save_and_release_entry(struct tee_pager_pmem *pmem)
{
	uint32_t attr;

	assert(pmem->area && pmem->area->pgt);

	area_get_entry(pmem->area, pmem->pgidx, NULL, &attr);
	area_set_entry(pmem->area, pmem->pgidx, 0, 0);
	tlbi_mva_allasid(area_idx2va(pmem->area, pmem->pgidx));
	tee_pager_save_page(pmem, attr);
	assert(pmem->area->pgt->num_used_entries);
	pmem->area->pgt->num_used_entries--;
	pmem->pgidx = INVALID_PGIDX;
	pmem->area = NULL;
}

void tee_pager_pgt_save_and_release_entries(struct pgt *pgt)
{
	struct tee_pager_pmem *pmem;
	struct tee_pager_area *area;
	uint32_t exceptions = pager_lock_check_stack(SMALL_PAGE_SIZE);

	if (!pgt->num_used_entries)
		goto out;

	TAILQ_FOREACH(pmem, &tee_pager_pmem_head, link) {
		if (!pmem->area || pmem->pgidx == INVALID_PGIDX)
			continue;
		if (pmem->area->pgt == pgt)
			pager_save_and_release_entry(pmem);
	}
	assert(!pgt->num_used_entries);

out:
	if (is_user_ta_ctx(pgt->ctx)) {
		TAILQ_FOREACH(area, to_user_ta_ctx(pgt->ctx)->areas, link) {
			if (area->pgt == pgt)
				area->pgt = NULL;
		}
	}

	pager_unlock(exceptions);
}
KEEP_PAGER(tee_pager_pgt_save_and_release_entries);
#endif /*CFG_PAGED_USER_TA*/

void tee_pager_release_phys(void *addr, size_t size)
{
	bool unmaped = false;
	vaddr_t va = (vaddr_t)addr;
	vaddr_t begin = ROUNDUP(va, SMALL_PAGE_SIZE);
	vaddr_t end = ROUNDDOWN(va + size, SMALL_PAGE_SIZE);
	struct tee_pager_area *area;
	uint32_t exceptions;

	if (end <= begin)
		return;

	exceptions = pager_lock_check_stack(128);

	for (va = begin; va < end; va += SMALL_PAGE_SIZE) {
		area = find_area(&tee_pager_area_head, va);
		if (!area)
			panic();
		unmaped |= tee_pager_release_one_phys(area, va);
	}

	if (unmaped)
		tlbi_mva_range(begin, end - begin, SMALL_PAGE_SIZE);

	pager_unlock(exceptions);
}
KEEP_PAGER(tee_pager_release_phys);

void *tee_pager_alloc(size_t size, uint32_t flags)
{
	tee_mm_entry_t *mm;
	uint32_t f = TEE_MATTR_PW | TEE_MATTR_PR | (flags & TEE_MATTR_LOCKED);
	uint8_t *smem;
	size_t bytes;

	if (!size)
		return NULL;

	mm = tee_mm_alloc(&tee_mm_vcore, ROUNDUP(size, SMALL_PAGE_SIZE));
	if (!mm)
		return NULL;

	bytes = tee_mm_get_bytes(mm);
	smem = (uint8_t *)tee_mm_get_smem(mm);
	tee_pager_add_core_area((vaddr_t)smem, bytes, f, NULL, NULL);
	asan_tag_access(smem, smem + bytes);

	return smem;
}
