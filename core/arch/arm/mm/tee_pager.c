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

#include <sys/queue.h>
#include <stdlib.h>
#include <inttypes.h>
#include <kernel/tee_common_unpg.h>
#include <kernel/tee_common.h>
#include <kernel/thread_defs.h>
#include <kernel/panic.h>
#include <mm/tee_mmu_defs.h>
#include <kernel/tee_ta_manager.h>
#include <kernel/tee_kta_trace.h>
#include <kernel/misc.h>
#include <kernel/tee_misc.h>
#include <kernel/tz_proc.h>
#include <mm/tee_pager.h>
#include <mm/tee_mm.h>
#include <mm/core_mmu.h>
#include <tee/arch_svc.h>
#include <arm.h>
#include <tee/tee_cryp_provider.h>
#include <tee_api_defines.h>
#include <utee_defines.h>
#include <trace.h>
#include <util.h>

struct tee_pager_abort_info {
	uint32_t abort_type;
	uint32_t fault_descr;
	vaddr_t va;
	uint32_t pc;
	struct thread_abort_regs *regs;
};

enum tee_pager_fault_type {
	TEE_PAGER_FAULT_TYPE_USER_TA_PANIC,
	TEE_PAGER_FAULT_TYPE_PAGEABLE,
	TEE_PAGER_FAULT_TYPE_IGNORE,
};

#ifdef CFG_WITH_PAGER

struct tee_pager_area {
	const uint8_t *hashes;
	const uint8_t *store;
	uint32_t flags;
	tee_mm_entry_t *mm;
	TAILQ_ENTRY(tee_pager_area) link;
};

static TAILQ_HEAD(tee_pager_area_head, tee_pager_area) tee_pager_area_head =
	TAILQ_HEAD_INITIALIZER(tee_pager_area_head);

/*
 * struct tee_pager_pmem - Represents a physical page used for paging.
 *
 * @pgidx	an index of the entry in tbl_info. The actual physical
 *		address is stored here so even if the page isn't mapped,
 *		there's always an MMU entry holding the physical address.
 *
 * @va_alias	Virtual address where the physical page always is aliased.
 *		Used during remapping of the page when the content need to
 *		be updated before it's available at the new location.
 *
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

static struct tee_pager_pmem_head tee_pager_rw_pmem_head =
	TAILQ_HEAD_INITIALIZER(tee_pager_rw_pmem_head);

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

/*
 * Reference to translation table used to map the virtual memory range
 * covered by the pager.
 */
static struct core_mmu_table_info tbl_info;

static unsigned pager_lock = SPINLOCK_UNLOCK;

/* Defines the range of the alias area */
static tee_mm_entry_t *pager_alias_area;
/*
 * Physical pages are added in a stack like fashion to the alias area,
 * @pager_alias_next_free gives the address of next free entry if
 * @pager_alias_next_free is != 0
 */
static uintptr_t pager_alias_next_free;

void tee_pager_set_alias_area(tee_mm_entry_t *mm)
{
	struct core_mmu_table_info ti;
	size_t tbl_va_size;
	unsigned idx;
	unsigned last_idx;
	vaddr_t smem = tee_mm_get_smem(mm);
	size_t nbytes = tee_mm_get_bytes(mm);

	DMSG("0x%" PRIxVA " - 0x%" PRIxVA, smem, smem + nbytes);

	TEE_ASSERT(!pager_alias_area);
	if (!core_mmu_find_table(smem, UINT_MAX, &ti)) {
		DMSG("Can't find translation table");
		panic();
	}
	if ((1 << ti.shift) != SMALL_PAGE_SIZE) {
		DMSG("Unsupported page size in translation table %u",
		     1 << ti.shift);
		panic();
	}

	tbl_va_size = (1 << ti.shift) * ti.num_entries;
	if (!core_is_buffer_inside(smem, nbytes,
				   ti.va_base, tbl_va_size)) {
		DMSG("area 0x%" PRIxVA " len 0x%zx doesn't fit it translation table 0x%" PRIxVA " len 0x%zx",
			smem, nbytes, ti.va_base, tbl_va_size);
		panic();
	}

	TEE_ASSERT(!(smem & SMALL_PAGE_MASK));
	TEE_ASSERT(!(nbytes & SMALL_PAGE_MASK));

	pager_alias_area = mm;
	pager_alias_next_free = smem;

	/* Clear all mapping in the alias area */
	idx = core_mmu_va2idx(&ti, smem);
	last_idx = core_mmu_va2idx(&ti, smem + nbytes);
	for (; idx < last_idx; idx++)
		core_mmu_set_entry(&ti, idx, 0, 0);
}

static void *pager_add_alias_page(paddr_t pa)
{
	unsigned idx;
	struct core_mmu_table_info ti;
	uint32_t attr = TEE_MATTR_VALID_BLOCK | TEE_MATTR_GLOBAL |
			TEE_MATTR_CACHE_DEFAULT | TEE_MATTR_SECURE |
			TEE_MATTR_PRW;

	DMSG("0x%" PRIxPA, pa);

	TEE_ASSERT(pager_alias_next_free);
	if (!core_mmu_find_table(pager_alias_next_free, UINT_MAX, &ti))
		panic();
	idx = core_mmu_va2idx(&ti, pager_alias_next_free);
	core_mmu_set_entry(&ti, idx, pa, attr);
	pager_alias_next_free += SMALL_PAGE_SIZE;
	if (pager_alias_next_free >= (tee_mm_get_smem(pager_alias_area) +
				      tee_mm_get_bytes(pager_alias_area)))
		pager_alias_next_free = 0;
	return (void *)core_mmu_idx2va(&ti, idx);
}

bool tee_pager_add_area(tee_mm_entry_t *mm, uint32_t flags, const void *store,
		const void *hashes)
{
	struct tee_pager_area *area;
	size_t tbl_va_size;

	DMSG("0x%" PRIxPTR " - 0x%" PRIxPTR " : flags 0x%x, store %p, hashes %p",
		tee_mm_get_smem(mm),
		tee_mm_get_smem(mm) + (mm->size << mm->pool->shift),
		flags, store, hashes);

	if (flags & TEE_PAGER_AREA_RO)
		TEE_ASSERT(store && hashes);
	else if (flags & TEE_PAGER_AREA_RW)
		TEE_ASSERT(!store && !hashes);
	else
		panic();

	if (!tbl_info.num_entries) {
		if (!core_mmu_find_table(tee_mm_get_smem(mm), UINT_MAX,
					&tbl_info))
			return false;
		if ((1 << tbl_info.shift) != SMALL_PAGE_SIZE) {
			DMSG("Unsupported page size in translation table %u",
			     1 << tbl_info.shift);
			return false;
		}
	}

	tbl_va_size = (1 << tbl_info.shift) * tbl_info.num_entries;
	if (!core_is_buffer_inside(tee_mm_get_smem(mm), tee_mm_get_bytes(mm),
				   tbl_info.va_base, tbl_va_size)) {
		DMSG("area 0x%" PRIxPTR " len 0x%zx doesn't fit it translation table 0x%" PRIxVA " len 0x%zx",
			tee_mm_get_smem(mm), tee_mm_get_bytes(mm),
			tbl_info.va_base, tbl_va_size);
		return false;
	}

	area = malloc(sizeof(struct tee_pager_area));
	if (!area)
		return false;

	area->mm = mm;
	area->flags = flags;
	area->store = store;
	area->hashes = hashes;
	TAILQ_INSERT_TAIL(&tee_pager_area_head, area, link);
	return true;
}

static struct tee_pager_area *tee_pager_find_area(vaddr_t va)
{
	struct tee_pager_area *area;

	TAILQ_FOREACH(area, &tee_pager_area_head, link) {
		tee_mm_entry_t *mm = area->mm;
		size_t offset = (va - mm->pool->lo) >> mm->pool->shift;

		if (offset >= mm->offset && offset < (mm->offset + mm->size))
			return area;
	}
	return NULL;
}

static uint32_t get_area_mattr(struct tee_pager_area *area)
{
	uint32_t attr = TEE_MATTR_VALID_BLOCK | TEE_MATTR_GLOBAL |
			TEE_MATTR_CACHE_DEFAULT | TEE_MATTR_SECURE |
			TEE_MATTR_PR;

	if (!(area->flags & TEE_PAGER_AREA_RO))
		attr |= TEE_MATTR_PW;
	if (area->flags & TEE_PAGER_AREA_X)
		attr |= TEE_MATTR_PX;

	return attr;
}

static void tee_pager_load_page(struct tee_pager_area *area, vaddr_t page_va,
			void *va_alias)
{
	size_t pg_idx = (page_va - area->mm->pool->lo) >> SMALL_PAGE_SHIFT;

	if (area->store) {
		size_t rel_pg_idx = pg_idx - area->mm->offset;
		const void *stored_page = area->store +
					  rel_pg_idx * SMALL_PAGE_SIZE;

		memcpy(va_alias, stored_page, SMALL_PAGE_SIZE);
		incr_ro_hits();
	} else {
		memset(va_alias, 0, SMALL_PAGE_SIZE);
		incr_rw_hits();
	}
}

static void tee_pager_verify_page(struct tee_pager_area *area, vaddr_t page_va,
			void *va_alias)
{
	size_t pg_idx = (page_va - area->mm->pool->lo) >> SMALL_PAGE_SHIFT;

	if (area->store) {
		size_t rel_pg_idx = pg_idx - area->mm->offset;
		const void *hash = area->hashes +
				   rel_pg_idx * TEE_SHA256_HASH_SIZE;

		if (hash_sha256_check(hash, va_alias, SMALL_PAGE_SIZE) !=
				TEE_SUCCESS) {
			EMSG("PH 0x%" PRIxVA " failed", page_va);
			panic();
		}
	}
}

static bool tee_pager_unhide_page(vaddr_t page_va)
{
	struct tee_pager_pmem *pmem;

	TAILQ_FOREACH(pmem, &tee_pager_pmem_head, link) {
		paddr_t pa;
		uint32_t attr;

		core_mmu_get_entry(&tbl_info, pmem->pgidx, &pa, &attr);

		if (!(attr & TEE_MATTR_HIDDEN_BLOCK))
			continue;

		if (core_mmu_va2idx(&tbl_info, page_va) == pmem->pgidx) {
			/* page is hidden, show and move to back */
			core_mmu_set_entry(&tbl_info, pmem->pgidx, pa,
					   get_area_mattr(pmem->area));

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
	struct tee_pager_pmem *pmem;
	size_t n = 0;

	TAILQ_FOREACH(pmem, &tee_pager_pmem_head, link) {
		paddr_t pa;
		uint32_t attr;

		if (n >= TEE_PAGER_NHIDE)
			break;
		n++;

		/*
		 * we cannot hide pages when pmem->area is not defined as
		 * unhide requires pmem->area to be defined
		 */
		if (!pmem->area)
			continue;

		core_mmu_get_entry(&tbl_info, pmem->pgidx, &pa, &attr);
		if (!(attr & TEE_MATTR_VALID_BLOCK))
			continue;

		core_mmu_set_entry(&tbl_info, pmem->pgidx, pa,
				   TEE_MATTR_HIDDEN_BLOCK);

	}

	/* TODO only invalidate entries touched above */
	core_tlb_maintenance(TLBINV_UNIFIEDTLB, 0);
}

/*
 * Find mapped pmem, hide and move to pageble pmem.
 * Return false if page was not mapped, and true if page was mapped.
 */
static bool tee_pager_release_one_zi(vaddr_t page_va)
{
	struct tee_pager_pmem *pmem;
	unsigned pgidx;
	paddr_t pa;
	uint32_t attr;

	pgidx = core_mmu_va2idx(&tbl_info, page_va);
	core_mmu_get_entry(&tbl_info, pgidx, &pa, &attr);

#ifdef TEE_PAGER_DEBUG_PRINT
	DMSG("%" PRIxVA " : %" PRIxPA "|%x", page_va, pa, attr);
#endif

	TAILQ_FOREACH(pmem, &tee_pager_rw_pmem_head, link) {
		if (pmem->pgidx != pgidx)
			continue;

		core_mmu_set_entry(&tbl_info, pgidx, pa, TEE_MATTR_PHYS_BLOCK);
		TAILQ_REMOVE(&tee_pager_rw_pmem_head, pmem, link);
		tee_pager_npages++;
		set_npages();
		TAILQ_INSERT_HEAD(&tee_pager_pmem_head, pmem, link);
		incr_zi_released();


		return true;
	}

	return false;
}
#endif /*CFG_WITH_PAGER*/

#ifdef ARM32
/* Returns true if the exception originated from user mode */
static bool tee_pager_is_user_exception(struct tee_pager_abort_info *ai)
{
	return (ai->regs->spsr & ARM32_CPSR_MODE_MASK) == ARM32_CPSR_MODE_USR;
}
#endif /*ARM32*/

#ifdef ARM64
/* Returns true if the exception originated from user mode */
static bool tee_pager_is_user_exception(struct tee_pager_abort_info *ai)
{
	uint32_t spsr = ai->regs->spsr;

	if (spsr & (SPSR_MODE_RW_32 << SPSR_MODE_RW_SHIFT))
		return true;
	if (((spsr >> SPSR_64_MODE_EL_SHIFT) & SPSR_64_MODE_EL_MASK) ==
	    SPSR_64_MODE_EL0)
		return true;
	return false;
}
#endif /*ARM64*/

#ifdef ARM32
/* Returns true if the exception originated from abort mode */
static bool tee_pager_is_abort_in_abort_handler(struct tee_pager_abort_info *ai)
{
	return (ai->regs->spsr & ARM32_CPSR_MODE_MASK) == ARM32_CPSR_MODE_ABT;
}
#endif /*ARM32*/

#ifdef ARM64
/* Returns true if the exception originated from abort mode */
static bool tee_pager_is_abort_in_abort_handler(
		struct tee_pager_abort_info *ai __unused)
{
	return false;
}
#endif /*ARM64*/

static __unused const char *abort_type_to_str(uint32_t abort_type)
{
	if (abort_type == THREAD_ABORT_DATA)
		return "data";
	if (abort_type == THREAD_ABORT_PREFETCH)
		return "prefetch";
	return "undef";
}

static __unused void tee_pager_print_detailed_abort(
				struct tee_pager_abort_info *ai __unused,
				const char *ctx __unused)
{
	EMSG_RAW("\n");
	EMSG_RAW("%s %s-abort at address 0x%" PRIxVA "\n",
		ctx, abort_type_to_str(ai->abort_type), ai->va);
#ifdef ARM32
	EMSG_RAW(" fsr 0x%08x  ttbr0 0x%08x  ttbr1 0x%08x  cidr 0x%X\n",
		 ai->fault_descr, read_ttbr0(), read_ttbr1(),
		 read_contextidr());
	EMSG_RAW(" cpu #%zu          cpsr 0x%08x\n",
		 get_core_pos(), ai->regs->spsr);
	EMSG_RAW(" r0 0x%08x      r4 0x%08x    r8 0x%08x   r12 0x%08x\n",
		 ai->regs->r0, ai->regs->r4, ai->regs->r8, ai->regs->ip);
	EMSG_RAW(" r1 0x%08x      r5 0x%08x    r9 0x%08x    sp 0x%08x\n",
		 ai->regs->r1, ai->regs->r5, ai->regs->r9,
		 read_mode_sp(ai->regs->spsr & CPSR_MODE_MASK));
	EMSG_RAW(" r2 0x%08x      r6 0x%08x   r10 0x%08x    lr 0x%08x\n",
		 ai->regs->r2, ai->regs->r6, ai->regs->r10,
		 read_mode_lr(ai->regs->spsr & CPSR_MODE_MASK));
	EMSG_RAW(" r3 0x%08x      r7 0x%08x   r11 0x%08x    pc 0x%08x\n",
		 ai->regs->r3, ai->regs->r7, ai->regs->r11, ai->pc);
#endif /*ARM32*/
#ifdef ARM64
	EMSG_RAW(" esr 0x%08x  ttbr0 0x%08" PRIx64 "   ttbr1 0x%08" PRIx64 "   cidr 0x%X\n",
		 ai->fault_descr, read_ttbr0_el1(), read_ttbr1_el1(),
		 read_contextidr_el1());
	EMSG_RAW(" cpu #%zu          cpsr 0x%08x\n",
		 get_core_pos(), (uint32_t)ai->regs->spsr);
	EMSG_RAW("x0  %016" PRIx64 " x1  %016" PRIx64,
		 ai->regs->x0, ai->regs->x1);
	EMSG_RAW("x2  %016" PRIx64 " x3  %016" PRIx64,
		 ai->regs->x2, ai->regs->x3);
	EMSG_RAW("x4  %016" PRIx64 " x5  %016" PRIx64,
		 ai->regs->x4, ai->regs->x5);
	EMSG_RAW("x6  %016" PRIx64 " x7  %016" PRIx64,
		 ai->regs->x6, ai->regs->x7);
	EMSG_RAW("x8  %016" PRIx64 " x9  %016" PRIx64,
		 ai->regs->x8, ai->regs->x9);
	EMSG_RAW("x10 %016" PRIx64 " x11 %016" PRIx64,
		 ai->regs->x10, ai->regs->x11);
	EMSG_RAW("x12 %016" PRIx64 " x13 %016" PRIx64,
		 ai->regs->x12, ai->regs->x13);
	EMSG_RAW("x14 %016" PRIx64 " x15 %016" PRIx64,
		 ai->regs->x14, ai->regs->x15);
	EMSG_RAW("x16 %016" PRIx64 " x17 %016" PRIx64,
		 ai->regs->x16, ai->regs->x17);
	EMSG_RAW("x18 %016" PRIx64 " x19 %016" PRIx64,
		 ai->regs->x18, ai->regs->x19);
	EMSG_RAW("x20 %016" PRIx64 " x21 %016" PRIx64,
		 ai->regs->x20, ai->regs->x21);
	EMSG_RAW("x22 %016" PRIx64 " x23 %016" PRIx64,
		 ai->regs->x22, ai->regs->x23);
	EMSG_RAW("x24 %016" PRIx64 " x25 %016" PRIx64,
		 ai->regs->x24, ai->regs->x25);
	EMSG_RAW("x26 %016" PRIx64 " x27 %016" PRIx64,
		 ai->regs->x26, ai->regs->x27);
	EMSG_RAW("x28 %016" PRIx64 " x29 %016" PRIx64,
		 ai->regs->x28, ai->regs->x29);
	EMSG_RAW("x30 %016" PRIx64 " elr %016" PRIx64,
		 ai->regs->x30, ai->regs->elr);
	EMSG_RAW("sp_el0 %016" PRIx64, ai->regs->sp_el0);
#endif /*ARM64*/
}

static void tee_pager_print_user_abort(struct tee_pager_abort_info *ai __unused)
{
#ifdef CFG_TEE_CORE_TA_TRACE
	tee_pager_print_detailed_abort(ai, "user TA");
	tee_ta_dump_current();
#endif
}

static void tee_pager_print_abort(struct tee_pager_abort_info *ai __unused)
{
#if (TRACE_LEVEL >= TRACE_INFO)
	tee_pager_print_detailed_abort(ai, "core");
#endif /*TRACE_LEVEL >= TRACE_DEBUG*/
}

static void tee_pager_print_error_abort(
		struct tee_pager_abort_info *ai __unused)
{
#if (TRACE_LEVEL >= TRACE_INFO)
	/* full verbose log at DEBUG level */
	tee_pager_print_detailed_abort(ai, "core");
#else
#ifdef ARM32
	EMSG("%s-abort at 0x%" PRIxVA "\n"
	     "FSR 0x%x PC 0x%x TTBR0 0x%X CONTEXIDR 0x%X\n"
	     "CPUID 0x%x CPSR 0x%x (read from SPSR)",
	     abort_type_to_str(ai->abort_type),
	     ai->va, ai->fault_descr, ai->pc, read_ttbr0(), read_contextidr(),
	     read_mpidr(), read_spsr());
#endif /*ARM32*/
#ifdef ARM64
	EMSG("%s-abort at 0x%" PRIxVA "\n"
	     "ESR 0x%x PC 0x%x TTBR0 0x%" PRIx64 " CONTEXIDR 0x%X\n"
	     "CPUID 0x%" PRIx64 " CPSR 0x%x (read from SPSR)",
	     abort_type_to_str(ai->abort_type),
	     ai->va, ai->fault_descr, ai->pc, read_ttbr0_el1(),
	     read_contextidr_el1(),
	     read_mpidr_el1(), (uint32_t)ai->regs->spsr);
#endif /*ARM64*/
#endif /*TRACE_LEVEL >= TRACE_DEBUG*/
}

static enum tee_pager_fault_type tee_pager_get_fault_type(
		struct tee_pager_abort_info *ai)
{
	if (tee_pager_is_user_exception(ai)) {
		tee_pager_print_user_abort(ai);
		DMSG("[TEE_PAGER] abort in User mode (TA will panic)");
		return TEE_PAGER_FAULT_TYPE_USER_TA_PANIC;
	}

	if (tee_pager_is_abort_in_abort_handler(ai)) {
		tee_pager_print_error_abort(ai);
		EMSG("[PAGER] abort in abort handler (trap CPU)");
		panic();
	}

	if (ai->abort_type == THREAD_ABORT_UNDEF) {
		tee_pager_print_error_abort(ai);
		EMSG("[TEE_PAGER] undefined abort (trap CPU)");
		panic();
	}

	switch (core_mmu_get_fault_type(ai->fault_descr)) {
	case CORE_MMU_FAULT_ALIGNMENT:
		tee_pager_print_error_abort(ai);
		EMSG("[TEE_PAGER] alignement fault!  (trap CPU)");
		panic();
		break;

	case CORE_MMU_FAULT_ACCESS_BIT:
		tee_pager_print_error_abort(ai);
		EMSG("[TEE_PAGER] access bit fault!  (trap CPU)");
		panic();
		break;

	case CORE_MMU_FAULT_DEBUG_EVENT:
		tee_pager_print_abort(ai);
		DMSG("[TEE_PAGER] Ignoring debug event!");
		return TEE_PAGER_FAULT_TYPE_IGNORE;

	case CORE_MMU_FAULT_TRANSLATION:
	case CORE_MMU_FAULT_WRITE_PERMISSION:
	case CORE_MMU_FAULT_READ_PERMISSION:
		return TEE_PAGER_FAULT_TYPE_PAGEABLE;

	case CORE_MMU_FAULT_ASYNC_EXTERNAL:
		tee_pager_print_abort(ai);
		DMSG("[TEE_PAGER] Ignoring async external abort!");
		return TEE_PAGER_FAULT_TYPE_IGNORE;

	case CORE_MMU_FAULT_OTHER:
	default:
		tee_pager_print_abort(ai);
		DMSG("[TEE_PAGER] Unhandled fault!");
		return TEE_PAGER_FAULT_TYPE_IGNORE;
	}
}


#ifdef CFG_WITH_PAGER

/* Finds the oldest page and remaps it for the new virtual address */
static bool tee_pager_get_page(struct tee_pager_abort_info *ai,
			struct tee_pager_area *area,
			struct tee_pager_pmem **pmem_ret, paddr_t *pa_ret)
{
	unsigned pgidx = core_mmu_va2idx(&tbl_info, ai->va);
	struct tee_pager_pmem *pmem;
	paddr_t pa;
	uint32_t attr;

	core_mmu_get_entry(&tbl_info, pgidx, &pa, &attr);

	assert(!(attr & (TEE_MATTR_VALID_BLOCK | TEE_MATTR_HIDDEN_BLOCK)));

	if (attr & TEE_MATTR_PHYS_BLOCK) {
		/*
		 * There's an pmem entry using this mmu entry, let's use
		 * that entry in the new mapping.
		 */
		TAILQ_FOREACH(pmem, &tee_pager_pmem_head, link) {
			if (pmem->pgidx == pgidx)
				break;
		}
		if (!pmem) {
			DMSG("Couldn't find pmem for pgidx %u", pgidx);
			return false;
		}
	} else {
		pmem = TAILQ_FIRST(&tee_pager_pmem_head);
		if (!pmem) {
			DMSG("No pmem entries");
			return false;
		}
		core_mmu_get_entry(&tbl_info, pmem->pgidx, &pa, &attr);
		core_mmu_set_entry(&tbl_info, pmem->pgidx, 0, 0);
	}

	pmem->pgidx = pgidx;
	pmem->area = area;
	core_mmu_set_entry(&tbl_info, pgidx, pa, TEE_MATTR_PHYS_BLOCK);

	TAILQ_REMOVE(&tee_pager_pmem_head, pmem, link);
	if (area->store) {
		/* move page to back */
		TAILQ_INSERT_TAIL(&tee_pager_pmem_head, pmem, link);
	} else {
		/* Move page to rw list */
		TEE_ASSERT(tee_pager_npages > 0);
		tee_pager_npages--;
		set_npages();
		TAILQ_INSERT_TAIL(&tee_pager_rw_pmem_head, pmem, link);
	}

	/* TODO only invalidate entries touched above */
	core_tlb_maintenance(TLBINV_UNIFIEDTLB, 0);

	*pmem_ret = pmem;
	*pa_ret = pa;
	return true;
}

static bool pager_check_access(struct tee_pager_abort_info *ai)
{
	unsigned pgidx = core_mmu_va2idx(&tbl_info, ai->va);
	uint32_t attr;

	core_mmu_get_entry(&tbl_info, pgidx, NULL, &attr);

	/* Not mapped */
	if (!(attr & TEE_MATTR_VALID_BLOCK))
		return false;

	/* Not readable, should not happen */
	if (!(attr & TEE_MATTR_PR)) {
		tee_pager_print_error_abort(ai);
		panic();
	}

	switch (core_mmu_get_fault_type(ai->fault_descr)) {
	case CORE_MMU_FAULT_TRANSLATION:
	case CORE_MMU_FAULT_READ_PERMISSION:
		if (ai->abort_type == THREAD_ABORT_PREFETCH &&
		    !(attr & TEE_MATTR_PX)) {
			/* Attempting to execute from an NOX page */
			tee_pager_print_error_abort(ai);
			panic();
		}
		/* Since the page is mapped now it's OK */
		return true;
	case CORE_MMU_FAULT_WRITE_PERMISSION:
		if (!(attr & TEE_MATTR_PW)) {
			/* Attempting to write to an RO page */
			tee_pager_print_error_abort(ai);
			panic();
		}
		return true;
	default:
		/* Some fault we can't deal with */
		tee_pager_print_error_abort(ai);
		panic();
	}

}

static void tee_pager_handle_fault(struct tee_pager_abort_info *ai)
{
	struct tee_pager_area *area;
	vaddr_t page_va = ai->va & ~SMALL_PAGE_MASK;
	uint32_t exceptions;

#ifdef TEE_PAGER_DEBUG_PRINT
	tee_pager_print_abort(ai);
#endif

	/* check if the access is valid */
	area = tee_pager_find_area(ai->va);
	if (!area) {
		tee_pager_print_abort(ai);
		DMSG("Invalid addr 0x%" PRIxVA, ai->va);
		panic();
	}

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

	if (!tee_pager_unhide_page(page_va)) {
		struct tee_pager_pmem *pmem = NULL;
		paddr_t pa = 0;

		/*
		 * The page wasn't hidden, but some other core may have
		 * updated the table entry before we got here.
		 */
		if (pager_check_access(ai)) {
			/*
			 * Kind of access is OK with the mapping, we're
			 * done here because the fault has already been
			 * dealt with by another core.
			 */
			goto out;
		}

		if (!tee_pager_get_page(ai, area, &pmem, &pa)) {
			tee_pager_print_abort(ai);
			panic();
		}

		/* load page code & data */
		tee_pager_load_page(area, page_va, pmem->va_alias);
		tee_pager_verify_page(area, page_va, pmem->va_alias);

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
		if (area->flags & TEE_PAGER_AREA_X) {
			/*
			 * Doing these operations to LoUIS (Level of
			 * unification, Inner Shareable) would be enough
			 */
			cache_maintenance_l1(DCACHE_AREA_CLEAN,
				pmem->va_alias, SMALL_PAGE_SIZE);

			cache_maintenance_l1(ICACHE_INVALIDATE, NULL, 0);
		}

		core_mmu_set_entry(&tbl_info, pmem->pgidx, pa,
				   get_area_mattr(area));

#ifdef TEE_PAGER_DEBUG_PRINT
		DMSG("Mapped 0x%" PRIxVA " -> 0x%" PRIxPA,
		     core_mmu_idx2va(&tbl_info, pmem->pgidx), pa);
#endif

	}

	tee_pager_hide_pages();
out:
	cpu_spin_unlock(&pager_lock);
	thread_unmask_exceptions(exceptions);
}

#else /*CFG_WITH_PAGER*/

static void tee_pager_handle_fault(struct tee_pager_abort_info *ai)
{
	/*
	 * Until PAGER is supported, trap CPU here.
	 */
	tee_pager_print_error_abort(ai);
	EMSG("Unexpected page fault! Trap CPU");
	panic();
}

#endif /*CFG_WITH_PAGER*/

#ifdef ARM32
static void set_abort_info(uint32_t abort_type, struct thread_abort_regs *regs,
		struct tee_pager_abort_info *ai)
{
	switch (abort_type) {
	case THREAD_ABORT_DATA:
		ai->fault_descr = read_dfsr();
		ai->va = read_dfar();
		break;
	case THREAD_ABORT_PREFETCH:
		ai->fault_descr = read_ifsr();
		ai->va = read_ifar();
		break;
	default:
		ai->fault_descr = 0;
		ai->va = regs->elr;
		break;
	}
	ai->abort_type = abort_type;
	ai->pc = regs->elr;
	ai->regs = regs;
}
#endif /*ARM32*/

#ifdef ARM64
static void set_abort_info(uint32_t abort_type __unused,
		struct thread_abort_regs *regs, struct tee_pager_abort_info *ai)
{
	ai->fault_descr = read_esr_el1();
	switch ((ai->fault_descr >> ESR_EC_SHIFT) & ESR_EC_MASK) {
	case ESR_EC_IABT_EL0:
	case ESR_EC_IABT_EL1:
		ai->abort_type = THREAD_ABORT_PREFETCH;
		ai->va = read_far_el1();
		break;
	case ESR_EC_DABT_EL0:
	case ESR_EC_DABT_EL1:
	case ESR_EC_SP_ALIGN:
		ai->abort_type = THREAD_ABORT_DATA;
		ai->va = read_far_el1();
		break;
	default:
		ai->abort_type = THREAD_ABORT_UNDEF;
		ai->va = regs->elr;
	}
	ai->pc = regs->elr;
	ai->regs = regs;
}
#endif /*ARM64*/

#ifdef ARM32
static void handle_user_ta_panic(struct tee_pager_abort_info *ai)
{
	/*
	 * It was a user exception, stop user execution and return
	 * to TEE Core.
	 */
	ai->regs->r0 = TEE_ERROR_TARGET_DEAD;
	ai->regs->r1 = true;
	ai->regs->r2 = 0xdeadbeef;
	ai->regs->elr = (uint32_t)thread_unwind_user_mode;
	ai->regs->spsr = read_cpsr();
	ai->regs->spsr &= ~CPSR_MODE_MASK;
	ai->regs->spsr |= CPSR_MODE_SVC;
	ai->regs->spsr &= ~CPSR_FIA;
	ai->regs->spsr |= read_spsr() & CPSR_FIA;
	/* Select Thumb or ARM mode */
	if (ai->regs->elr & 1)
		ai->regs->spsr |= CPSR_T;
	else
		ai->regs->spsr &= ~CPSR_T;
}
#endif /*ARM32*/

#ifdef ARM64
static void handle_user_ta_panic(struct tee_pager_abort_info *ai)
{
	uint32_t daif;

	/*
	 * It was a user exception, stop user execution and return
	 * to TEE Core.
	 */
	ai->regs->x0 = TEE_ERROR_TARGET_DEAD;
	ai->regs->x1 = true;
	ai->regs->x2 = 0xdeadbeef;
	ai->regs->elr = (vaddr_t)thread_unwind_user_mode;
	ai->regs->sp_el0 = thread_get_saved_thread_sp();

	daif = (ai->regs->spsr >> SPSR_32_AIF_SHIFT) & SPSR_32_AIF_MASK;
	/* XXX what about DAIF_D? */
	ai->regs->spsr = SPSR_64(SPSR_64_MODE_EL1, SPSR_64_MODE_SP_EL0, daif);
}
#endif /*ARM64*/

void tee_pager_abort_handler(uint32_t abort_type,
		struct thread_abort_regs *regs)
{
	struct tee_pager_abort_info ai;

	set_abort_info(abort_type, regs, &ai);

	switch (tee_pager_get_fault_type(&ai)) {
	case TEE_PAGER_FAULT_TYPE_IGNORE:
		break;
	case TEE_PAGER_FAULT_TYPE_USER_TA_PANIC:
		handle_user_ta_panic(&ai);
		break;
	case TEE_PAGER_FAULT_TYPE_PAGEABLE:
	default:
		tee_pager_handle_fault(&ai);
		break;
	}
}

#ifdef CFG_WITH_PAGER
void tee_pager_add_pages(vaddr_t vaddr, size_t npages, bool unmap)
{
	size_t n;

	DMSG("0x%" PRIxVA " - 0x%" PRIxVA " : %d",
	     vaddr, vaddr + npages * SMALL_PAGE_SIZE, (int)unmap);

	/* setup memory */
	for (n = 0; n < npages; n++) {
		struct tee_pager_pmem *pmem;
		tee_vaddr_t va = vaddr + n * SMALL_PAGE_SIZE;
		unsigned pgidx = core_mmu_va2idx(&tbl_info, va);
		paddr_t pa;
		uint32_t attr;

		core_mmu_get_entry(&tbl_info, pgidx, &pa, &attr);

		/* Ignore unmapped pages/blocks */
		if (!(attr & TEE_MATTR_VALID_BLOCK))
			continue;

		pmem = malloc(sizeof(struct tee_pager_pmem));
		if (pmem == NULL) {
			DMSG("Can't allocate memory");
			panic();
		}

		pmem->pgidx = pgidx;
		pmem->va_alias = pager_add_alias_page(pa);

		if (unmap) {
			/*
			 * Note that we're making the page inaccessible
			 * with the TEE_MATTR_PHYS_BLOCK attribute to
			 * indicate that the descriptor still holds a valid
			 * physical address of a page.
			 */
			pmem->area = NULL;
			core_mmu_set_entry(&tbl_info, pgidx, pa,
					   TEE_MATTR_PHYS_BLOCK);
		} else {
			/*
			 * The page is still mapped, let's assign the area
			 * and update the protection bits accordingly.
			 */
			pmem->area = tee_pager_find_area(va);
			core_mmu_set_entry(&tbl_info, pgidx, pa,
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

void tee_pager_release_zi(vaddr_t vaddr, size_t size)
{
	bool unmaped = false;
	uint32_t exceptions = thread_mask_exceptions(THREAD_EXCP_ALL);

	if ((vaddr & SMALL_PAGE_MASK) || (size & SMALL_PAGE_MASK))
		panic();

	for (; size; vaddr += SMALL_PAGE_SIZE, size -= SMALL_PAGE_SIZE)
		unmaped |= tee_pager_release_one_zi(vaddr);

	/* Invalidate secure TLB */
	if (unmaped)
		core_tlb_maintenance(TLBINV_UNIFIEDTLB, 0);

	thread_set_exceptions(exceptions);
}

void *tee_pager_request_zi(size_t size)
{
	tee_mm_entry_t *mm;

	if (!size)
		return NULL;

	mm = tee_mm_alloc(&tee_mm_vcore, ROUNDUP(size, SMALL_PAGE_SIZE));
	if (!mm)
		return NULL;

	tee_pager_add_area(mm, TEE_PAGER_AREA_RW, NULL, NULL);

	return (void *)tee_mm_get_smem(mm);
}

#else /*CFG_WITH_PAGER*/

void tee_pager_get_stats(struct tee_pager_stats *stats)
{
	memset(stats, 0, sizeof(struct tee_pager_stats));
}

#endif /*CFG_WITH_PAGER*/
