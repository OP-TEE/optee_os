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
#include <mm/tee_pager.h>
#include <mm/tee_mm.h>
#include <mm/core_mmu.h>
#include <tee/arch_svc.h>
#include <arm.h>
#include <tee/tee_cryp_provider.h>
#include <tee_api_defines.h>
#include <utee_defines.h>
#include <trace.h>

struct tee_pager_abort_info {
	uint32_t abort_type;
	uint32_t fsr;
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
 * @area	a pointer to the pager area
 */
struct tee_pager_pmem {
	unsigned pgidx;
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

/*
 * Reference to translation table used to map the virtual memory range
 * covered by the pager.
 */
static struct core_mmu_table_info tbl_info;

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

static uint32_t get_area_mattr(struct tee_pager_area *area __unused)
{
	uint32_t attr = TEE_MATTR_VALID_BLOCK | TEE_MATTR_GLOBAL |
			TEE_MATTR_CACHE_DEFAULT | TEE_MATTR_SECURE;

	attr |= TEE_MATTR_PRWX;

	return attr;
}



static void tee_pager_load_page(struct tee_pager_area *area, vaddr_t page_va)
{
	size_t pg_idx = (page_va - area->mm->pool->lo) >> SMALL_PAGE_SHIFT;

	if (area->store) {
		size_t rel_pg_idx = pg_idx - area->mm->offset;
		const void *stored_page = area->store +
					  rel_pg_idx * SMALL_PAGE_SIZE;

		memcpy((void *)page_va, stored_page, SMALL_PAGE_SIZE);
	} else {
		memset((void *)page_va, 0, SMALL_PAGE_SIZE);
	}
}

static void tee_pager_verify_page(struct tee_pager_area *area, vaddr_t page_va)
{
	size_t pg_idx = (page_va - area->mm->pool->lo) >> SMALL_PAGE_SHIFT;

	if (area->store) {
		size_t rel_pg_idx = pg_idx - area->mm->offset;
		const void *hash = area->hashes +
				   rel_pg_idx * TEE_SHA256_HASH_SIZE;

		if (hash_sha256_check(hash, (void *)page_va, SMALL_PAGE_SIZE) !=
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
		core_mmu_get_entry(&tbl_info, pmem->pgidx, &pa, &attr);
		if (!(attr & TEE_MATTR_VALID_BLOCK))
			continue;

		core_mmu_set_entry(&tbl_info, pmem->pgidx, pa,
				   TEE_MATTR_HIDDEN_BLOCK);

	}

	/* TODO only invalidate entries touched above */
	core_tlb_maintenance(TLBINV_UNIFIEDTLB, 0);
}
#endif /*CFG_WITH_PAGER*/

/* Returns true if the exception originated from user mode */
static bool tee_pager_is_user_exception(void)
{
	return (read_spsr() & CPSR_MODE_MASK) == CPSR_MODE_USR;
}

/* Returns true if the exception originated from abort mode */
static bool tee_pager_is_abort_in_abort_handler(void)
{
	return (read_spsr() & CPSR_MODE_MASK) == CPSR_MODE_ABT;
}

static __unused const char *abort_type_to_str(uint32_t abort_type)
{
	if (abort_type == THREAD_ABORT_DATA)
		return "data";
	if (abort_type == THREAD_ABORT_PREFETCH)
		return "prefetch";
	return "undef";
}

static void tee_pager_print_user_abort(struct tee_pager_abort_info *ai __unused)
{
#ifdef CFG_TEE_CORE_TA_TRACE
	EMSG_RAW("\nUser TA %s-abort at address 0x%" PRIxVA,
		abort_type_to_str(ai->abort_type), ai->va);
	EMSG_RAW(" fsr 0x%08x  ttbr0 0x%08x   ttbr1 0x%08x   cidr 0x%X\n",
		 ai->fsr, read_ttbr0(), read_ttbr1(), read_contextidr());
	EMSG_RAW(" cpu #%d          cpsr 0x%08x\n",
		 get_core_pos(), read_spsr());
	EMSG_RAW(" r0 0x%08x     r4 0x%08x     r8 0x%08x    r12 0x%08x\n",
		 ai->regs->r0, ai->regs->r4, ai->regs->r8, ai->regs->ip);
	EMSG_RAW(" r1 0x%08x     r5 0x%08x     r9 0x%08x     sp 0x%08x\n",
		 ai->regs->r1, ai->regs->r5, ai->regs->r9, read_usr_sp());
	EMSG_RAW(" r2 0x%08x     r6 0x%08x    r10 0x%08x     lr 0x%08x\n",
		 ai->regs->r2, ai->regs->r6, ai->regs->r10, read_usr_lr());
	EMSG_RAW(" r3 0x%08x     r7 0x%08x    r11 0x%08x     pc 0x%08x\n",
		 ai->regs->r3, ai->regs->r7, ai->regs->r11, ai->pc);

	tee_ta_dump_current();
#endif
}

static void tee_pager_print_abort(struct tee_pager_abort_info *ai __unused)
{
	DMSG("%s-abort at 0x%" PRIxVA ": FSR 0x%x PC 0x%x TTBR0 0x%X CONTEXIDR 0x%X",
	     abort_type_to_str(ai->abort_type),
	     ai->va, ai->fsr, ai->pc, read_ttbr0(), read_contextidr());
	DMSG("CPUID 0x%x SPSR_abt 0x%x",
	     read_mpidr(), read_spsr());
}

static void tee_pager_print_error_abort(
		struct tee_pager_abort_info *ai __unused)
{
	EMSG("%s-abort at 0x%" PRIxVA "\n"
	     "FSR 0x%x PC 0x%x TTBR0 0x%X CONTEXIDR 0x%X\n"
	     "CPUID 0x%x CPSR 0x%x (read from SPSR)",
	     abort_type_to_str(ai->abort_type),
	     ai->va, ai->fsr, ai->pc, read_ttbr0(), read_contextidr(),
	     read_mpidr(), read_spsr());
}


static enum tee_pager_fault_type tee_pager_get_fault_type(
		struct tee_pager_abort_info *ai)
{

	/* In case of multithreaded version, this section must be protected */

	if (tee_pager_is_user_exception()) {
		tee_pager_print_user_abort(ai);
		DMSG("[TEE_PAGER] abort in User mode (TA will panic)");
		return TEE_PAGER_FAULT_TYPE_USER_TA_PANIC;
	}

	if (tee_pager_is_abort_in_abort_handler()) {
		tee_pager_print_error_abort(ai);
		EMSG("[PAGER] abort in abort handler (trap CPU)");
		panic();
	}

	if (ai->abort_type == THREAD_ABORT_UNDEF) {
		tee_pager_print_error_abort(ai);
		EMSG("[TEE_PAGER] undefined abort (trap CPU)");
		panic();
	}

	switch (core_mmu_get_fault_type(ai->fsr)) {
	case CORE_MMU_FAULT_ALIGNMENT:
		tee_pager_print_error_abort(ai);
		EMSG("[TEE_PAGER] alignement fault!  (trap CPU)");
		panic();
		break;

	case CORE_MMU_FAULT_DEBUG_EVENT:
		tee_pager_print_abort(ai);
		DMSG("[TEE_PAGER] Ignoring debug event!");
		return TEE_PAGER_FAULT_TYPE_IGNORE;

	case CORE_MMU_FAULT_TRANSLATION:
	case CORE_MMU_FAULT_PERMISSION:
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
static struct tee_pager_pmem *tee_pager_get_page(
		struct tee_pager_abort_info *ai,
		struct tee_pager_area *area)
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
			tee_pager_print_abort(ai);
			DMSG("Couldn't find pmem for pgidx %u", pgidx);
			panic();
		}
	} else {
		pmem = TAILQ_FIRST(&tee_pager_pmem_head);
		if (!pmem) {
			tee_pager_print_abort(ai);
			DMSG("No pmem entries");
			panic();
		}
		core_mmu_get_entry(&tbl_info, pmem->pgidx, &pa, &attr);
		core_mmu_set_entry(&tbl_info, pmem->pgidx, 0, 0);
	}

	pmem->pgidx = pgidx;
	pmem->area = area;
	core_mmu_set_entry(&tbl_info, pgidx, pa, get_area_mattr(area));

	TAILQ_REMOVE(&tee_pager_pmem_head, pmem, link);
	if (area->store) {
		/* move page to back */
		TAILQ_INSERT_TAIL(&tee_pager_pmem_head, pmem, link);
	} else {
		/* Move page to rw list */
		TEE_ASSERT(tee_pager_npages > 0);
		tee_pager_npages--;
		TAILQ_INSERT_TAIL(&tee_pager_rw_pmem_head, pmem, link);
	}

	/* TODO only invalidate entries touched above */
	core_tlb_maintenance(TLBINV_UNIFIEDTLB, 0);

#ifdef TEE_PAGER_DEBUG_PRINT
	DMSG("Mapped 0x%x -> 0x%x", core_mmu_idx2va(&tbl_info, pgidx), pa);
#endif

	return pmem;
}

static void tee_pager_handle_fault(struct tee_pager_abort_info *ai)
{
	struct tee_pager_area *area;
	vaddr_t page_va = ai->va & ~SMALL_PAGE_MASK;

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

	if (!tee_pager_unhide_page(page_va)) {
		/* the page wasn't hidden */
		tee_pager_get_page(ai, area);

		/* load page code & data */
		tee_pager_load_page(area, page_va);
		/* TODO remap readonly if TEE_PAGER_AREA_RO */
		tee_pager_verify_page(area, page_va);
		/* TODO remap executable if TEE_PAGER_AREA_X */

		if (area->flags & TEE_PAGER_AREA_X) {
			cache_maintenance_l1(DCACHE_AREA_CLEAN,
				(void *)page_va, SMALL_PAGE_SIZE);

			cache_maintenance_l1(ICACHE_AREA_INVALIDATE,
				(void *)page_va, SMALL_PAGE_SIZE);
		}
	}

	tee_pager_hide_pages();
	/* end protect (multithreded version) */
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

void tee_pager_abort_handler(uint32_t abort_type,
		struct thread_abort_regs *regs)
{
	struct tee_pager_abort_info ai;

	switch (abort_type) {
	case THREAD_ABORT_DATA:
		ai.fsr = read_dfsr();
		ai.va = read_dfar();
		break;
	case THREAD_ABORT_PREFETCH:
		ai.fsr = read_ifsr();
		ai.va = read_ifar();
		break;
	default:
		ai.fsr = 0;
		ai.va = regs->lr;
		break;
	}
	ai.abort_type = abort_type;
	ai.pc = regs->lr;
	ai.regs = regs;

	switch (tee_pager_get_fault_type(&ai)) {
	case TEE_PAGER_FAULT_TYPE_IGNORE:
		break;
	case TEE_PAGER_FAULT_TYPE_USER_TA_PANIC:
		/*
		 * It was a user exception, stop user execution and return
		 * to TEE Core.
		 */
		regs->r0 = TEE_ERROR_TARGET_DEAD;
		regs->r1 = true;
		regs->r2 = 0xdeadbeef;
		regs->lr = (uint32_t)thread_unwind_user_mode;
		regs->spsr = read_cpsr();
		regs->spsr &= ~CPSR_MODE_MASK;
		regs->spsr |= CPSR_MODE_SVC;
		regs->spsr &= ~CPSR_FIA;
		regs->spsr |= read_spsr() & CPSR_FIA;
		/* Select Thumb or ARM mode */
		if (regs->lr & 1)
			regs->spsr |= CPSR_T;
		else
			regs->spsr &= ~CPSR_T;
		break;
	case TEE_PAGER_FAULT_TYPE_PAGEABLE:
	default:
		tee_pager_handle_fault(&ai);
		break;
	}
}

#ifdef CFG_WITH_PAGER
void tee_pager_add_pages(tee_vaddr_t vaddr, size_t npages, bool unmap)
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
		pmem->area = NULL;

		if (unmap) {
			/*
			 * Note that we're making the page inaccessible
			 * with the TEE_MATTR_PHYS_BLOCK attribute to
			 * indicate that the descriptor still holds a valid
			 * physical address of a page.
			 */
			core_mmu_set_entry(&tbl_info, pgidx, pa,
					   TEE_MATTR_PHYS_BLOCK);
		}
		tee_pager_npages++;
		TAILQ_INSERT_TAIL(&tee_pager_pmem_head, pmem, link);
	}

	if (unmap) {
		/* Invalidate secure TLB */
		core_tlb_maintenance(TLBINV_UNIFIEDTLB, 0);
	}
}
#endif /*CFG_WITH_PAGER*/
