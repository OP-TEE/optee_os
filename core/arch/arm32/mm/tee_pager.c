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
#include <mm/tee_pager.h>
#include <mm/tee_mm_unpg.h>
#include <mm/tee_mmu_unpg.h>
#include <mm/core_mmu.h>
#include <tee/arch_svc.h>
#include <arm32.h>
#include <tee/tee_cryp_provider.h>
#include <tee_api_defines.h>
#include <utee_defines.h>
#include <trace.h>

/* Interesting aborts for TEE pager */
#define TEE_PAGER_FSR_FS_MASK                     0x040F
	/* DFSR[10,3:0] 0b00001 */
#define TEE_PAGER_FSR_FS_ALIGNMENT_FAULT          0x0001
	/* DFSR[10,3:0] 0b00010 */
#define TEE_PAGER_FSR_FS_DEBUG_EVENT              0x0002
	/* DFSR[10,3:0] 0b10110 */
#define TEE_PAGER_FSR_FS_ASYNC_EXTERNAL_ABORT     0x0406
	/* DFSR[10,3:0] 0b01101 */
#define TEE_PAGER_FSR_FS_PERMISSION_FAULT_SECTION 0x000D
	/* DFSR[10,3:0] 0b01111 */
#define TEE_PAGER_FSR_FS_PERMISSION_FAULT_PAGE    0x000F

struct tee_pager_abort_info {
	uint32_t abort_type;
	uint32_t fsr;
	vaddr_t va;
	uint32_t pc;
	struct thread_abort_regs *regs;
};

enum tee_pager_fault_type {
	TEE_PAGER_FAULT_TYPE_USER_TA_PANIC,
	TEE_PAGER_FAULT_TYPE_PAGABLE,
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
 * Represents a physical page used for paging.
 *
 * mmu_entry points to currently used MMU entry. This actual physical
 * address is stored here so even if the page isn't mapped, there's allways
 * an MMU entry holding the physical address.
 *
 * session_handle is a pointer returned by tee_ta_load_page() and later
 * used when saving rw-data.
 */
struct tee_pager_pmem {
	uint32_t *mmu_entry;
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
 * Pointer to L2 translation table used to map the virtual memory range
 * covered by the pager.
 */
static uint32_t *l2_table;

bool tee_pager_add_area(tee_mm_entry_t *mm, uint32_t flags, const void *store,
		const void *hashes)
{
	struct tee_pager_area *area;

	DMSG("0x%x - 0x%x : flags 0x%x, store %p, hashes %p",
		tee_mm_get_smem(mm),
		tee_mm_get_smem(mm) + (mm->size << mm->pool->shift),
		flags, store, hashes);

	if (flags & TEE_PAGER_AREA_RO)
		TEE_ASSERT(store && hashes);
	else if (flags & TEE_PAGER_AREA_RW)
		TEE_ASSERT(!store && !hashes);
	else
		panic();

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

void tee_pager_init(void *xlat_table)
{
	l2_table = xlat_table;
}


/* Get L2 translation entry address from virtual address */
static uint32_t *tee_pager_va_to_xe(vaddr_t va)
{
	vaddr_t page_va = va & ~SMALL_PAGE_MASK;
	size_t mmu_entry_offset = (page_va - tee_mm_vcore.lo) >>
					SMALL_PAGE_SHIFT;

	return l2_table + mmu_entry_offset;
}

/* Get virtual address of page from translation entry */
static vaddr_t tee_pager_xe_to_va(uint32_t *xe)
{
	return (vaddr_t)(xe - l2_table) * SMALL_PAGE_SIZE + tee_mm_vcore.lo;
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
			EMSG("PH 0x%x failed", page_va);
			panic();
		}
	}
}

static bool tee_pager_unhide_page(vaddr_t page_va)
{
	struct tee_pager_pmem *pmem;

	TAILQ_FOREACH(pmem, &tee_pager_pmem_head, link) {
		if (((*pmem->mmu_entry & SMALL_PAGE_MASK) ==
			TEE_PAGER_PAGE_UNLOADED) &&
		    page_va == tee_pager_xe_to_va(pmem->mmu_entry)) {
			/* page is hidden, show and move to back */
			*pmem->mmu_entry |= TEE_MMU_L2SP_PRIV_ACC;

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
		if (n >= TEE_PAGER_NHIDE)
			break;
		n++;
		*pmem->mmu_entry = TEE_MMU_L2SP_CLEAR_ACC(*pmem->mmu_entry);
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
	EMSG_RAW("\nUser TA %s-abort at address 0x%x\n",
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
}

static void tee_pager_print_abort(struct tee_pager_abort_info *ai __unused)
{
	DMSG("%s-abort at 0x%x: FSR 0x%x PC 0x%x TTBR0 0x%X CONTEXIDR 0x%X",
	     abort_type_to_str(ai->abort_type),
	     ai->va, ai->fsr, ai->pc, read_ttbr0(), read_contextidr());
	DMSG("CPUID 0x%x SPSR_abt 0x%x",
	     read_mpidr(), read_spsr());
}

static void tee_pager_print_error_abort(
		struct tee_pager_abort_info *ai __unused)
{
	EMSG("%s-abort at 0x%x\n"
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

	switch (ai->fsr & TEE_PAGER_FSR_FS_MASK) {
	/* Only possible for data abort */
	case TEE_PAGER_FSR_FS_ALIGNMENT_FAULT:
		tee_pager_print_error_abort(ai);
		EMSG("[TEE_PAGER] alignement fault!  (trap CPU)");
		panic();

	case TEE_PAGER_FSR_FS_DEBUG_EVENT:
		tee_pager_print_abort(ai);
		DMSG("[TEE_PAGER] Ignoring debug event!");
		return TEE_PAGER_FAULT_TYPE_IGNORE;

	/* Only possible for data abort */
	case TEE_PAGER_FSR_FS_ASYNC_EXTERNAL_ABORT:
		tee_pager_print_abort(ai);
		DMSG("[TEE_PAGER] Ignoring async external abort!");
		return TEE_PAGER_FAULT_TYPE_IGNORE;

	default:
		break;
	}
	return TEE_PAGER_FAULT_TYPE_PAGABLE;
}


#ifdef CFG_WITH_PAGER

/* Finds the oldest page and remaps it for the new virtual address */
static struct tee_pager_pmem *tee_pager_get_page(
		struct tee_pager_abort_info *ai,
		struct tee_pager_area *area)
{
	vaddr_t page_va = ai->va & ~SMALL_PAGE_MASK;

	uint32_t pa;
	uint32_t *mmu_entry = tee_pager_va_to_xe(page_va);
	struct tee_pager_pmem *pmem;

	if (*mmu_entry != 0) {
		/*
		 * There's an pmem entry using this mmu entry, let's use
		 * that entry in the new mapping.
		 */
		TAILQ_FOREACH(pmem, &tee_pager_pmem_head, link) {
			if (pmem->mmu_entry == mmu_entry)
				break;
		}
		if (!pmem) {
			tee_pager_print_abort(ai);
			DMSG("Couldn't find pmem for mmu_entry %p",
			     (void *)mmu_entry);
			panic();
		}
	} else {
		pmem = TAILQ_FIRST(&tee_pager_pmem_head);
		if (!pmem) {
			tee_pager_print_abort(ai);
			DMSG("No pmem entries");
			panic();
		}
	}

	/* add page to mmu table, small pages [31:12]PA */
	pa = *pmem->mmu_entry & ~SMALL_PAGE_MASK;

	*pmem->mmu_entry = 0;
	pmem->mmu_entry = mmu_entry;
	*pmem->mmu_entry = pa | TEE_PAGER_PAGE_LOADED;

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
	DMSG("Mapped 0x%x -> 0x%x", page_va, pa);
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
		DMSG("Invalid addr 0x%" PRIx32, ai->va);
		panic();
	}

	if (!tee_pager_unhide_page(page_va)) {
		/* the page wasn't hidden */
		struct tee_pager_pmem *pmem;

		pmem = tee_pager_get_page(ai, area);

		/* load page code & data */
		pmem->area = area;
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
		regs->lr = (uint32_t)tee_svc_unwind_enter_user_mode;
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
	case TEE_PAGER_FAULT_TYPE_PAGABLE:
	default:
		tee_pager_handle_fault(&ai);
		break;
	}
}

#ifdef CFG_WITH_PAGER
void tee_pager_add_pages(tee_vaddr_t vaddr, size_t npages, bool unmap)
{
	size_t n;

	DMSG("0x%x - 0x%x : %d",
	     vaddr, vaddr + npages * SMALL_PAGE_SIZE, (int)unmap);

	/* setup memory */
	for (n = 0; n < npages; n++) {
		struct tee_pager_pmem *pmem;
		tee_vaddr_t va = vaddr + n * SMALL_PAGE_SIZE;
		uint32_t *mmu_entry = tee_pager_va_to_xe(va);

		/* Ignore unmapped entries */
		if (*mmu_entry == 0)
			continue;

		pmem = malloc(sizeof(struct tee_pager_pmem));
		if (pmem == NULL) {
			DMSG("Can't allocate memory");
			panic();
		}

		pmem->mmu_entry = (uint32_t *)mmu_entry;
		pmem->area = NULL;

		if (unmap) {
			/*
			 * Set to TEE_PAGER_NO_ACCESS_ATTRIBUTES and not
			 * TEE_PAGER_PAGE_UNLOADED since pager would
			 * misstake it for a hidden page in case the
			 * virtual address was reused before the physical
			 * page was used for another virtual page.
			 */
			*mmu_entry = (*mmu_entry & ~SMALL_PAGE_MASK) |
			    TEE_PAGER_NO_ACCESS_ATTRIBUTES;

		}
		tee_pager_npages++;
		TAILQ_INSERT_TAIL(&tee_pager_pmem_head, pmem, link);
	}

	if (unmap) {
		/* Invalidate secure TLB */
		core_tlb_maintenance(TLBINV_UNIFIEDTLB, 0);
	}
}

void tee_pager_unmap(uint32_t page, uint8_t psize)
{
	int i;

	if ((page & 0xFFF) != 0) {
		EMSG("Invalid page address");
		panic();
	}

	for (i = 0; i < psize; i++) {
		uint32_t addr = page + (i << SMALL_PAGE_SHIFT);
		uint32_t *mmu_entry = tee_pager_va_to_xe(addr);

		if (*mmu_entry != 0) {
			struct tee_pager_pmem *pmem;

			/* Invalidate mmu_entry */
			*mmu_entry &= ~SMALL_PAGE_MASK;

			/*
			 * Unregister the session from the page entry using
			 * this mmu_entry.
			 */
			TAILQ_FOREACH(pmem, &tee_pager_pmem_head, link) {
				if (pmem->mmu_entry == (uint32_t *)mmu_entry) {
					pmem->area = NULL;
					break;
				}
			}

			if (pmem == NULL) {
				EMSG("Physical page to unmap not found");
				panic();
			}
		}
	}

	/* Invalidate secure TLB */
	core_tlb_maintenance(TLBINV_UNIFIEDTLB, 0);
}

void tee_pager_unhide_all_pages(void)
{
	struct tee_pager_pmem *pmem;
	bool has_hidden_page = false;

	TAILQ_FOREACH(pmem, &tee_pager_pmem_head, link) {
		if ((*pmem->mmu_entry & SMALL_PAGE_MASK) ==
				TEE_PAGER_PAGE_UNLOADED) {
			/* Page is hidden, unhide it */
			has_hidden_page = true;
			*pmem->mmu_entry |= TEE_MMU_L2SP_PRIV_ACC;
		}
	}

	/* Only invalidate secure TLB if something was changed */
	if (has_hidden_page)
		core_tlb_maintenance(TLBINV_UNIFIEDTLB, 0);
}
#endif /*CFG_WITH_PAGER*/
