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
#include <kernel/panic.h>
#include <mm/tee_mmu_defs.h>
#include <trace.h>
#include <kernel/tee_ta_manager.h>
#include <kernel/tee_kta_trace.h>
#include <kernel/misc.h>
#include <mm/tee_pager.h>
#include <mm/tee_mm_unpg.h>
#include <mm/tee_mmu_unpg.h>
#include <mm/core_mmu.h>
#include <tee/arch_svc.h>
#include <arm32.h>

/* Interesting aborts for TEE pager */
#define TEE_FSR_FS_MASK                     0x040F
#define TEE_FSR_FS_ALIGNMENT_FAULT          0x0001 /* DFSR[10,3:0] 0b00001 */
#define TEE_FSR_FS_DEBUG_EVENT              0x0002 /* DFSR[10,3:0] 0b00010 */
#define TEE_FSR_FS_ASYNC_EXTERNAL_ABORT     0x0406 /* DFSR[10,3:0] 0b10110 */
#define TEE_FSR_FS_PERMISSION_FAULT_SECTION 0x000D /* DFSR[10,3:0] 0b01101 */
#define TEE_FSR_FS_PERMISSION_FAULT_PAGE    0x000F /* DFSR[10,3:0] 0b01111 */

#define TEE_PAGER_NORMAL_RETURN 0
#define TEE_PAGER_USER_TA_PANIC 1

#define TEE_PAGER_SPSR_MODE_MASK    0x1F
#define TEE_PAGER_SPSR_MODE_USR     0x10
#define TEE_PAGER_SPSR_MODE_SVC     0x13
#define TEE_PAGER_SPSR_MODE_ABT     0x17
#define TEE_PAGER_SPSR_MODE_MON     0x16

#define TEE_PAGER_DATA_ABORT    0x00000000
#define TEE_PAGER_PREF_ABORT    0x00000001
#define TEE_PAGER_UNDEF_ABORT   0x00000002



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
	void *ctx_handle;
	 TAILQ_ENTRY(tee_pager_pmem) link;
};

/* The list of physical pages. The first page in the list is the oldest */
TAILQ_HEAD(tee_pager_pmem_head, tee_pager_pmem);
static struct tee_pager_pmem_head tee_pager_pmem_head =
TAILQ_HEAD_INITIALIZER(tee_pager_pmem_head);

/* number of pages hidden */
#define TEE_PAGER_NHIDE (tee_pager_npages / 3)


/* Get VA from L2 MMU entry address */
#define TEE_PAGER_GET_VA(a)					\
	(((((uint32_t)a) - SEC_VIRT_MMU_L2_BASE) <<		\
	(SMALL_PAGE_SHIFT - 2)) + TEE_VMEM_START)

/* Number of registered physical pages, used hiding pages. */
static uint8_t tee_pager_npages;

/* Get L2 MMU entry address from virtual address */
static uint32_t *tee_pager_get_mmu_entry(tee_vaddr_t va)
{
	tee_vaddr_t addr = va & ~SMALL_PAGE_MASK;
	size_t mmu_entry_offset = (addr - TEE_VMEM_START) >> SMALL_PAGE_SHIFT;

	return (uint32_t *)(TEE_VIRT_MMU_L2_BASE +
			     mmu_entry_offset * sizeof(uint32_t));
}

/* Returns true if the exception originated from user mode */
static bool tee_pager_is_user_exception(void)
{
	return (read_spsr() & TEE_PAGER_SPSR_MODE_MASK) ==
	    TEE_PAGER_SPSR_MODE_USR;
}

/* Returns true if the exception originated from abort mode */
static bool tee_pager_is_abort_in_abort_handler(void)
{
	return (read_spsr() & TEE_PAGER_SPSR_MODE_MASK) ==
	    TEE_PAGER_SPSR_MODE_ABT;
}

static void tee_pager_print_abort(const uint32_t addr __unused,
		const uint32_t fsr __unused, const uint32_t pc __unused,
		const uint32_t flags __unused, const uint32_t dbgpcsr __unused)
{
	DMSG("%s at 0x%x: FSR 0x%x PC 0x%x TTBR0 0x%X CONTEXIDR 0x%X",
	     (flags == TEE_PAGER_DATA_ABORT) ? "data-abort" :
	     (flags == TEE_PAGER_PREF_ABORT) ? "prefetch-abort" : "undef-abort",
	     addr, fsr, pc, read_ttbr0(), read_contextidr());
	DMSG("CPUID %dd DBGPCSR 0x%x SPSR_abt 0x%x",
	     read_mpidr(), dbgpcsr, read_spsr());
}

static void tee_pager_print_error_abort(const uint32_t addr __unused,
		const uint32_t fsr __unused, const uint32_t pc __unused,
		const uint32_t flags __unused, const uint32_t dbgpcsr __unused)
{
	EMSG("%s at 0x%x\n"
	     "FSR 0x%x PC 0x%x TTBR0 0x%X CONTEXIDR 0x%X\n"
	     "CPUID 0x%x DBGPCSR 0x%x CPSR 0x%x (read from SPSR)",
	     (flags == TEE_PAGER_DATA_ABORT) ? "data-abort" :
	     (flags == TEE_PAGER_PREF_ABORT) ? "prefetch-abort" : "undef-abort",
	     addr, fsr, pc, read_ttbr0(), read_contextidr(),
	     read_mpidr(), dbgpcsr, read_spsr());
}

static void tee_pager_restore_irq(void)
{
	/*
	 * Restores the settings of IRQ as saved when entering secure
	 * world, using something like
	 * INTERRUPT_ENABLE(SEC_ENV_SETTINGS_READ() & SEC_ROM_IRQ_ENABLE_MASK);
	 */

	/* Infinite loop as this is not implemented yet */
	volatile bool mytrue = true;
	EMSG("tee_pager_restore_irq not implemented yet");
	while (mytrue)
	;
}

static void tee_pager_print_user_abort(const uint32_t addr __unused,
					const uint32_t fsr __unused,
					const uint32_t pc  __unused,
					const uint32_t flags __unused,
					const uint32_t dbgpcsr __unused,
					struct thread_abort_regs *regs __unused)
{
	EMSG_RAW("\nUser TA %s at address 0x%x\n",
	    (flags == TEE_PAGER_DATA_ABORT) ? "data-abort" :
	    (flags == TEE_PAGER_PREF_ABORT) ? "prefetch-abort" : "undef-abort",
	    addr);
	EMSG_RAW(" fsr 0x%08x  ttbr0 0x%08x   ttbr1 0x%08x   cidr 0x%X\n",
		 fsr, read_ttbr0(), read_ttbr1(), read_contextidr());
	EMSG_RAW(" cpu #%d          cpsr 0x%08x  (0x%08x)\n",
		 get_core_pos(), read_spsr(), dbgpcsr);
	EMSG_RAW(" r0 0x%08x     r4 0x%08x     r8 0x%08x    r12 0x%08x\n",
		 regs->r0, regs->r4, regs->r8, regs->ip);
	EMSG_RAW(" r1 0x%08x     r5 0x%08x     r9 0x%08x     sp 0x%08x\n",
		 regs->r1, regs->r5, regs->r9, read_usr_sp());
	EMSG_RAW(" r2 0x%08x     r6 0x%08x    r10 0x%08x     lr 0x%08x\n",
		 regs->r2, regs->r6, regs->r10, read_usr_lr());
	EMSG_RAW(" r3 0x%08x     r7 0x%08x    r11 0x%08x     pc 0x%08x\n",
		 regs->r3, regs->r7, regs->r11, pc);

	tee_ta_dump_current();
}

static uint32_t tee_pager_handle_abort(const uint32_t flags, const uint32_t pc,
				       const uint32_t dbgpcsr,
				       struct thread_abort_regs *regs)
{
	struct tee_pager_pmem *apage;
	uint32_t addr;
	uint32_t w_addr;
	uint32_t i;
	uint32_t fsr;

	if (flags == TEE_PAGER_DATA_ABORT) {
		fsr = read_dfsr();
		addr = read_dfar();
	} else {
		if (flags == TEE_PAGER_PREF_ABORT) {
			fsr = read_ifsr();
			addr = read_ifar();
		} else {
			fsr = 0;
			addr = pc;
		}
	}

	w_addr = addr;

	/* In case of multithreaded version, this section must be protected */

	if (tee_pager_is_user_exception()) {
		tee_pager_print_user_abort(addr, fsr, pc, flags, dbgpcsr, regs);
		DMSG("[TEE_PAGER] abort in User mode (TA will panic)");
		return TEE_PAGER_USER_TA_PANIC;
	}

	if (tee_pager_is_abort_in_abort_handler()) {
		tee_pager_print_error_abort(addr, fsr, pc, flags, dbgpcsr);
		EMSG("[TEE_PAGER] abort in abort handler (trap CPU)");
		panic();
	}

	if (flags == TEE_PAGER_UNDEF_ABORT) {
		tee_pager_print_error_abort(addr, fsr, pc, flags, dbgpcsr);
		EMSG("[TEE_PAGER] undefined abort (trap CPU)");
		panic();
	}

	switch (fsr & TEE_FSR_FS_MASK) {
	case TEE_FSR_FS_ALIGNMENT_FAULT: /* Only possible for data abort */
		tee_pager_print_error_abort(addr, fsr, pc, flags, dbgpcsr);
		EMSG("[TEE_PAGER] alignement fault!  (trap CPU)");
		panic();

	case TEE_FSR_FS_DEBUG_EVENT:
		tee_pager_print_abort(addr, fsr, pc, flags, dbgpcsr);
		DMSG("[TEE_PAGER] Ignoring debug event!");
		return TEE_PAGER_NORMAL_RETURN;

	case TEE_FSR_FS_ASYNC_EXTERNAL_ABORT: /* Only possible for data abort */
		tee_pager_print_abort(addr, fsr, pc, flags, dbgpcsr);
		DMSG("[TEE_PAGER] Ignoring async external abort!");
		return TEE_PAGER_NORMAL_RETURN;

	default:
#ifdef PAGER_DEBUG_PRINT
		tee_pager_print_abort(addr, fsr, pc, flags, dbgpcsr);
#endif
		break;
	}

#ifndef CFG_TEE_PAGER
	/*
	 * Until PAGER is supported, trap CPU here.
	 */
	tee_pager_print_error_abort(addr, fsr, pc, flags, dbgpcsr);
	EMSG("Unexpected page fault! Trap CPU");
	while (1)
		;
#endif

	/* check if the access is valid */
	if (!tee_mm_validate(&tee_mm_vcore, w_addr)) {
		tee_pager_print_abort(addr, fsr, pc, flags, dbgpcsr);
		DMSG("Invalid addr 0x%" PRIx32, addr);
		panic();
	}

	/* check if page is hidden */
	TAILQ_FOREACH(apage, &tee_pager_pmem_head, link) {
		if (((*apage->mmu_entry & 0xFFF) == TEE_PAGER_PAGE_UNLOADED) &&
		    apage->ctx_handle != NULL &&
		    w_addr >= TEE_PAGER_GET_VA(apage->mmu_entry) &&
		    w_addr <
		    TEE_PAGER_GET_VA(apage->mmu_entry) + SMALL_PAGE_SIZE) {
			/* page is hidden, show and move to back */
			*(apage->mmu_entry) |= TEE_MMU_L2SP_PRIV_ACC;

			TAILQ_REMOVE(&tee_pager_pmem_head, apage, link);
			TAILQ_INSERT_TAIL(&tee_pager_pmem_head, apage, link);

			w_addr = 0;
			break;
		}
	}

	if (apage == NULL) {
		/* the page wasn't hidden */
		uint32_t pa;
		uint32_t *mmu_entry =
		    (uint32_t *)tee_pager_get_mmu_entry((tee_vaddr_t) w_addr);

		if (*mmu_entry != 0) {
			/*
			 * There's an pmem entry using this mmu entry, let's use
			 * that entry in the new mapping.
			 */
			TAILQ_FOREACH(apage, &tee_pager_pmem_head, link) {
				if (apage->mmu_entry == mmu_entry)
					break;
			}
			if (apage == NULL) {
				tee_pager_print_abort(addr, fsr, pc, flags,
						      dbgpcsr);
				DMSG("Couldn't find pmem for mmu_entry %p",
				     (void *)mmu_entry);
				panic();
			}
		} else {
			apage = TAILQ_FIRST(&tee_pager_pmem_head);
			if (apage == NULL) {
				tee_pager_print_abort(addr, fsr, pc, flags,
						      dbgpcsr);
				DMSG("No pmem entries");
				panic();
			}
		}

		/* save rw data if needed */
		if ((*apage->mmu_entry & 0xFFF) != 0 &&
		    tee_ta_check_rw(TEE_PAGER_GET_VA(apage->mmu_entry),
				    apage->ctx_handle)) {
			/* make sure the page is accessible */
			if (((*apage->mmu_entry & 0xFFF) ==
			     TEE_PAGER_PAGE_UNLOADED)) {
				*apage->mmu_entry |= TEE_MMU_L2SP_PRIV_ACC;

				/* Invalidate secure TLB */
				core_tlb_maintenance(TLBINV_UNIFIEDTLB, 0);
			}

			tee_ta_save_rw(TEE_PAGER_GET_VA(apage->mmu_entry),
				       apage->ctx_handle);
		}

		/* move page to back */
		TAILQ_REMOVE(&tee_pager_pmem_head, apage, link);
		TAILQ_INSERT_TAIL(&tee_pager_pmem_head, apage, link);

		/* add page to mmu table, small pages [31:12]PA */
		pa = *apage->mmu_entry & 0xFFFFF000;

		*apage->mmu_entry = 0;
		apage->mmu_entry = mmu_entry;

		*apage->mmu_entry = pa | TEE_PAGER_PAGE_LOADED;

#ifdef PAGER_DEBUG_PRINT
		DMSG("Mapped %p -> %p", w_addr & 0xFFFFF000, pa);
#endif
	}

	/* Hide */
	{
		struct tee_pager_pmem *bpage;

		i = 0;
		TAILQ_FOREACH(bpage, &tee_pager_pmem_head, link) {
			if (i >= TEE_PAGER_NHIDE)
				break;
			i++;
			*bpage->mmu_entry =
			    TEE_MMU_L2SP_CLEAR_ACC(*bpage->mmu_entry);
		}
	}

	/* Invalidate secure TLB */
	core_tlb_maintenance(TLBINV_UNIFIEDTLB, 0);

	if (w_addr) {
		/* load page code & data */
		apage->ctx_handle = tee_ta_load_page(w_addr);

		cache_maintenance_l1(DCACHE_AREA_CLEAN,
			(void *)(w_addr & 0xFFFFF000), SMALL_PAGE_SIZE);

		cache_maintenance_l1(ICACHE_AREA_INVALIDATE,
			(void *)(w_addr & 0xFFFFF000), SMALL_PAGE_SIZE);
	}

	/* end protect (multithreded version) */

	/*
	 * Until now we've been running with IRQ blocked. Let's enble IRQ now
	 * when it should be safe to do further processing with them enabled.
	 *
	 * It should be possible to enable IRQ earlier, but MMU updates and
	 * cache mainentance may need some tweaking to guarentee coherency in
	 * case we switch CPU in the middle of an operation.
	 */
	tee_pager_restore_irq();

	return TEE_PAGER_NORMAL_RETURN;
}

void tee_pager_abort_handler(uint32_t abort_type,
			     struct thread_abort_regs *regs)
{
	static const uint32_t abort_type_to_flags[] = {
		TEE_PAGER_UNDEF_ABORT,
		TEE_PAGER_PREF_ABORT,
		TEE_PAGER_DATA_ABORT,
	};
	uint32_t res;

	res = tee_pager_handle_abort(abort_type_to_flags[abort_type],
				     regs->lr, 0, regs);
	if (res == TEE_PAGER_USER_TA_PANIC) {
		/*
		 * It was a user exception, stop user execution and return
		 * to TEE Core.
		 */
		regs->r0 = TEE_ERROR_TARGET_DEAD;
		regs->r1 = true;
		regs->r2 = 0xdeadbeef;
		regs->lr = (uint32_t)tee_svc_unwind_enter_user_mode;
		regs->spsr = read_cpsr();
		regs->spsr &= ~TEE_PAGER_SPSR_MODE_MASK;
		regs->spsr |= TEE_PAGER_SPSR_MODE_SVC;
		/* Select Thumb or ARM mode */
		if (regs->lr & 1)
			regs->spsr |= CPSR_T;
		else
			regs->spsr &= ~CPSR_T;
	}
}

void tee_pager_add_pages(tee_vaddr_t vaddr, size_t npages)
{
	size_t n;

	/* setup memory */
	for (n = 0; n < npages; n++) {
		struct tee_pager_pmem *apage;
		tee_vaddr_t va = vaddr + n * SMALL_PAGE_SIZE;
		uint32_t *mmu_entry = tee_pager_get_mmu_entry(va);

		/* Ignore unmapped entries */
		if (*mmu_entry == 0)
			continue;

		apage = malloc(sizeof(struct tee_pager_pmem));
		if (apage == NULL) {
			DMSG("Can't allocate memory");
			while (1)
				;
		}

		apage->mmu_entry = (uint32_t *)mmu_entry;

		/*
		 * Set to TEE_PAGER_NO_ACCESS_ATTRIBUTES and not
		 * TEE_PAGER_PAGE_UNLOADED since pager would misstake it for a
		 * hidden page in case the virtual address was reused before
		 * the physical page was used for another virtual page.
		 */
		*mmu_entry = (*mmu_entry & ~SMALL_PAGE_MASK) |
		    TEE_PAGER_NO_ACCESS_ATTRIBUTES;
		apage->ctx_handle = NULL;

		TAILQ_INSERT_TAIL(&tee_pager_pmem_head, apage, link);
		tee_pager_npages++;
	}

	/* Invalidate secure TLB */
	core_tlb_maintenance(TLBINV_UNIFIEDTLB, 0);
}

void tee_pager_unmap(uint32_t page, uint8_t psize)
{
	int i;

	if ((page & 0xFFF) != 0) {
		EMSG("Invalid page address");
		while (1)
			;
	}

	for (i = 0; i < psize; i++) {
		uint32_t addr = page + (i << SMALL_PAGE_SHIFT);
		uint32_t *mmu_entry = tee_pager_get_mmu_entry(addr);

		if (*mmu_entry != 0) {
			struct tee_pager_pmem *apage;

			/* Invalidate mmu_entry */
			*mmu_entry &= ~SMALL_PAGE_MASK;

			/*
			 * Unregister the session from the page entry using
			 * this mmu_entry.
			 */
			TAILQ_FOREACH(apage, &tee_pager_pmem_head, link) {
				if (apage->mmu_entry == (uint32_t *)mmu_entry) {
					apage->ctx_handle = NULL;
					break;
				}
			}

			if (apage == NULL) {
				EMSG("Physical page to unmap not found");
				while (1)
					;
			}
		}
	}

	/* Invalidate secure TLB */
	core_tlb_maintenance(TLBINV_UNIFIEDTLB, 0);
}

void tee_pager_unhide_all_pages(void)
{
	struct tee_pager_pmem *apage;
	bool has_hidden_page = false;

	TAILQ_FOREACH(apage, &tee_pager_pmem_head, link) {
		if ((*apage->mmu_entry & 0xfff) == TEE_PAGER_PAGE_UNLOADED) {
			/* Page is hidden, unhide it */
			has_hidden_page = true;
			*apage->mmu_entry |= 0x10;
		}
	}

	/* Only invalidate secure TLB if something was changed */
	if (has_hidden_page)
		core_tlb_maintenance(TLBINV_UNIFIEDTLB, 0);
}
