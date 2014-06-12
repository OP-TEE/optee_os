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

#include <stdlib.h>
#include <inttypes.h>
#include <kernel/tee_common_unpg.h>
#include <mm/tee_mmu_defs.h>
#include <kernel/tee_core_trace.h>

#include <mm/tee_pager_unpg.h>

#include <mm/tee_mm_unpg.h>
#include <mm/tee_mmu_unpg.h>
#include <mm/core_mmu.h>
#include <tee/tee_svc.h>
#include <arm32.h>

/* Dummies to allow the macros to be left at current places below */
#define TEE_PAGER_RECORD_FAULT(x)   do { } while (0)
#define TEE_PAGER_SET_OLD_VA(x)     do { } while (0)
#define TEE_PAGER_SET_PA(x)         do { } while (0)
#define TEE_PAGER_SET_COPY(x)       do { } while (0)
#define TEE_PAGER_SET_UNHIDE(x)     do { } while (0)
#define TEE_PAGER_DUMP_RECORDING()  do { } while (0)
#define TEE_PRINT_SAVED_REGS()      do { } while (0)

/* The list of physical pages. The first page in the list is the oldest */
struct tee_pager_pmem_head tee_pager_pmem_head =
TAILQ_HEAD_INITIALIZER(tee_pager_pmem_head);

/* number of pages hidden */
#define TEE_PAGER_NHIDE (tee_pager_npages / 3)

/* number of pages */
uint8_t tee_pager_npages;

static bool tee_pager_is_monitor_exception(void)
{
	return (tee_pager_get_spsr() & TEE_PAGER_SPSR_MODE_MASK) ==
	    TEE_PAGER_SPSR_MODE_MON;
}

bool tee_pager_is_user_exception(void)
{
	return (tee_pager_get_spsr() & TEE_PAGER_SPSR_MODE_MASK) ==
	    TEE_PAGER_SPSR_MODE_USR;
}

bool tee_pager_is_abort_in_abort_handler(void)
{
	return (tee_pager_get_spsr() & TEE_PAGER_SPSR_MODE_MASK) ==
	    TEE_PAGER_SPSR_MODE_ABT;
}

static void tee_pager_print_abort(const uint32_t addr, const uint32_t fsr,
				  const uint32_t pc, const uint32_t flags,
				  const uint32_t dbgpcsr)
{
	DMSG("%s at 0x%x: FSR 0x%x PC 0x%x TTBR0 0x%X CONTEXIDR 0x%X",
	     (flags == TEE_PAGER_DATA_ABORT) ? "data-abort" :
	     (flags == TEE_PAGER_PREF_ABORT) ? "prefetch-abort" : "undef-abort",
	     addr, fsr, pc, tee_mmu_get_ttbr0(), tee_mmu_get_context());
	DMSG("CPUID %dd DBGPCSR 0x%x SPSR_abt 0x%x",
	     TEE_PAGER_GET_CPUID_asm(), dbgpcsr, tee_pager_get_spsr());
}

static void tee_pager_print_error_abort(const uint32_t addr, const uint32_t fsr,
					const uint32_t pc, const uint32_t flags,
					const uint32_t dbgpcsr)
{
	EMSG("%s at 0x%x\n"
	     "FSR 0x%x PC 0x%x TTBR0 0x%X CONTEXIDR 0x%X\n"
	     "CPUID 0x%x DBGPCSR 0x%x CPSR 0x%x (read from SPSR)",
	     (flags == TEE_PAGER_DATA_ABORT) ? "data-abort" :
	     (flags == TEE_PAGER_PREF_ABORT) ? "prefetch-abort" : "undef-abort",
	     addr, fsr, pc, tee_mmu_get_ttbr0(), tee_mmu_get_context(),
	     TEE_PAGER_GET_CPUID_asm(), dbgpcsr, tee_pager_get_spsr());
}

static uint32_t tee_pager_handle_abort(const uint32_t flags, const uint32_t pc,
				       const uint32_t dbgpcsr)
{
	struct tee_pager_pmem *apage;
	uint32_t addr;
	uint32_t w_addr;
	uint32_t i;
	uint32_t fsr;

	if (flags == TEE_PAGER_DATA_ABORT) {
		fsr = TEE_PAGER_GET_DFSR_asm();
		addr = TEE_PAGER_GET_DFAR_asm();
	} else {
		if (flags == TEE_PAGER_PREF_ABORT) {
			fsr = TEE_PAGER_GET_IFSR_asm();
			addr = TEE_PAGER_GET_IFAR_asm();
		} else {
			fsr = 0;
			addr = pc;
		}
	}

	w_addr = addr;

	/*
	 * w_addr is the address that we intend to handle to the page fault
	 * for. This is normally the same as addr except in the case where we
	 * have thumb instruction spread over two pages and the first page
	 * already is available. In that case will addr still be the beginning
	 * of the instruction even if the fault really is for the second page.
	 */

	/* In case of multithreaded version, this section must be protected */

	if (tee_pager_is_user_exception()) {
		tee_pager_print_error_abort(addr, fsr, pc, flags, dbgpcsr);
		EMSG("[TEE_PAGER] abort in User mode (TA will panic)");
		return TEE_PAGER_USER_TA_PANIC;
	}

	if (tee_pager_is_monitor_exception())
		EMSG("[TEE_PAGER] abort in monitor!");

	if (tee_pager_is_abort_in_abort_handler()) {
		tee_pager_print_error_abort(addr, fsr, pc, flags, dbgpcsr);
		EMSG("[TEE_PAGER] abort in abort handler (trap CPU)");
		while (1)
			;
	}

	if (flags == TEE_PAGER_UNDEF_ABORT) {
		tee_pager_print_error_abort(addr, fsr, pc, flags, dbgpcsr);
		EMSG("[TEE_PAGER] undefined abort (trap CPU)");
		while (1)
			;
	}

	switch (fsr & TEE_FSR_FS_MASK) {
	case TEE_FSR_FS_ALIGNMENT_FAULT: /* Only possible for data abort */
		tee_pager_print_error_abort(addr, fsr, pc, flags, dbgpcsr);
		EMSG("[TEE_PAGER] alignement fault!  (trap CPU)");
		while (1)
			;

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

	TEE_PAGER_RECORD_FAULT(addr);

	/* check if the access is valid */
	if (!tee_mm_validate(&tee_mm_vcore, w_addr)) {
		tee_pager_print_abort(addr, fsr, pc, flags, dbgpcsr);
		DMSG("Invalid addr 0x%" PRIx32, addr);
		TEE_PRINT_SAVED_REGS();
		TEE_PAGER_DUMP_RECORDING();
		while (1)
			;
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
			TEE_PAGER_SET_UNHIDE(1);
			TEE_PAGER_SET_PA((*(apage->mmu_entry)) & 0xFFFFF000);

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
				while (1)
					;
			}
		} else {
			apage = TAILQ_FIRST(&tee_pager_pmem_head);
			if (apage == NULL) {
				tee_pager_print_abort(addr, fsr, pc, flags,
						      dbgpcsr);
				DMSG("No pmem entries");
				while (1)
					;
			}
		}

		TEE_PAGER_SET_OLD_VA(TEE_PAGER_GET_VA(apage->mmu_entry));

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
		TEE_PAGER_SET_PA(pa);

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
		TEE_PAGER_SET_COPY(1);

		core_cache_maintenance(DCACHE_AREA_CLEAN,
				      (void *)(w_addr & 0xFFFFF000),
				      SMALL_PAGE_SIZE);

		core_cache_maintenance(ICACHE_AREA_INVALIDATE,
				      (void *)(w_addr & 0xFFFFF000),
				      SMALL_PAGE_SIZE);
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
				     regs->lr, 0);
	if (res == TEE_PAGER_USER_TA_PANIC) {
		/*
		 * It was a user exception, stop user execution and return
		 * to TEE Core.
		 */
		regs->r0 = 0xdeadbeef;
		regs->lr = (uint32_t)tee_svc_user_ta_panic_from_pager;
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

void tee_pager_restore_irq(void)
{
	/*
	 * Restores the settings of IRQ as saved when entering secure
	 * world, using something like
	 * INTERRUPT_ENABLE(SEC_ENV_SETTINGS_READ() & SEC_ROM_IRQ_ENABLE_MASK);
	 */

	/* Make a crash on purpose as this is not implemented yet */
	int *p = 0;
	*p = 1;
}
