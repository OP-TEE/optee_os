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
#include <stdint.h>
#include <string.h>
#include <sm/sm.h>
#include <sm/tee_mon.h>
#include <sm/teesmc.h>
#include <sm/teesmc_optee.h>
#include <arm.h>
#include <kernel/thread.h>
#include <kernel/panic.h>
#include <malloc.h>
#include <util.h>
#include <trace.h>
#include <kernel/misc.h>
#include <mm/tee_pager.h>
#include <mm/core_mmu.h>
#include <mm/tee_mmu.h>
#include <mm/tee_mmu_defs.h>
#include <plat_common.h>
#include <pm/pm.h>
#include <tee/entry.h>
#include <tee/arch_svc.h>
#include <console.h>
#include <asc.h>
#include <assert.h>
#include <platform_config.h>

/* teecore heap address/size is defined in scatter file */
extern unsigned char teecore_heap_start;
extern unsigned char teecore_heap_end;


static void main_fiq(void);
static void main_tee_entry(struct thread_smc_args *args);

static const struct thread_handlers handlers = {
	.std_smc = main_tee_entry,
	.fast_smc = main_tee_entry,
	.fiq = main_fiq,
	.svc = tee_svc_handler,
	.abort = tee_pager_abort_handler,
	.cpu_on = pm_panic,
	.cpu_off = pm_panic,
	.cpu_suspend = pm_panic,
	.cpu_resume = pm_panic,
	.system_off = pm_panic,
	.system_reset = pm_panic,
};

void main_init(uint32_t nsec_entry); /* called from assembly only */
void main_init(uint32_t nsec_entry)
{
	struct sm_nsec_ctx *nsec_ctx;
	size_t pos = get_core_pos();

	/*
	 * Mask IRQ and FIQ before switch to the thread vector as the
	 * thread handler requires IRQ and FIQ to be masked while executing
	 * with the temporary stack. The thread subsystem also asserts that
	 * IRQ is blocked when using most if its functions.
	 */
	write_cpsr(read_cpsr() | CPSR_F | CPSR_I);

	if (pos == 0)
		thread_init_primary(&handlers);

	thread_init_per_cpu();

	/* Initialize secure monitor */
	nsec_ctx = sm_get_nsec_ctx();
	nsec_ctx->mon_lr = nsec_entry;
	nsec_ctx->mon_spsr = CPSR_MODE_SVC | CPSR_I;

	if (pos == 0) {
		unsigned long a, s;
		/* core malloc pool init */
#ifdef CFG_TEE_MALLOC_START
		a = CFG_TEE_MALLOC_START;
		s = CFG_TEE_MALLOC_SIZE;
#else
		a = (unsigned long)&teecore_heap_start;
		s = (unsigned long)&teecore_heap_end;
		a = ((a + 1) & ~0x0FFFF) + 0x10000;	/* 64kB aligned */
		s = s & ~0x0FFFF;	/* 64kB aligned */
		s = s - a;
#endif
		malloc_init((void *)a, s);

		teecore_init_ta_ram();
	}
}

static void main_fiq(void)
{
	panic();
}

static void main_tee_entry(struct thread_smc_args *args)
{
	/* TODO move to main_init() */
	if (init_teecore() != TEE_SUCCESS)
		panic();

	plat_common_tee_entry(args);
}

/* ttbr1 for teecore mapping: 16kB, fixed addr. */
extern uint8_t *SEC_MMU_TTB_FLD;
/* ttbr0 for TA mapping (default was 128kB) */
extern uint8_t *SEC_TA_MMU_TTB_FLD;

paddr_t core_mmu_get_main_ttb_pa(void)
{
	/* Note that this depends on flat mapping of TEE Core */
	paddr_t pa = (paddr_t)core_mmu_get_main_ttb_va();

	TEE_ASSERT(!(pa & ~TEE_MMU_TTB_L1_MASK));
	return pa;
}

vaddr_t core_mmu_get_main_ttb_va(void)
{
	return (vaddr_t)&SEC_MMU_TTB_FLD;
}

paddr_t core_mmu_get_ul1_ttb_pa(void)
{
	/* Note that this depends on flat mapping of TEE Core */
	paddr_t pa = (paddr_t)core_mmu_get_ul1_ttb_va();
	TEE_ASSERT(!(pa & ~TEE_MMU_TTB_UL1_MASK));
	return pa;
}

vaddr_t core_mmu_get_ul1_ttb_va(void)
{
	return (vaddr_t)&SEC_TA_MMU_TTB_FLD;
}

void console_putc(int ch)
{
	__asc_xmit_char((char)ch);
}

void console_flush(void)
{
	__asc_flush();
}

/* L2 translation table(s) for teecore mapping: fixed addr. */
extern uint8_t *SEC_MMU_L2_TTB_FLD;
extern uint8_t *SEC_MMU_L2_TTB_END;

void *core_mmu_alloc_l2(struct tee_mmap_region *mm)
{
	/* Can't have this in .bss since it's not initialized yet */
	static size_t l2_offs __attribute__((section(".data")));
	const size_t l2_size = SEC_MMU_L2_TTB_END - SEC_MMU_L2_TTB_FLD;
	const size_t l2_va_size = TEE_MMU_L2_NUM_ENTRIES * SMALL_PAGE_SIZE;
	size_t l2_va_space = ((l2_size - l2_offs) / TEE_MMU_L2_SIZE) *
				l2_va_size;

	if (l2_offs)
		return NULL;
	if (mm->size > l2_va_space)
		return NULL;
	l2_offs += ROUNDUP(mm->size, l2_va_size) / l2_va_size;
	return SEC_MMU_L2_TTB_FLD;
}
