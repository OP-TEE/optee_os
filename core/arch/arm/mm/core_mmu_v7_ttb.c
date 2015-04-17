/*
 * Copyright (c) 2014, Linaro Limited
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

#include <mm/core_mmu.h>
#include <mm/tee_mmu_defs.h>
#include <kernel/thread.h>
#include <trace.h>
#include <util.h>

#ifdef CFG_WITH_LPAE
#error This file is not to be used with LPAE
#endif

/* Main MMU L1 table for teecore */
static uint32_t main_mmu_l1_ttb[TEE_MMU_L1_NUM_ENTRIES]
	__attribute__((section(".nozi.mmu.l1"),
		       aligned(TEE_MMU_L1_ALIGNMENT)));
static uint32_t main_mmu_l2_ttb[TEE_MMU_L2_NUM_ENTRIES]
	__attribute__((section(".nozi.mmu.l2"),
		       aligned(TEE_MMU_L2_ALIGNMENT)));

/* MMU L1 table for TAs, one for each Core */
static uint32_t main_mmu_ul1_ttb[CFG_NUM_THREADS][TEE_MMU_UL1_NUM_ENTRIES]
	__attribute__((section(".nozi.mmu.ul1"),
		      aligned(TEE_MMU_UL1_ALIGNMENT)));

paddr_t core_mmu_get_main_ttb_pa(void)
{
	/* Note that this depends on flat mapping of TEE Core */
	paddr_t pa = (paddr_t)core_mmu_get_main_ttb_va();

	TEE_ASSERT(!(pa & ~TEE_MMU_TTB_L1_MASK));
	return pa;
}

vaddr_t core_mmu_get_main_ttb_va(void)
{
	return (vaddr_t)main_mmu_l1_ttb;
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
	return (vaddr_t)main_mmu_ul1_ttb[thread_get_id()];
}

void *core_mmu_alloc_l2(struct tee_mmap_region *mm)
{
	/* Can't have this in .bss since it's not initialized yet */
	static size_t l2_offs __attribute__((section(".data")));
	const size_t l2_va_size = TEE_MMU_L2_NUM_ENTRIES * SMALL_PAGE_SIZE;
	size_t l2_va_space = ((sizeof(main_mmu_l2_ttb) - l2_offs) /
			     TEE_MMU_L2_SIZE) * l2_va_size;

	if (l2_offs)
		return NULL;
	if (mm->size > l2_va_space)
		return NULL;
	l2_offs += ROUNDUP(mm->size, l2_va_size) / l2_va_size;
	return main_mmu_l2_ttb;
}
