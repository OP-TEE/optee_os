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

#include <kernel/tee_common.h>
#include <mm/tee_mmu_defs.h>
#include <kernel/tee_core_trace.h>
#include <mm/tee_pager_unpg.h>
#include <mm/core_mmu.h>

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
