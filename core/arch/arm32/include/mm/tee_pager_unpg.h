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

/*
 * This h-file holds shared internal defintions for tee_pager*.[cs]
 * and should not be included in other files.
 */

#ifndef TEE_PAGER_UNPG_H
#define TEE_PAGER_UNPG_H

#include <kernel/tee_common_unpg.h>
#include <mm/tee_pager_defines.h>
#include <sys/queue.h>
#include <kernel/thread.h>

/* Interesting aborts for TEE pager */
#define TEE_FSR_FS_MASK                     0x040F
#define TEE_FSR_FS_ALIGNMENT_FAULT          0x0001 /* DFSR[10,3:0] 0b00001 */
#define TEE_FSR_FS_DEBUG_EVENT              0x0002 /* DFSR[10,3:0] 0b00010 */
#define TEE_FSR_FS_ASYNC_EXTERNAL_ABORT     0x0406 /* DFSR[10,3:0] 0b10110 */
#define TEE_FSR_FS_PERMISSION_FAULT_SECTION 0x000D /* DFSR[10,3:0] 0b01101 */
#define TEE_FSR_FS_PERMISSION_FAULT_PAGE    0x000F /* DFSR[10,3:0] 0b01111 */

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

TAILQ_HEAD(tee_pager_pmem_head, tee_pager_pmem);

/* Head of registered physical pages */
extern struct tee_pager_pmem_head tee_pager_pmem_head;
/* Number of registered physical pages, used hiding pages. */
extern uint8_t tee_pager_npages;

void tee_pager_abort_handler(uint32_t abort_type,
			     struct thread_abort_regs *regs);

/* Get VA from L2 MMU entry address */
#define TEE_PAGER_GET_VA(a)					\
	(((((uint32_t)a) - SEC_VIRT_MMU_L2_BASE) <<		\
	(SMALL_PAGE_SHIFT - 2)) + TEE_VMEM_START)

/* Get L2 MMU entry address from virtual address */
static inline uint32_t *tee_pager_get_mmu_entry(tee_vaddr_t va)
{
	tee_vaddr_t addr = va & ~SMALL_PAGE_MASK;
	size_t mmu_entry_offset = (addr - TEE_VMEM_START) >> SMALL_PAGE_SHIFT;

	return (uint32_t *)(TEE_VIRT_MMU_L2_BASE +
			     mmu_entry_offset * sizeof(uint32_t));
}

/* Returns true if the exception originated from user mode */
bool tee_pager_is_user_exception(void);
/* Returns true if the exception originated from abort mode */
bool tee_pager_is_abort_in_abort_handler(void);

void tee_pager_restore_irq(void);

#endif /* TEE_PAGER_UNPG_H */
