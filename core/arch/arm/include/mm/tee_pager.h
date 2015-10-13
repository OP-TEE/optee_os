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

#ifndef MM_TEE_PAGER_H
#define MM_TEE_PAGER_H

#include <kernel/thread.h>
#include <mm/tee_mm_unpg.h>

/* Read-only mapping */
#define TEE_PAGER_AREA_RO	(1 << 0)
/*
 * Read/write mapping, pages will only be reused after explicit release of
 * the pages. A partial area can be release for instance when shrinking a
 * stack.
 */
#define TEE_PAGER_AREA_RW	(1 << 1)
/* Executable mapping */
#define TEE_PAGER_AREA_X	(1 << 2)

/*
 * tee_pager_add_area() - Adds a pageable area
 * @mm:		covered memory area
 * @flags:	describes attributes of mapping
 * @store:	backing store for the memory area
 * @hashes:	hashes of the pages in the backing store
 *
 * Exacly of TEE_PAGER_AREA_RO and TEE_PAGER_AREA_RW has to be supplied in
 * flags.
 *
 * If TEE_PAGER_AREA_X is supplied the area will be mapped as executable,
 * currently only supported together with TEE_PAGER_AREA_RO.
 *
 * TEE_PAGER_AREA_RO requires store and hashes to be !NULL while
 * TEE_PAGER_AREA_RW requires store and hashes to be NULL, pages will only
 * be reused after explicit release of the pages. A partial area can be
 * release for instance when releasing unused parts of a stack.
 *
 * Invalid use of flags will cause a panic.
 *
 * Return true on success or false if area can't be added.
 */
bool tee_pager_add_area(tee_mm_entry_t *mm, uint32_t flags, const void *store,
		const void *hashes);

void tee_pager_abort_handler(uint32_t abort_type,
		struct thread_abort_regs *regs);

/*
 * Adds physical pages to the pager to use. The supplied virtual address range
 * is searched for mapped physical pages and unmapped pages are ignored.
 *
 * vaddr is the first virtual address
 * npages is the number of pages to add
 */
void tee_pager_add_pages(vaddr_t vaddr, size_t npages, bool unmap);

/*
 * Unmap vmem and free physical pages for the pager.
 *
 * vaddr is the first virtual address (must be page aligned)
 * size is the vmem size in bytes (must be page size aligned)
 */
void tee_pager_release_zi(vaddr_t vaddr, size_t size);

/*
 * allocate RW vmem and register to the pager.
 *
 * size is the vmem size in bytes
 */
void *tee_pager_request_zi(size_t size);

#endif /*MM_TEE_PAGER_H*/
