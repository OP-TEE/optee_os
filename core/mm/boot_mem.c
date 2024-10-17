// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2024, Linaro Limited
 */

#include <assert.h>
#include <kernel/boot.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <mm/phys_mem.h>
#include <mm/tee_mm.h>
#include <stdalign.h>
#include <string.h>
#include <util.h>

struct boot_mem_reloc {
	void **ptrs[64];
	size_t count;
	struct boot_mem_reloc *next;
};

struct boot_mem_desc {
	vaddr_t orig_mem_start;
	vaddr_t orig_mem_end;
	vaddr_t mem_start;
	vaddr_t mem_end;
	struct boot_mem_reloc *reloc;
};

static struct boot_mem_desc *boot_mem_desc;

static void *mem_alloc_tmp(struct boot_mem_desc *desc, size_t len, size_t align)
{
	vaddr_t va = 0;

	assert(desc && desc->mem_start && desc->mem_end);
	assert(IS_POWER_OF_TWO(align) && !(len % align));
	if (SUB_OVERFLOW(desc->mem_end, len, &va))
		panic();
	va = ROUNDDOWN(va, align);
	if (va < desc->mem_start)
		panic();
	desc->mem_end = va;
	return (void *)va;
}

static void *mem_alloc(struct boot_mem_desc *desc, size_t len, size_t align)
{
	vaddr_t va = 0;
	vaddr_t ve = 0;

	runtime_assert(!IS_ENABLED(CFG_WITH_PAGER));
	assert(desc && desc->mem_start && desc->mem_end);
	assert(IS_POWER_OF_TWO(align) && !(len % align));
	va = ROUNDUP(desc->mem_start, align);
	if (ADD_OVERFLOW(va, len, &ve))
		panic();
	if (ve > desc->mem_end)
		panic();
	desc->mem_start = ve;
	return (void *)va;
}

void boot_mem_init(vaddr_t start, vaddr_t end, vaddr_t orig_end)
{
	struct boot_mem_desc desc = {
		.orig_mem_start = start,
		.orig_mem_end = orig_end,
		.mem_start = start,
		.mem_end = end,
	};

	boot_mem_desc = mem_alloc_tmp(&desc, sizeof(desc), alignof(desc));
	*boot_mem_desc = desc;
	boot_mem_desc->reloc = mem_alloc_tmp(boot_mem_desc,
					     sizeof(*boot_mem_desc->reloc),
					     alignof(*boot_mem_desc->reloc));
	memset(boot_mem_desc->reloc, 0, sizeof(*boot_mem_desc->reloc));
}

void boot_mem_add_reloc(void *ptr)
{
	struct boot_mem_reloc *reloc = NULL;

	assert(boot_mem_desc && boot_mem_desc->reloc);
	reloc = boot_mem_desc->reloc;

	/* If the reloc struct is full, allocate a new and link it first */
	if (reloc->count == ARRAY_SIZE(reloc->ptrs)) {
		reloc = boot_mem_alloc_tmp(sizeof(*reloc), alignof(*reloc));
		reloc->next = boot_mem_desc->reloc;
		boot_mem_desc->reloc = reloc;
	}

	reloc->ptrs[reloc->count] = ptr;
	reloc->count++;
}

static void *add_offs(void *p, size_t offs)
{
	assert(p);
	return (uint8_t *)p + offs;
}

void boot_mem_relocate(size_t offs)
{
	struct boot_mem_reloc *reloc = NULL;
	size_t n = 0;

	boot_mem_desc = add_offs(boot_mem_desc, offs);

	boot_mem_desc->orig_mem_start += offs;
	boot_mem_desc->orig_mem_end += offs;
	boot_mem_desc->mem_start += offs;
	boot_mem_desc->mem_end += offs;
	boot_mem_desc->reloc = add_offs(boot_mem_desc->reloc, offs);

	for (reloc = boot_mem_desc->reloc;; reloc = reloc->next) {
		for (n = 0; n < reloc->count; n++) {
			reloc->ptrs[n] = add_offs(reloc->ptrs[n], offs);
			*reloc->ptrs[n] = add_offs(*reloc->ptrs[n], offs);
		}
		if (!reloc->next)
			break;
		reloc->next = add_offs(reloc->next, offs);
	}
}

void *boot_mem_alloc(size_t len, size_t align)
{
	return mem_alloc(boot_mem_desc, len, align);
}

void *boot_mem_alloc_tmp(size_t len, size_t align)
{
	return mem_alloc_tmp(boot_mem_desc, len, align);
}

vaddr_t boot_mem_release_unused(void)
{
	tee_mm_entry_t *mm = NULL;
	paddr_t pa = 0;
	vaddr_t va = 0;
	size_t n = 0;
	vaddr_t tmp_va = 0;
	paddr_t tmp_pa = 0;
	size_t tmp_n = 0;

	assert(boot_mem_desc);

	n = boot_mem_desc->mem_start - boot_mem_desc->orig_mem_start;
	DMSG("Allocated %zu bytes at va %#"PRIxVA" pa %#"PRIxPA,
	     n, boot_mem_desc->orig_mem_start,
	     vaddr_to_phys(boot_mem_desc->orig_mem_start));

	DMSG("Tempalloc %zu bytes at va %#"PRIxVA,
	     (size_t)(boot_mem_desc->orig_mem_end - boot_mem_desc->mem_end),
	     boot_mem_desc->mem_end);

	if (IS_ENABLED(CFG_WITH_PAGER))
		goto out;

	pa = vaddr_to_phys(ROUNDUP(boot_mem_desc->orig_mem_start,
				   SMALL_PAGE_SIZE));
	mm = nex_phys_mem_mm_find(pa);
	if (!mm)
		panic();

	va = ROUNDUP(boot_mem_desc->mem_start, SMALL_PAGE_SIZE);

	tmp_va = ROUNDDOWN(boot_mem_desc->mem_end, SMALL_PAGE_SIZE);
	tmp_n = boot_mem_desc->orig_mem_end - tmp_va;
	tmp_pa = vaddr_to_phys(tmp_va);

	pa = tee_mm_get_smem(mm);
	n = vaddr_to_phys(boot_mem_desc->mem_start) - pa;
	tee_mm_free(mm);
	DMSG("Carving out %#"PRIxPA"..%#"PRIxPA, pa, pa + n - 1);
	mm = nex_phys_mem_alloc2(pa, n);
	if (!mm)
		panic();
	mm = nex_phys_mem_alloc2(tmp_pa, tmp_n);
	if (!mm)
		panic();

	n = tmp_va - boot_mem_desc->mem_start;
	DMSG("Releasing %zu bytes from va %#"PRIxVA, n, va);

	/* Unmap the now unused pages */
	core_mmu_unmap_pages(va, n / SMALL_PAGE_SIZE);

out:
	/* Stop further allocations. */
	boot_mem_desc->mem_start = boot_mem_desc->mem_end;
	return va;
}

void boot_mem_release_tmp_alloc(void)
{
	tee_mm_entry_t *mm = NULL;
	vaddr_t va = 0;
	paddr_t pa = 0;
	size_t n = 0;

	assert(boot_mem_desc &&
	       boot_mem_desc->mem_start == boot_mem_desc->mem_end);

	if (IS_ENABLED(CFG_WITH_PAGER)) {
		n = boot_mem_desc->orig_mem_end - boot_mem_desc->mem_end;
		va = boot_mem_desc->mem_end;
		boot_mem_desc = NULL;
		DMSG("Releasing %zu bytes from va %#"PRIxVA, n, va);
		return;
	}

	va = ROUNDDOWN(boot_mem_desc->mem_end, SMALL_PAGE_SIZE);
	pa = vaddr_to_phys(va);

	mm = nex_phys_mem_mm_find(pa);
	if (!mm)
		panic();
	assert(pa == tee_mm_get_smem(mm));
	n = tee_mm_get_bytes(mm);

	/* Boot memory allocation is now done */
	boot_mem_desc = NULL;

	DMSG("Releasing %zu bytes from va %#"PRIxVA, n, va);

	/* Unmap the now unused pages */
	core_mmu_unmap_pages(va, n / SMALL_PAGE_SIZE);
}
