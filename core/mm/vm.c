// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016-2021, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2021, Arm Limited
 */

#include <assert.h>
#include <config.h>
#include <initcall.h>
#include <kernel/panic.h>
#include <kernel/spinlock.h>
#include <kernel/tee_common.h>
#include <kernel/tee_misc.h>
#include <kernel/tlb_helpers.h>
#include <kernel/user_mode_ctx.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <mm/mobj.h>
#include <mm/pgt_cache.h>
#include <mm/tee_mm.h>
#include <mm/tee_mmu_types.h>
#include <mm/tee_pager.h>
#include <mm/vm.h>
#include <stdlib.h>
#include <tee_api_defines_extensions.h>
#include <tee_api_types.h>
#include <trace.h>
#include <types_ext.h>
#include <user_ta_header.h>
#include <util.h>

#ifdef CFG_PL310
#include <kernel/tee_l2cc_mutex.h>
#endif

#define TEE_MMU_UDATA_ATTR		(TEE_MATTR_VALID_BLOCK | \
					 TEE_MATTR_PRW | TEE_MATTR_URW | \
					 TEE_MATTR_SECURE)
#define TEE_MMU_UCODE_ATTR		(TEE_MATTR_VALID_BLOCK | \
					 TEE_MATTR_PRW | TEE_MATTR_URWX | \
					 TEE_MATTR_SECURE)

#define TEE_MMU_UCACHE_DEFAULT_ATTR	(TEE_MATTR_MEM_TYPE_CACHED << \
					 TEE_MATTR_MEM_TYPE_SHIFT)

static vaddr_t select_va_in_range(const struct vm_region *prev_reg,
				  const struct vm_region *next_reg,
				  const struct vm_region *reg,
				  size_t pad_begin, size_t pad_end,
				  size_t granul)
{
	const uint32_t f = VM_FLAG_EPHEMERAL | VM_FLAG_PERMANENT |
			    VM_FLAG_SHAREABLE;
	vaddr_t begin_va = 0;
	vaddr_t end_va = 0;
	size_t pad = 0;

	/*
	 * Insert an unmapped entry to separate regions with differing
	 * VM_FLAG_EPHEMERAL, VM_FLAG_PERMANENT or VM_FLAG_SHAREABLE
	 * bits as they never are to be contiguous with another region.
	 */
	if (prev_reg->flags && (prev_reg->flags & f) != (reg->flags & f))
		pad = SMALL_PAGE_SIZE;
	else
		pad = 0;

#ifndef CFG_WITH_LPAE
	if ((prev_reg->attr & TEE_MATTR_SECURE) !=
	    (reg->attr & TEE_MATTR_SECURE))
		granul = CORE_MMU_PGDIR_SIZE;
#endif

	if (ADD_OVERFLOW(prev_reg->va, prev_reg->size, &begin_va) ||
	    ADD_OVERFLOW(begin_va, pad_begin, &begin_va) ||
	    ADD_OVERFLOW(begin_va, pad, &begin_va) ||
	    ROUNDUP_OVERFLOW(begin_va, granul, &begin_va))
		return 0;

	if (reg->va) {
		if (reg->va < begin_va)
			return 0;
		begin_va = reg->va;
	}

	if (next_reg->flags && (next_reg->flags & f) != (reg->flags & f))
		pad = SMALL_PAGE_SIZE;
	else
		pad = 0;

#ifndef CFG_WITH_LPAE
	if ((next_reg->attr & TEE_MATTR_SECURE) !=
	    (reg->attr & TEE_MATTR_SECURE))
		granul = CORE_MMU_PGDIR_SIZE;
#endif
	if (ADD_OVERFLOW(begin_va, reg->size, &end_va) ||
	    ADD_OVERFLOW(end_va, pad_end, &end_va) ||
	    ADD_OVERFLOW(end_va, pad, &end_va) ||
	    ROUNDUP_OVERFLOW(end_va, granul, &end_va))
		return 0;

	if (end_va <= next_reg->va) {
		assert(!reg->va || reg->va == begin_va);
		return begin_va;
	}

	return 0;
}

static TEE_Result alloc_pgt(struct user_mode_ctx *uctx)
{
	struct thread_specific_data *tsd __maybe_unused;

	if (!pgt_check_avail(uctx)) {
		EMSG("Page tables are not available");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

#ifdef CFG_PAGED_USER_TA
	tsd = thread_get_tsd();
	if (uctx->ts_ctx == tsd->ctx) {
		/*
		 * The supplied utc is the current active utc, allocate the
		 * page tables too as the pager needs to use them soon.
		 */
		pgt_get_all(uctx);
	}
#endif

	return TEE_SUCCESS;
}

static void rem_um_region(struct user_mode_ctx *uctx, struct vm_region *r)
{
	vaddr_t begin = ROUNDDOWN(r->va, CORE_MMU_PGDIR_SIZE);
	vaddr_t last = ROUNDUP(r->va + r->size, CORE_MMU_PGDIR_SIZE);
	struct vm_region *r2 = NULL;

	if (mobj_is_paged(r->mobj)) {
		tee_pager_rem_um_region(uctx, r->va, r->size);
	} else {
		pgt_clear_range(uctx, r->va, r->va + r->size);
		tlbi_va_range_asid(r->va, r->size, SMALL_PAGE_SIZE,
				   uctx->vm_info.asid);
	}

	/*
	 * Figure out how much virtual memory on a CORE_MMU_PGDIR_SIZE
	 * grunalarity can be freed. Only completely unused
	 * CORE_MMU_PGDIR_SIZE ranges can be supplied to pgt_flush_range().
	 *
	 * Note that there's is no margin for error here, both flushing too
	 * many or too few translation tables can be fatal.
	 */
	r2 = TAILQ_NEXT(r, link);
	if (r2)
		last = MIN(last, ROUNDDOWN(r2->va, CORE_MMU_PGDIR_SIZE));

	r2 = TAILQ_PREV(r, vm_region_head, link);
	if (r2)
		begin = MAX(begin,
			    ROUNDUP(r2->va + r2->size, CORE_MMU_PGDIR_SIZE));

	if (begin < last)
		pgt_flush_range(uctx, begin, last);
}

static void set_pa_range(struct core_mmu_table_info *ti, vaddr_t va,
			 paddr_t pa, size_t size, uint32_t attr)
{
	unsigned int end = core_mmu_va2idx(ti, va + size);
	unsigned int idx = core_mmu_va2idx(ti, va);

	while (idx < end) {
		core_mmu_set_entry(ti, idx, pa, attr);
		idx++;
		pa += BIT64(ti->shift);
	}
}

static void set_reg_in_table(struct core_mmu_table_info *ti,
			     struct vm_region *r)
{
	vaddr_t va = MAX(r->va, ti->va_base);
	vaddr_t end = MIN(r->va + r->size, ti->va_base + CORE_MMU_PGDIR_SIZE);
	size_t sz = MIN(end - va, mobj_get_phys_granule(r->mobj));
	size_t granule = BIT(ti->shift);
	size_t offset = 0;
	paddr_t pa = 0;

	while (va < end) {
		offset = va - r->va + r->offset;
		if (mobj_get_pa(r->mobj, offset, granule, &pa))
			panic("Failed to get PA");
		set_pa_range(ti, va, pa, sz, r->attr);
		va += sz;
	}
}

static void set_um_region(struct user_mode_ctx *uctx, struct vm_region *r)
{
	struct pgt *p = SLIST_FIRST(&uctx->pgt_cache);
	struct core_mmu_table_info ti = { };

	assert(!mobj_is_paged(r->mobj));

	core_mmu_set_info_table(&ti, CORE_MMU_PGDIR_LEVEL, 0, NULL);

	if (p) {
		/* All the pgts are already allocated, update in place */
		do {
			ti.va_base = p->vabase;
			ti.table = p->tbl;
			set_reg_in_table(&ti, r);
			p = SLIST_NEXT(p, link);
		} while (p);
	} else {
		/*
		 * We may have a few pgts in the cache list, update the
		 * ones found.
		 */
		for (ti.va_base = ROUNDDOWN(r->va, CORE_MMU_PGDIR_SIZE);
		     ti.va_base < r->va + r->size;
		     ti.va_base += CORE_MMU_PGDIR_SIZE) {
			p = pgt_pop_from_cache_list(ti.va_base, uctx->ts_ctx);
			if (!p)
				continue;
			ti.table = p->tbl;
			set_reg_in_table(&ti, r);
			pgt_push_to_cache_list(p);
		}
	}
}

static TEE_Result umap_add_region(struct vm_info *vmi, struct vm_region *reg,
				  size_t pad_begin, size_t pad_end,
				  size_t align)
{
	struct vm_region dummy_first_reg = { };
	struct vm_region dummy_last_reg = { };
	struct vm_region *r = NULL;
	struct vm_region *prev_r = NULL;
	vaddr_t va_range_base = 0;
	size_t va_range_size = 0;
	size_t granul;
	vaddr_t va = 0;
	size_t offs_plus_size = 0;

	core_mmu_get_user_va_range(&va_range_base, &va_range_size);
	dummy_first_reg.va = va_range_base;
	dummy_last_reg.va = va_range_base + va_range_size;

	/* Check alignment, it has to be at least SMALL_PAGE based */
	if ((reg->va | reg->size | pad_begin | pad_end) & SMALL_PAGE_MASK)
		return TEE_ERROR_ACCESS_CONFLICT;

	/* Check that the mobj is defined for the entire range */
	if (ADD_OVERFLOW(reg->offset, reg->size, &offs_plus_size))
		return TEE_ERROR_BAD_PARAMETERS;
	if (offs_plus_size > ROUNDUP(reg->mobj->size, SMALL_PAGE_SIZE))
		return TEE_ERROR_BAD_PARAMETERS;

	granul = MAX(align, SMALL_PAGE_SIZE);
	if (!IS_POWER_OF_TWO(granul))
		return TEE_ERROR_BAD_PARAMETERS;

	prev_r = &dummy_first_reg;
	TAILQ_FOREACH(r, &vmi->regions, link) {
		va = select_va_in_range(prev_r, r, reg, pad_begin, pad_end,
					granul);
		if (va) {
			reg->va = va;
			TAILQ_INSERT_BEFORE(r, reg, link);
			return TEE_SUCCESS;
		}
		prev_r = r;
	}

	r = TAILQ_LAST(&vmi->regions, vm_region_head);
	if (!r)
		r = &dummy_first_reg;
	va = select_va_in_range(r, &dummy_last_reg, reg, pad_begin, pad_end,
				granul);
	if (va) {
		reg->va = va;
		TAILQ_INSERT_TAIL(&vmi->regions, reg, link);
		return TEE_SUCCESS;
	}

	return TEE_ERROR_ACCESS_CONFLICT;
}

TEE_Result vm_map_pad(struct user_mode_ctx *uctx, vaddr_t *va, size_t len,
		      uint32_t prot, uint32_t flags, struct mobj *mobj,
		      size_t offs, size_t pad_begin, size_t pad_end,
		      size_t align)
{
	TEE_Result res = TEE_SUCCESS;
	struct vm_region *reg = NULL;
	uint32_t attr = 0;

	if (prot & ~TEE_MATTR_PROT_MASK)
		return TEE_ERROR_BAD_PARAMETERS;

	reg = calloc(1, sizeof(*reg));
	if (!reg)
		return TEE_ERROR_OUT_OF_MEMORY;

	if (!mobj_is_paged(mobj)) {
		uint32_t mem_type = 0;

		res = mobj_get_mem_type(mobj, &mem_type);
		if (res)
			goto err_free_reg;
		attr |= mem_type << TEE_MATTR_MEM_TYPE_SHIFT;
	}
	attr |= TEE_MATTR_VALID_BLOCK;
	if (mobj_is_secure(mobj))
		attr |= TEE_MATTR_SECURE;

	reg->mobj = mobj_get(mobj);
	reg->offset = offs;
	reg->va = *va;
	reg->size = ROUNDUP(len, SMALL_PAGE_SIZE);
	reg->attr = attr | prot;
	reg->flags = flags;

	res = umap_add_region(&uctx->vm_info, reg, pad_begin, pad_end, align);
	if (res)
		goto err_put_mobj;

	res = alloc_pgt(uctx);
	if (res)
		goto err_rem_reg;

	if (mobj_is_paged(mobj)) {
		struct fobj *fobj = mobj_get_fobj(mobj);

		if (!fobj) {
			res = TEE_ERROR_GENERIC;
			goto err_rem_reg;
		}

		res = tee_pager_add_um_region(uctx, reg->va, fobj, prot);
		fobj_put(fobj);
		if (res)
			goto err_rem_reg;
	} else {
		set_um_region(uctx, reg);
	}

	/*
	 * If the context currently is active set it again to update
	 * the mapping.
	 */
	if (thread_get_tsd()->ctx == uctx->ts_ctx)
		vm_set_ctx(uctx->ts_ctx);

	*va = reg->va;

	return TEE_SUCCESS;

err_rem_reg:
	TAILQ_REMOVE(&uctx->vm_info.regions, reg, link);
err_put_mobj:
	mobj_put(reg->mobj);
err_free_reg:
	free(reg);
	return res;
}

static struct vm_region *find_vm_region(struct vm_info *vm_info, vaddr_t va)
{
	struct vm_region *r = NULL;

	TAILQ_FOREACH(r, &vm_info->regions, link)
		if (va >= r->va && va < r->va + r->size)
			return r;

	return NULL;
}

static bool va_range_is_contiguous(struct vm_region *r0, vaddr_t va,
				   size_t len,
				   bool (*cmp_regs)(const struct vm_region *r0,
						    const struct vm_region *r,
						    const struct vm_region *rn))
{
	struct vm_region *r = r0;
	vaddr_t end_va = 0;

	if (ADD_OVERFLOW(va, len, &end_va))
		return false;

	while (true) {
		struct vm_region *r_next = TAILQ_NEXT(r, link);
		vaddr_t r_end_va = r->va + r->size;

		if (r_end_va >= end_va)
			return true;
		if (!r_next)
			return false;
		if (r_end_va != r_next->va)
			return false;
		if (cmp_regs && !cmp_regs(r0, r, r_next))
			return false;
		r = r_next;
	}
}

static TEE_Result split_vm_region(struct user_mode_ctx *uctx,
				  struct vm_region *r, vaddr_t va)
{
	struct vm_region *r2 = NULL;
	size_t diff = va - r->va;

	assert(diff && diff < r->size);

	r2 = calloc(1, sizeof(*r2));
	if (!r2)
		return TEE_ERROR_OUT_OF_MEMORY;

	if (mobj_is_paged(r->mobj)) {
		TEE_Result res = tee_pager_split_um_region(uctx, va);

		if (res) {
			free(r2);
			return res;
		}
	}

	r2->mobj = mobj_get(r->mobj);
	r2->offset = r->offset + diff;
	r2->va = va;
	r2->size = r->size - diff;
	r2->attr = r->attr;
	r2->flags = r->flags;

	r->size = diff;

	TAILQ_INSERT_AFTER(&uctx->vm_info.regions, r, r2, link);

	return TEE_SUCCESS;
}

static TEE_Result split_vm_range(struct user_mode_ctx *uctx, vaddr_t va,
				 size_t len,
				 bool (*cmp_regs)(const struct vm_region *r0,
						  const struct vm_region *r,
						  const struct vm_region *rn),
				 struct vm_region **r0_ret)
{
	TEE_Result res = TEE_SUCCESS;
	struct vm_region *r = NULL;
	vaddr_t end_va = 0;

	if ((va | len) & SMALL_PAGE_MASK)
		return TEE_ERROR_BAD_PARAMETERS;

	if (ADD_OVERFLOW(va, len, &end_va))
		return TEE_ERROR_BAD_PARAMETERS;

	/*
	 * Find first vm_region in range and check that the entire range is
	 * contiguous.
	 */
	r = find_vm_region(&uctx->vm_info, va);
	if (!r || !va_range_is_contiguous(r, va, len, cmp_regs))
		return TEE_ERROR_BAD_PARAMETERS;

	/*
	 * If needed split regions so that va and len covers only complete
	 * regions.
	 */
	if (va != r->va) {
		res = split_vm_region(uctx, r, va);
		if (res)
			return res;
		r = TAILQ_NEXT(r, link);
	}

	*r0_ret = r;
	r = find_vm_region(&uctx->vm_info, va + len - 1);
	if (!r)
		return TEE_ERROR_BAD_PARAMETERS;
	if (end_va != r->va + r->size) {
		res = split_vm_region(uctx, r, end_va);
		if (res)
			return res;
	}

	return TEE_SUCCESS;
}

static void merge_vm_range(struct user_mode_ctx *uctx, vaddr_t va, size_t len)
{
	struct vm_region *r_next = NULL;
	struct vm_region *r = NULL;
	vaddr_t end_va = 0;

	if (ADD_OVERFLOW(va, len, &end_va))
		return;

	tee_pager_merge_um_region(uctx, va, len);

	for (r = TAILQ_FIRST(&uctx->vm_info.regions);; r = r_next) {
		r_next = TAILQ_NEXT(r, link);
		if (!r_next)
			return;

		/* Try merging with the region just before va */
		if (r->va + r->size < va)
			continue;

		/*
		 * If r->va is well past our range we're done.
		 * Note that if it's just the page after our range we'll
		 * try to merge.
		 */
		if (r->va > end_va)
			return;

		if (r->va + r->size != r_next->va)
			continue;
		if (r->mobj != r_next->mobj ||
		    r->flags != r_next->flags ||
		    r->attr != r_next->attr)
			continue;
		if (r->offset + r->size != r_next->offset)
			continue;

		TAILQ_REMOVE(&uctx->vm_info.regions, r_next, link);
		r->size += r_next->size;
		mobj_put(r_next->mobj);
		free(r_next);
		r_next = r;
	}
}

static bool cmp_region_for_remap(const struct vm_region *r0,
				 const struct vm_region *r,
				 const struct vm_region *rn)
{
	/*
	 * All the essentionals has to match for remap to make sense. The
	 * essentials are, mobj/fobj, attr, flags and the offset should be
	 * contiguous.
	 *
	 * Note that vm_remap() depends on mobj/fobj to be the same.
	 */
	return r0->flags == r->flags && r0->attr == r->attr &&
	       r0->mobj == r->mobj && rn->offset == r->offset + r->size;
}

TEE_Result vm_remap(struct user_mode_ctx *uctx, vaddr_t *new_va, vaddr_t old_va,
		    size_t len, size_t pad_begin, size_t pad_end)
{
	struct vm_region_head regs = TAILQ_HEAD_INITIALIZER(regs);
	TEE_Result res = TEE_SUCCESS;
	struct vm_region *r0 = NULL;
	struct vm_region *r = NULL;
	struct vm_region *r_next = NULL;
	struct vm_region *r_last = NULL;
	struct vm_region *r_first = NULL;
	struct fobj *fobj = NULL;
	vaddr_t next_va = 0;

	assert(thread_get_tsd()->ctx == uctx->ts_ctx);

	if (!len || ((len | old_va) & SMALL_PAGE_MASK))
		return TEE_ERROR_BAD_PARAMETERS;

	res = split_vm_range(uctx, old_va, len, cmp_region_for_remap, &r0);
	if (res)
		return res;

	if (mobj_is_paged(r0->mobj)) {
		fobj = mobj_get_fobj(r0->mobj);
		if (!fobj)
			panic();
	}

	for (r = r0; r; r = r_next) {
		if (r->va + r->size > old_va + len)
			break;
		r_next = TAILQ_NEXT(r, link);
		rem_um_region(uctx, r);
		TAILQ_REMOVE(&uctx->vm_info.regions, r, link);
		TAILQ_INSERT_TAIL(&regs, r, link);
	}

	/*
	 * Synchronize change to translation tables. Even though the pager
	 * case unmaps immediately we may still free a translation table.
	 */
	vm_set_ctx(uctx->ts_ctx);

	r_first = TAILQ_FIRST(&regs);
	while (!TAILQ_EMPTY(&regs)) {
		r = TAILQ_FIRST(&regs);
		TAILQ_REMOVE(&regs, r, link);
		if (r_last) {
			r->va = r_last->va + r_last->size;
			res = umap_add_region(&uctx->vm_info, r, 0, 0, 0);
		} else {
			r->va = *new_va;
			res = umap_add_region(&uctx->vm_info, r, pad_begin,
					      pad_end + len - r->size, 0);
		}
		if (!res) {
			r_last = r;
			res = alloc_pgt(uctx);
		}
		if (!res) {
			if (!fobj)
				set_um_region(uctx, r);
			else
				res = tee_pager_add_um_region(uctx, r->va, fobj,
							      r->attr);
		}

		if (res) {
			/*
			 * Something went wrong move all the recently added
			 * regions back to regs for later reinsertion at
			 * the original spot.
			 */
			struct vm_region *r_tmp = NULL;
			struct vm_region *r_stop = NULL;

			if (r != r_last) {
				/*
				 * umap_add_region() failed, move r back to
				 * regs before all the rest are moved back.
				 */
				TAILQ_INSERT_HEAD(&regs, r, link);
			}
			if (r_last)
				r_stop = TAILQ_NEXT(r_last, link);
			for (r = r_first; r != r_stop; r = r_next) {
				r_next = TAILQ_NEXT(r, link);
				TAILQ_REMOVE(&uctx->vm_info.regions, r, link);
				if (r_tmp)
					TAILQ_INSERT_AFTER(&regs, r_tmp, r,
							   link);
				else
					TAILQ_INSERT_HEAD(&regs, r, link);
				r_tmp = r;
			}

			goto err_restore_map;
		}
	}

	fobj_put(fobj);

	vm_set_ctx(uctx->ts_ctx);
	*new_va = r_first->va;

	return TEE_SUCCESS;

err_restore_map:
	next_va = old_va;
	while (!TAILQ_EMPTY(&regs)) {
		r = TAILQ_FIRST(&regs);
		TAILQ_REMOVE(&regs, r, link);
		r->va = next_va;
		next_va += r->size;
		if (umap_add_region(&uctx->vm_info, r, 0, 0, 0))
			panic("Cannot restore mapping");
		if (alloc_pgt(uctx))
			panic("Cannot restore mapping");
		if (fobj) {
			if (tee_pager_add_um_region(uctx, r->va, fobj, r->attr))
				panic("Cannot restore mapping");
		} else {
			set_um_region(uctx, r);
		}
	}
	fobj_put(fobj);
	vm_set_ctx(uctx->ts_ctx);

	return res;
}

static bool cmp_region_for_get_flags(const struct vm_region *r0,
				     const struct vm_region *r,
				     const struct vm_region *rn __unused)
{
	return r0->flags == r->flags;
}

TEE_Result vm_get_flags(struct user_mode_ctx *uctx, vaddr_t va, size_t len,
			uint32_t *flags)
{
	struct vm_region *r = NULL;

	if (!len || ((len | va) & SMALL_PAGE_MASK))
		return TEE_ERROR_BAD_PARAMETERS;

	r = find_vm_region(&uctx->vm_info, va);
	if (!r)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!va_range_is_contiguous(r, va, len, cmp_region_for_get_flags))
		return TEE_ERROR_BAD_PARAMETERS;

	*flags = r->flags;

	return TEE_SUCCESS;
}

static bool cmp_region_for_get_prot(const struct vm_region *r0,
				    const struct vm_region *r,
				    const struct vm_region *rn __unused)
{
	return (r0->attr & TEE_MATTR_PROT_MASK) ==
	       (r->attr & TEE_MATTR_PROT_MASK);
}

TEE_Result vm_get_prot(struct user_mode_ctx *uctx, vaddr_t va, size_t len,
		       uint16_t *prot)
{
	struct vm_region *r = NULL;

	if (!len || ((len | va) & SMALL_PAGE_MASK))
		return TEE_ERROR_BAD_PARAMETERS;

	r = find_vm_region(&uctx->vm_info, va);
	if (!r)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!va_range_is_contiguous(r, va, len, cmp_region_for_get_prot))
		return TEE_ERROR_BAD_PARAMETERS;

	*prot = r->attr & TEE_MATTR_PROT_MASK;

	return TEE_SUCCESS;
}

TEE_Result vm_set_prot(struct user_mode_ctx *uctx, vaddr_t va, size_t len,
		       uint32_t prot)
{
	TEE_Result res = TEE_SUCCESS;
	struct vm_region *r0 = NULL;
	struct vm_region *r = NULL;
	bool was_writeable = false;
	bool need_sync = false;

	assert(thread_get_tsd()->ctx == uctx->ts_ctx);

	if (prot & ~TEE_MATTR_PROT_MASK || !len)
		return TEE_ERROR_BAD_PARAMETERS;

	res = split_vm_range(uctx, va, len, NULL, &r0);
	if (res)
		return res;

	for (r = r0; r; r = TAILQ_NEXT(r, link)) {
		if (r->va + r->size > va + len)
			break;
		if (r->attr & (TEE_MATTR_UW | TEE_MATTR_PW))
			was_writeable = true;

		r->attr &= ~TEE_MATTR_PROT_MASK;
		r->attr |= prot;

		if (!mobj_is_paged(r->mobj)) {
			need_sync = true;
			set_um_region(uctx, r);
			/*
			 * Normally when set_um_region() is called we
			 * change from no mapping to some mapping, but in
			 * this case we change the permissions on an
			 * already present mapping so some TLB invalidation
			 * is needed. We also depend on the dsb() performed
			 * as part of the TLB invalidation.
			 */
			tlbi_va_range_asid(r->va, r->size, SMALL_PAGE_SIZE,
					   uctx->vm_info.asid);
		}
	}

	for (r = r0; r; r = TAILQ_NEXT(r, link)) {
		if (r->va + r->size > va + len)
			break;
		if (mobj_is_paged(r->mobj)) {
			if (!tee_pager_set_um_region_attr(uctx, r->va, r->size,
							  prot))
				panic();
		} else if (was_writeable) {
			cache_op_inner(DCACHE_AREA_CLEAN, (void *)r->va,
				       r->size);
		}

	}
	if (need_sync && was_writeable)
		cache_op_inner(ICACHE_INVALIDATE, NULL, 0);

	merge_vm_range(uctx, va, len);

	return TEE_SUCCESS;
}

static void umap_remove_region(struct vm_info *vmi, struct vm_region *reg)
{
	TAILQ_REMOVE(&vmi->regions, reg, link);
	mobj_put(reg->mobj);
	free(reg);
}

TEE_Result vm_unmap(struct user_mode_ctx *uctx, vaddr_t va, size_t len)
{
	TEE_Result res = TEE_SUCCESS;
	struct vm_region *r = NULL;
	struct vm_region *r_next = NULL;
	size_t end_va = 0;
	size_t unmap_end_va = 0;
	size_t l = 0;

	assert(thread_get_tsd()->ctx == uctx->ts_ctx);

	if (ROUNDUP_OVERFLOW(len, SMALL_PAGE_SIZE, &l))
		return TEE_ERROR_BAD_PARAMETERS;

	if (!l || (va & SMALL_PAGE_MASK))
		return TEE_ERROR_BAD_PARAMETERS;

	if (ADD_OVERFLOW(va, l, &end_va))
		return TEE_ERROR_BAD_PARAMETERS;

	res = split_vm_range(uctx, va, l, NULL, &r);
	if (res)
		return res;

	while (true) {
		r_next = TAILQ_NEXT(r, link);
		unmap_end_va = r->va + r->size;
		rem_um_region(uctx, r);
		umap_remove_region(&uctx->vm_info, r);
		if (!r_next || unmap_end_va == end_va)
			break;
		r = r_next;
	}

	return TEE_SUCCESS;
}

static TEE_Result map_kinit(struct user_mode_ctx *uctx)
{
	TEE_Result res = TEE_SUCCESS;
	struct mobj *mobj = NULL;
	size_t offs = 0;
	vaddr_t va = 0;
	size_t sz = 0;
	uint32_t prot = 0;

	thread_get_user_kcode(&mobj, &offs, &va, &sz);
	if (sz) {
		prot = TEE_MATTR_PRX;
		if (IS_ENABLED(CFG_CORE_BTI))
			prot |= TEE_MATTR_GUARDED;
		res = vm_map(uctx, &va, sz, prot, VM_FLAG_PERMANENT,
			     mobj, offs);
		if (res)
			return res;
	}

	thread_get_user_kdata(&mobj, &offs, &va, &sz);
	if (sz)
		return vm_map(uctx, &va, sz, TEE_MATTR_PRW, VM_FLAG_PERMANENT,
			      mobj, offs);

	return TEE_SUCCESS;
}

TEE_Result vm_info_init(struct user_mode_ctx *uctx, struct ts_ctx *ts_ctx)
{
	TEE_Result res;
	uint32_t asid = asid_alloc();

	if (!asid) {
		DMSG("Failed to allocate ASID");
		return TEE_ERROR_GENERIC;
	}

	memset(uctx, 0, sizeof(*uctx));
	TAILQ_INIT(&uctx->vm_info.regions);
	SLIST_INIT(&uctx->pgt_cache);
	uctx->vm_info.asid = asid;
	uctx->ts_ctx = ts_ctx;

	res = map_kinit(uctx);
	if (res)
		vm_info_final(uctx);
	return res;
}

void vm_clean_param(struct user_mode_ctx *uctx)
{
	struct vm_region *next_r;
	struct vm_region *r;

	TAILQ_FOREACH_SAFE(r, &uctx->vm_info.regions, link, next_r) {
		if (r->flags & VM_FLAG_EPHEMERAL) {
			rem_um_region(uctx, r);
			umap_remove_region(&uctx->vm_info, r);
		}
	}
}

static void check_param_map_empty(struct user_mode_ctx *uctx __maybe_unused)
{
	struct vm_region *r = NULL;

	TAILQ_FOREACH(r, &uctx->vm_info.regions, link)
		assert(!(r->flags & VM_FLAG_EPHEMERAL));
}

static TEE_Result param_mem_to_user_va(struct user_mode_ctx *uctx,
				       struct param_mem *mem, void **user_va)
{
	struct vm_region *region = NULL;

	TAILQ_FOREACH(region, &uctx->vm_info.regions, link) {
		vaddr_t va = 0;
		size_t phys_offs = 0;

		if (!(region->flags & VM_FLAG_EPHEMERAL))
			continue;
		if (mem->mobj != region->mobj)
			continue;

		phys_offs = mobj_get_phys_offs(mem->mobj,
					       CORE_MMU_USER_PARAM_SIZE);
		phys_offs += mem->offs;
		if (phys_offs < region->offset)
			continue;
		if (phys_offs >= (region->offset + region->size))
			continue;
		va = region->va + phys_offs - region->offset;
		*user_va = (void *)va;
		return TEE_SUCCESS;
	}
	return TEE_ERROR_GENERIC;
}

static int cmp_param_mem(const void *a0, const void *a1)
{
	const struct param_mem *m1 = a1;
	const struct param_mem *m0 = a0;
	int ret;

	/* Make sure that invalid param_mem are placed last in the array */
	if (!m0->mobj && !m1->mobj)
		return 0;
	if (!m0->mobj)
		return 1;
	if (!m1->mobj)
		return -1;

	ret = CMP_TRILEAN(mobj_is_secure(m0->mobj), mobj_is_secure(m1->mobj));
	if (ret)
		return ret;

	ret = CMP_TRILEAN((vaddr_t)m0->mobj, (vaddr_t)m1->mobj);
	if (ret)
		return ret;

	ret = CMP_TRILEAN(m0->offs, m1->offs);
	if (ret)
		return ret;

	return CMP_TRILEAN(m0->size, m1->size);
}

TEE_Result vm_map_param(struct user_mode_ctx *uctx, struct tee_ta_param *param,
			void *param_va[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_SUCCESS;
	size_t n;
	size_t m;
	struct param_mem mem[TEE_NUM_PARAMS];

	memset(mem, 0, sizeof(mem));
	for (n = 0; n < TEE_NUM_PARAMS; n++) {
		uint32_t param_type = TEE_PARAM_TYPE_GET(param->types, n);
		size_t phys_offs;

		if (param_type != TEE_PARAM_TYPE_MEMREF_INPUT &&
		    param_type != TEE_PARAM_TYPE_MEMREF_OUTPUT &&
		    param_type != TEE_PARAM_TYPE_MEMREF_INOUT)
			continue;
		phys_offs = mobj_get_phys_offs(param->u[n].mem.mobj,
					       CORE_MMU_USER_PARAM_SIZE);
		mem[n].mobj = param->u[n].mem.mobj;
		mem[n].offs = ROUNDDOWN(phys_offs + param->u[n].mem.offs,
					CORE_MMU_USER_PARAM_SIZE);
		mem[n].size = ROUNDUP(phys_offs + param->u[n].mem.offs -
				      mem[n].offs + param->u[n].mem.size,
				      CORE_MMU_USER_PARAM_SIZE);
		/*
		 * For size 0 (raw pointer parameter), add minimum size
		 * value to allow address to be mapped
		 */
		if (!mem[n].size)
			mem[n].size = CORE_MMU_USER_PARAM_SIZE;
	}

	/*
	 * Sort arguments so NULL mobj is last, secure mobjs first, then by
	 * mobj pointer value since those entries can't be merged either,
	 * finally by offset.
	 *
	 * This should result in a list where all mergeable entries are
	 * next to each other and unused/invalid entries are at the end.
	 */
	qsort(mem, TEE_NUM_PARAMS, sizeof(struct param_mem), cmp_param_mem);

	for (n = 1, m = 0; n < TEE_NUM_PARAMS && mem[n].mobj; n++) {
		if (mem[n].mobj == mem[m].mobj &&
		    (mem[n].offs == (mem[m].offs + mem[m].size) ||
		     core_is_buffer_intersect(mem[m].offs, mem[m].size,
					      mem[n].offs, mem[n].size))) {
			mem[m].size = mem[n].offs + mem[n].size - mem[m].offs;
			continue;
		}
		m++;
		if (n != m)
			mem[m] = mem[n];
	}
	/*
	 * We'd like 'm' to be the number of valid entries. Here 'm' is the
	 * index of the last valid entry if the first entry is valid, else
	 * 0.
	 */
	if (mem[0].mobj)
		m++;

	check_param_map_empty(uctx);

	for (n = 0; n < m; n++) {
		vaddr_t va = 0;

		res = vm_map(uctx, &va, mem[n].size,
			     TEE_MATTR_PRW | TEE_MATTR_URW,
			     VM_FLAG_EPHEMERAL | VM_FLAG_SHAREABLE,
			     mem[n].mobj, mem[n].offs);
		if (res)
			goto out;
	}

	for (n = 0; n < TEE_NUM_PARAMS; n++) {
		uint32_t param_type = TEE_PARAM_TYPE_GET(param->types, n);

		if (param_type != TEE_PARAM_TYPE_MEMREF_INPUT &&
		    param_type != TEE_PARAM_TYPE_MEMREF_OUTPUT &&
		    param_type != TEE_PARAM_TYPE_MEMREF_INOUT)
			continue;
		if (!param->u[n].mem.mobj)
			continue;

		res = param_mem_to_user_va(uctx, &param->u[n].mem,
					   param_va + n);
		if (res != TEE_SUCCESS)
			goto out;
	}

	res = alloc_pgt(uctx);
out:
	if (res)
		vm_clean_param(uctx);

	return res;
}

void vm_info_final(struct user_mode_ctx *uctx)
{
	if (!uctx->vm_info.asid)
		return;

	pgt_flush(uctx);
	tee_pager_rem_um_regions(uctx);

	/* clear MMU entries to avoid clash when asid is reused */
	tlbi_asid(uctx->vm_info.asid);

	asid_free(uctx->vm_info.asid);
	uctx->vm_info.asid = 0;

	while (!TAILQ_EMPTY(&uctx->vm_info.regions))
		umap_remove_region(&uctx->vm_info,
				   TAILQ_FIRST(&uctx->vm_info.regions));
}

/* return true only if buffer fits inside TA private memory */
bool vm_buf_is_inside_um_private(const struct user_mode_ctx *uctx,
				 const void *va, size_t size)
{
	struct vm_region *r = NULL;

	TAILQ_FOREACH(r, &uctx->vm_info.regions, link) {
		if (r->flags & VM_FLAGS_NONPRIV)
			continue;
		if (core_is_buffer_inside((vaddr_t)va, size, r->va, r->size))
			return true;
	}

	return false;
}

/* return true only if buffer intersects TA private memory */
bool vm_buf_intersects_um_private(const struct user_mode_ctx *uctx,
				  const void *va, size_t size)
{
	struct vm_region *r = NULL;

	TAILQ_FOREACH(r, &uctx->vm_info.regions, link) {
		if (r->attr & VM_FLAGS_NONPRIV)
			continue;
		if (core_is_buffer_intersect((vaddr_t)va, size, r->va, r->size))
			return true;
	}

	return false;
}

TEE_Result vm_buf_to_mboj_offs(const struct user_mode_ctx *uctx,
			       const void *va, size_t size,
			       struct mobj **mobj, size_t *offs)
{
	struct vm_region *r = NULL;

	TAILQ_FOREACH(r, &uctx->vm_info.regions, link) {
		if (!r->mobj)
			continue;
		if (core_is_buffer_inside((vaddr_t)va, size, r->va, r->size)) {
			size_t poffs;

			poffs = mobj_get_phys_offs(r->mobj,
						   CORE_MMU_USER_PARAM_SIZE);
			*mobj = r->mobj;
			*offs = (vaddr_t)va - r->va + r->offset - poffs;
			return TEE_SUCCESS;
		}
	}

	return TEE_ERROR_BAD_PARAMETERS;
}

static TEE_Result tee_mmu_user_va2pa_attr(const struct user_mode_ctx *uctx,
					  void *ua, paddr_t *pa, uint32_t *attr)
{
	struct vm_region *region = NULL;

	TAILQ_FOREACH(region, &uctx->vm_info.regions, link) {
		if (!core_is_buffer_inside((vaddr_t)ua, 1, region->va,
					   region->size))
			continue;

		if (pa) {
			TEE_Result res;
			paddr_t p;
			size_t offset;
			size_t granule;

			/*
			 * mobj and input user address may each include
			 * a specific offset-in-granule position.
			 * Drop both to get target physical page base
			 * address then apply only user address
			 * offset-in-granule.
			 * Mapping lowest granule is the small page.
			 */
			granule = MAX(region->mobj->phys_granule,
				      (size_t)SMALL_PAGE_SIZE);
			assert(!granule || IS_POWER_OF_TWO(granule));

			offset = region->offset +
				 ROUNDDOWN((vaddr_t)ua - region->va, granule);

			res = mobj_get_pa(region->mobj, offset, granule, &p);
			if (res != TEE_SUCCESS)
				return res;

			*pa = p | ((vaddr_t)ua & (granule - 1));
		}
		if (attr)
			*attr = region->attr;

		return TEE_SUCCESS;
	}

	return TEE_ERROR_ACCESS_DENIED;
}

TEE_Result vm_va2pa(const struct user_mode_ctx *uctx, void *ua, paddr_t *pa)
{
	return tee_mmu_user_va2pa_attr(uctx, ua, pa, NULL);
}

void *vm_pa2va(const struct user_mode_ctx *uctx, paddr_t pa, size_t pa_size)
{
	paddr_t p = 0;
	struct vm_region *region = NULL;

	TAILQ_FOREACH(region, &uctx->vm_info.regions, link) {
		size_t granule = 0;
		size_t size = 0;
		size_t ofs = 0;

		/* pa2va is expected only for memory tracked through mobj */
		if (!region->mobj)
			continue;

		/* Physically granulated memory object must be scanned */
		granule = region->mobj->phys_granule;
		assert(!granule || IS_POWER_OF_TWO(granule));

		for (ofs = region->offset; ofs < region->size; ofs += size) {

			if (granule) {
				/* From current offset to buffer/granule end */
				size = granule - (ofs & (granule - 1));

				if (size > (region->size - ofs))
					size = region->size - ofs;
			} else {
				size = region->size;
			}

			if (mobj_get_pa(region->mobj, ofs, granule, &p))
				continue;

			if (core_is_buffer_inside(pa, pa_size, p, size)) {
				/* Remove region offset (mobj phys offset) */
				ofs -= region->offset;
				/* Get offset-in-granule */
				p = pa - p;

				return (void *)(region->va + ofs + (vaddr_t)p);
			}
		}
	}

	return NULL;
}

TEE_Result vm_check_access_rights(const struct user_mode_ctx *uctx,
				  uint32_t flags, uaddr_t uaddr, size_t len)
{
	uaddr_t a = 0;
	uaddr_t end_addr = 0;
	size_t addr_incr = MIN(CORE_MMU_USER_CODE_SIZE,
			       CORE_MMU_USER_PARAM_SIZE);

	if (ADD_OVERFLOW(uaddr, len, &end_addr))
		return TEE_ERROR_ACCESS_DENIED;

	if ((flags & TEE_MEMORY_ACCESS_NONSECURE) &&
	    (flags & TEE_MEMORY_ACCESS_SECURE))
		return TEE_ERROR_ACCESS_DENIED;

	/*
	 * Rely on TA private memory test to check if address range is private
	 * to TA or not.
	 */
	if (!(flags & TEE_MEMORY_ACCESS_ANY_OWNER) &&
	   !vm_buf_is_inside_um_private(uctx, (void *)uaddr, len))
		return TEE_ERROR_ACCESS_DENIED;

	for (a = ROUNDDOWN(uaddr, addr_incr); a < end_addr; a += addr_incr) {
		uint32_t attr;
		TEE_Result res;

		res = tee_mmu_user_va2pa_attr(uctx, (void *)a, NULL, &attr);
		if (res != TEE_SUCCESS)
			return res;

		if ((flags & TEE_MEMORY_ACCESS_NONSECURE) &&
		    (attr & TEE_MATTR_SECURE))
			return TEE_ERROR_ACCESS_DENIED;

		if ((flags & TEE_MEMORY_ACCESS_SECURE) &&
		    !(attr & TEE_MATTR_SECURE))
			return TEE_ERROR_ACCESS_DENIED;

		if ((flags & TEE_MEMORY_ACCESS_WRITE) && !(attr & TEE_MATTR_UW))
			return TEE_ERROR_ACCESS_DENIED;
		if ((flags & TEE_MEMORY_ACCESS_READ) && !(attr & TEE_MATTR_UR))
			return TEE_ERROR_ACCESS_DENIED;
	}

	return TEE_SUCCESS;
}

void vm_set_ctx(struct ts_ctx *ctx)
{
	struct thread_specific_data *tsd = thread_get_tsd();
	struct user_mode_ctx *uctx = NULL;

	core_mmu_set_user_map(NULL);

	if (is_user_mode_ctx(tsd->ctx)) {
		/*
		 * We're coming from a user mode context so we must make
		 * the pgts available for reuse.
		 */
		uctx = to_user_mode_ctx(tsd->ctx);
		pgt_put_all(uctx);
	}

	if (is_user_mode_ctx(ctx)) {
		struct core_mmu_user_map map = { };

		uctx = to_user_mode_ctx(ctx);
		core_mmu_create_user_map(uctx, &map);
		core_mmu_set_user_map(&map);
		tee_pager_assign_um_tables(uctx);
	}
	tsd->ctx = ctx;
}

struct mobj *vm_get_mobj(struct user_mode_ctx *uctx, vaddr_t va, size_t *len,
			 uint16_t *prot, size_t *offs)
{
	struct vm_region *r = NULL;
	size_t r_offs = 0;

	if (!len || ((*len | va) & SMALL_PAGE_MASK))
		return NULL;

	r = find_vm_region(&uctx->vm_info, va);
	if (!r)
		return NULL;

	r_offs = va - r->va;

	*len = MIN(r->size - r_offs, *len);
	*offs = r->offset + r_offs;
	*prot = r->attr & TEE_MATTR_PROT_MASK;
	return mobj_get(r->mobj);
}
