// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016-2021, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#include <arm.h>
#include <assert.h>
#include <initcall.h>
#include <kernel/panic.h>
#include <kernel/spinlock.h>
#include <kernel/tee_common.h>
#include <kernel/tee_misc.h>
#include <kernel/tlb_helpers.h>
#include <kernel/user_mode_ctx.h>
#include <kernel/virtualization.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <mm/mobj.h>
#include <mm/pgt_cache.h>
#include <mm/tee_mm.h>
#include <mm/tee_mmu_types.h>
#include <mm/tee_pager.h>
#include <mm/vm.h>
#include <sm/optee_smc.h>
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

#define TEE_MMU_UCACHE_DEFAULT_ATTR	(TEE_MATTR_CACHE_CACHED << \
					 TEE_MATTR_CACHE_SHIFT)

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

static size_t get_num_req_pgts(struct user_mode_ctx *uctx, vaddr_t *begin,
			       vaddr_t *end)
{
	vaddr_t b;
	vaddr_t e;

	if (TAILQ_EMPTY(&uctx->vm_info.regions)) {
		core_mmu_get_user_va_range(&b, NULL);
		e = b;
	} else {
		struct vm_region *r;

		b = TAILQ_FIRST(&uctx->vm_info.regions)->va;
		r = TAILQ_LAST(&uctx->vm_info.regions, vm_region_head);
		e = r->va + r->size;
		b = ROUNDDOWN(b, CORE_MMU_PGDIR_SIZE);
		e = ROUNDUP(e, CORE_MMU_PGDIR_SIZE);
	}

	if (begin)
		*begin = b;
	if (end)
		*end = e;
	return (e - b) >> CORE_MMU_PGDIR_SHIFT;
}

static TEE_Result alloc_pgt(struct user_mode_ctx *uctx)
{
	struct thread_specific_data *tsd __maybe_unused;
	vaddr_t b;
	vaddr_t e;
	size_t ntbl;

	ntbl = get_num_req_pgts(uctx, &b, &e);
	if (!pgt_check_avail(ntbl)) {
		EMSG("%zu page tables not available", ntbl);
		return TEE_ERROR_OUT_OF_MEMORY;
	}

#ifdef CFG_PAGED_USER_TA
	tsd = thread_get_tsd();
	if (uctx->ts_ctx == tsd->ctx) {
		/*
		 * The supplied utc is the current active utc, allocate the
		 * page tables too as the pager needs to use them soon.
		 */
		pgt_alloc(&tsd->pgt_cache, uctx->ts_ctx, b, e - 1);
	}
#endif

	return TEE_SUCCESS;
}

static void rem_um_region(struct user_mode_ctx *uctx, struct vm_region *r)
{
	struct thread_specific_data *tsd = thread_get_tsd();
	struct pgt_cache *pgt_cache = NULL;
	vaddr_t begin = ROUNDDOWN(r->va, CORE_MMU_PGDIR_SIZE);
	vaddr_t last = ROUNDUP(r->va + r->size, CORE_MMU_PGDIR_SIZE);
	struct vm_region *r2 = NULL;

	if (uctx->ts_ctx == tsd->ctx)
		pgt_cache = &tsd->pgt_cache;

	if (mobj_is_paged(r->mobj)) {
		tee_pager_rem_um_region(uctx, r->va, r->size);
	} else {
		pgt_clear_ctx_range(pgt_cache, uctx->ts_ctx, r->va,
				    r->va + r->size);
		tlbi_mva_range_asid(r->va, r->size, SMALL_PAGE_SIZE,
				    uctx->vm_info.asid);
	}

	r2 = TAILQ_NEXT(r, link);
	if (r2)
		last = MIN(last, ROUNDDOWN(r2->va, CORE_MMU_PGDIR_SIZE));

	r2 = TAILQ_PREV(r, vm_region_head, link);
	if (r2)
		begin = MAX(begin,
			    ROUNDUP(r2->va + r2->size, CORE_MMU_PGDIR_SIZE));

	/* If there's no unused page tables, there's nothing left to do */
	if (begin >= last)
		return;

	pgt_flush_ctx_range(pgt_cache, uctx->ts_ctx, r->va, r->va + r->size);
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
		uint32_t cattr;

		res = mobj_get_cattr(mobj, &cattr);
		if (res)
			goto err_free_reg;
		attr |= cattr << TEE_MATTR_CACHE_SHIFT;
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
		if (!res)
			r_last = r;
		if (!res)
			res = alloc_pgt(uctx);
		if (fobj && !res)
			res = tee_pager_add_um_region(uctx, r->va, fobj,
						      r->attr);

		if (res) {
			/*
			 * Something went wrong move all the recently added
			 * regions back to regs for later reinsertion at
			 * the original spot.
			 */
			struct vm_region *r_tmp = NULL;

			if (r != r_last) {
				/*
				 * umap_add_region() failed, move r back to
				 * regs before all the rest are moved back.
				 */
				TAILQ_INSERT_HEAD(&regs, r, link);
			}
			for (r = r_first; r_last && r != r_last; r = r_next) {
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
		if (fobj && tee_pager_add_um_region(uctx, r->va, fobj, r->attr))
			panic("Cannot restore mapping");
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

		if (!mobj_is_paged(r->mobj))
			need_sync = true;

		r->attr &= ~TEE_MATTR_PROT_MASK;
		r->attr |= prot;
	}

	if (need_sync) {
		/* Synchronize changes to translation tables */
		vm_set_ctx(uctx->ts_ctx);
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
	TEE_Result res;
	struct mobj *mobj;
	size_t offs;
	vaddr_t va;
	size_t sz;

	thread_get_user_kcode(&mobj, &offs, &va, &sz);
	if (sz) {
		res = vm_map(uctx, &va, sz, TEE_MATTR_PRX, VM_FLAG_PERMANENT,
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

TEE_Result vm_info_init(struct user_mode_ctx *uctx)
{
	TEE_Result res;
	uint32_t asid = asid_alloc();

	if (!asid) {
		DMSG("Failed to allocate ASID");
		return TEE_ERROR_GENERIC;
	}

	memset(&uctx->vm_info, 0, sizeof(uctx->vm_info));
	TAILQ_INIT(&uctx->vm_info.regions);
	uctx->vm_info.asid = asid;

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

TEE_Result vm_add_rwmem(struct user_mode_ctx *uctx, struct mobj *mobj,
			vaddr_t *va)
{
	TEE_Result res;
	struct vm_region *reg = calloc(1, sizeof(*reg));

	if (!reg)
		return TEE_ERROR_OUT_OF_MEMORY;

	reg->mobj = mobj;
	reg->offset = 0;
	reg->va = 0;
	reg->size = ROUNDUP(mobj->size, SMALL_PAGE_SIZE);
	if (mobj_is_secure(mobj))
		reg->attr = TEE_MATTR_SECURE;
	else
		reg->attr = 0;

	res = umap_add_region(&uctx->vm_info, reg, 0, 0, 0);
	if (res) {
		free(reg);
		return res;
	}

	res = alloc_pgt(uctx);
	if (res)
		umap_remove_region(&uctx->vm_info, reg);
	else
		*va = reg->va;

	return res;
}

void vm_rem_rwmem(struct user_mode_ctx *uctx, struct mobj *mobj, vaddr_t va)
{
	struct vm_region *r = NULL;

	TAILQ_FOREACH(r, &uctx->vm_info.regions, link) {
		if (r->mobj == mobj && r->va == va) {
			rem_um_region(uctx, r);
			umap_remove_region(&uctx->vm_info, r);
			return;
		}
	}
}

void vm_info_final(struct user_mode_ctx *uctx)
{
	if (!uctx->vm_info.asid)
		return;

	/* clear MMU entries to avoid clash when asid is reused */
	tlbi_asid(uctx->vm_info.asid);

	asid_free(uctx->vm_info.asid);
	while (!TAILQ_EMPTY(&uctx->vm_info.regions))
		umap_remove_region(&uctx->vm_info,
				   TAILQ_FIRST(&uctx->vm_info.regions));
	memset(&uctx->vm_info, 0, sizeof(uctx->vm_info));
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

	core_mmu_set_user_map(NULL);
	/*
	 * No matter what happens below, the current user TA will not be
	 * current any longer. Make sure pager is in sync with that.
	 * This function has to be called before there's a chance that
	 * pgt_free_unlocked() is called.
	 *
	 * Save translation tables in a cache if it's a user TA.
	 */
	pgt_free(&tsd->pgt_cache, is_user_ta_ctx(tsd->ctx));

	if (is_user_mode_ctx(ctx)) {
		struct core_mmu_user_map map = { };
		struct user_mode_ctx *uctx = to_user_mode_ctx(ctx);

		core_mmu_create_user_map(uctx, &map);
		core_mmu_set_user_map(&map);
		tee_pager_assign_um_tables(uctx);
	}
	tsd->ctx = ctx;
}

