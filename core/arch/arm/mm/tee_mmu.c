// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#include <arm.h>
#include <assert.h>
#include <kernel/panic.h>
#include <kernel/spinlock.h>
#include <kernel/virtualization.h>
#include <kernel/tee_common.h>
#include <kernel/tee_misc.h>
#include <kernel/tlb_helpers.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <mm/mobj.h>
#include <mm/pgt_cache.h>
#include <mm/tee_mm.h>
#include <mm/tee_mmu.h>
#include <mm/tee_mmu_types.h>
#include <mm/tee_pager.h>
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
				  size_t pad_begin, size_t pad_end)
{
	const uint32_t f = VM_FLAG_EPHEMERAL | VM_FLAG_PERMANENT |
			    VM_FLAG_SHAREABLE;
	vaddr_t begin_va = 0;
	vaddr_t end_va = 0;
	size_t granul = 0;
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

	granul = SMALL_PAGE_SIZE;
#ifndef CFG_WITH_LPAE
	if ((prev_reg->attr & TEE_MATTR_SECURE) !=
	    (reg->attr & TEE_MATTR_SECURE))
		granul = CORE_MMU_PGDIR_SIZE;
#endif
	begin_va = ROUNDUP(prev_reg->va + prev_reg->size + pad_begin + pad,
			   granul);
	if (reg->va) {
		if (reg->va < begin_va)
			return 0;
		begin_va = reg->va;
	}

	if (next_reg->flags && (next_reg->flags & f) != (reg->flags & f))
		pad = SMALL_PAGE_SIZE;
	else
		pad = 0;

	granul = SMALL_PAGE_SIZE;
#ifndef CFG_WITH_LPAE
	if ((next_reg->attr & TEE_MATTR_SECURE) !=
	    (reg->attr & TEE_MATTR_SECURE))
		granul = CORE_MMU_PGDIR_SIZE;
#endif
	end_va = ROUNDUP(begin_va + reg->size + pad_end + pad, granul);

	if (end_va <= next_reg->va) {
		assert(!reg->va || reg->va == begin_va);
		return begin_va;
	}

	return 0;
}

static size_t get_num_req_pgts(struct user_ta_ctx *utc, vaddr_t *begin,
			       vaddr_t *end)
{
	vaddr_t b;
	vaddr_t e;

	if (TAILQ_EMPTY(&utc->vm_info->regions)) {
		core_mmu_get_user_va_range(&b, NULL);
		e = b;
	} else {
		struct vm_region *r;

		b = TAILQ_FIRST(&utc->vm_info->regions)->va;
		r = TAILQ_LAST(&utc->vm_info->regions, vm_region_head);
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

static TEE_Result alloc_pgt(struct user_ta_ctx *utc)
{
	struct thread_specific_data *tsd __maybe_unused;
	vaddr_t b;
	vaddr_t e;
	size_t ntbl;

	ntbl = get_num_req_pgts(utc, &b, &e);
	if (!pgt_check_avail(ntbl)) {
		EMSG("%zu page tables not available", ntbl);
		return TEE_ERROR_OUT_OF_MEMORY;
	}

#ifdef CFG_PAGED_USER_TA
	tsd = thread_get_tsd();
	if (&utc->ctx == tsd->ctx) {
		/*
		 * The supplied utc is the current active utc, allocate the
		 * page tables too as the pager needs to use them soon.
		 */
		pgt_alloc(&tsd->pgt_cache, &utc->ctx, b, e - 1);
	}
#endif

	return TEE_SUCCESS;
}

static void maybe_free_pgt(struct user_ta_ctx *utc, struct vm_region *r)
{
	struct thread_specific_data *tsd = NULL;
	struct pgt_cache *pgt_cache = NULL;
	vaddr_t begin = ROUNDDOWN(r->va, CORE_MMU_PGDIR_SIZE);
	vaddr_t last = ROUNDUP(r->va + r->size, CORE_MMU_PGDIR_SIZE);
	struct vm_region *r2 = NULL;

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

	tsd = thread_get_tsd();
	if (&utc->ctx == tsd->ctx)
		pgt_cache = &tsd->pgt_cache;

	pgt_flush_ctx_range(pgt_cache, &utc->ctx, r->va, r->va + r->size);
}

static TEE_Result umap_add_region(struct vm_info *vmi, struct vm_region *reg,
				  size_t pad_begin, size_t pad_end)
{
	struct vm_region dummy_first_reg = { };
	struct vm_region dummy_last_reg = { };
	struct vm_region *r = NULL;
	struct vm_region *prev_r = NULL;
	vaddr_t va_range_base = 0;
	size_t va_range_size = 0;
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

	prev_r = &dummy_first_reg;
	TAILQ_FOREACH(r, &vmi->regions, link) {
		va = select_va_in_range(prev_r, r, reg, pad_begin, pad_end);
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
	va = select_va_in_range(r, &dummy_last_reg, reg, pad_begin, pad_end);
	if (va) {
		reg->va = va;
		TAILQ_INSERT_TAIL(&vmi->regions, reg, link);
		return TEE_SUCCESS;
	}

	return TEE_ERROR_ACCESS_CONFLICT;
}

TEE_Result vm_map_pad(struct user_ta_ctx *utc, vaddr_t *va, size_t len,
		      uint32_t prot, uint32_t flags, struct mobj *mobj,
		      size_t offs, size_t pad_begin, size_t pad_end)
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

	res = umap_add_region(utc->vm_info, reg, pad_begin, pad_end);
	if (res)
		goto err_free_reg;

	res = alloc_pgt(utc);
	if (res)
		goto err_rem_reg;

	if (mobj_is_paged(mobj)) {
		struct fobj *fobj = mobj_get_fobj(mobj);

		if (!fobj) {
			res = TEE_ERROR_GENERIC;
			goto err_rem_reg;
		}

		res = tee_pager_add_uta_area(utc, reg->va, fobj, prot);
		fobj_put(fobj);
		if (res)
			goto err_rem_reg;
	}

	/*
	 * If the context currently is active set it again to update
	 * the mapping.
	 */
	if (thread_get_tsd()->ctx == &utc->ctx)
		tee_mmu_set_ctx(&utc->ctx);

	*va = reg->va;

	return TEE_SUCCESS;

err_rem_reg:
	TAILQ_REMOVE(&utc->vm_info->regions, reg, link);
err_free_reg:
	mobj_put(reg->mobj);
	free(reg);
	return res;
}

static TEE_Result find_exact_vm_region(struct user_ta_ctx *utc, vaddr_t va,
				       size_t len, struct vm_region **r_ret)
{
	struct vm_region *r = NULL;

	TAILQ_FOREACH(r, &utc->vm_info->regions, link) {
		if (core_is_buffer_intersect(r->va, r->size, va, len)) {
			if (r->va != va || r->size != len)
				return TEE_ERROR_BAD_PARAMETERS;

			*r_ret = r;
			return TEE_SUCCESS;
		}
	}

	return TEE_ERROR_ITEM_NOT_FOUND;
}

TEE_Result vm_remap(struct user_ta_ctx *utc, vaddr_t *new_va, vaddr_t old_va,
		    size_t len, size_t pad_begin, size_t pad_end)
{
	TEE_Result res = TEE_SUCCESS;
	struct vm_region *r = NULL;
	struct fobj *fobj = NULL;

	assert(thread_get_tsd()->ctx == &utc->ctx);

	res = find_exact_vm_region(utc, old_va, len, &r);
	if (res)
		return res;

	if (mobj_is_paged(r->mobj)) {
		fobj = mobj_get_fobj(r->mobj);
		if (!fobj)
			return TEE_ERROR_GENERIC;
		tee_pager_rem_uta_region(utc, r->va, r->size);
	}
	maybe_free_pgt(utc, r);

	TAILQ_REMOVE(&utc->vm_info->regions, r, link);

	/*
	 * Synchronize change to translation tables. Even though the pager
	 * case unmaps immediately we may still free a translation table.
	 */
	tee_mmu_set_ctx(&utc->ctx);

	r->va = *new_va;
	res = umap_add_region(utc->vm_info, r, pad_begin, pad_end);
	if (res)
		goto err_restore_map;

	res = alloc_pgt(utc);
	if (res)
		goto err_restore_map_rem_reg;

	if (fobj) {
		res = tee_pager_add_uta_area(utc, r->va, fobj, r->attr);
		if (res)
			goto err_restore_map_rem_reg;
		fobj_put(fobj);
	}

	tee_mmu_set_ctx(&utc->ctx);
	*new_va = r->va;

	return TEE_SUCCESS;

err_restore_map_rem_reg:
	TAILQ_REMOVE(&utc->vm_info->regions, r, link);
err_restore_map:
	r->va = old_va;
	if (umap_add_region(utc->vm_info, r, 0, 0))
		panic("Cannot restore mapping");
	if (alloc_pgt(utc))
		panic("Cannot restore mapping");
	if (fobj) {
		if (tee_pager_add_uta_area(utc, r->va, fobj, r->attr))
			panic("Cannot restore mapping");
		fobj_put(fobj);
	}

	tee_mmu_set_ctx(&utc->ctx);

	return res;
}

TEE_Result vm_get_flags(struct user_ta_ctx *utc, vaddr_t va, size_t len,
			uint32_t *flags)
{
	TEE_Result res = TEE_SUCCESS;
	struct vm_region *r = NULL;

	res = find_exact_vm_region(utc, va, len, &r);
	if (!res)
		*flags = r->flags;

	return res;
}

TEE_Result vm_set_prot(struct user_ta_ctx *utc, vaddr_t va, size_t len,
		       uint32_t prot)
{
	TEE_Result res = TEE_SUCCESS;
	struct vm_region *r = NULL;
	bool was_writeable = false;

	assert(thread_get_tsd()->ctx == &utc->ctx);

	if (prot & ~TEE_MATTR_PROT_MASK)
		return TEE_ERROR_BAD_PARAMETERS;

	/*
	 * To keep thing simple: specified va and len have to match exactly
	 * with an already registered region.
	 */
	res = find_exact_vm_region(utc, va, len, &r);
	if (res)
		return res;

	if ((r->attr & TEE_MATTR_PROT_MASK) == prot)
		return TEE_SUCCESS;

	was_writeable = r->attr & (TEE_MATTR_UW | TEE_MATTR_PW);

	r->attr &= ~TEE_MATTR_PROT_MASK;
	r->attr |= prot;

	if (mobj_is_paged(r->mobj)) {
		if (!tee_pager_set_uta_area_attr(utc, va, len,
						 prot))
			return TEE_ERROR_GENERIC;
	} else if ((prot & TEE_MATTR_UX) && was_writeable) {
		/* Synchronize changes to translation tables */
		tee_mmu_set_ctx(&utc->ctx);

		cache_op_inner(DCACHE_AREA_CLEAN,
			       (void *)va, len);
		cache_op_inner(ICACHE_INVALIDATE, NULL, 0);
	}

	return TEE_SUCCESS;
}

static void umap_remove_region(struct vm_info *vmi, struct vm_region *reg)
{
	TAILQ_REMOVE(&vmi->regions, reg, link);
	mobj_put(reg->mobj);
	free(reg);
}

TEE_Result vm_unmap(struct user_ta_ctx *utc, vaddr_t va, size_t len)
{
	TEE_Result res = TEE_SUCCESS;
	struct vm_region *r = NULL;

	assert(thread_get_tsd()->ctx == &utc->ctx);

	/*
	 * To keep thing simple: specified va and len has to match exactly
	 * with an already registered region.
	 */
	res = find_exact_vm_region(utc, va, ROUNDUP(len, SMALL_PAGE_SIZE), &r);
	if (res)
		return res;

	if (mobj_is_paged(r->mobj))
		tee_pager_rem_uta_region(utc, r->va, r->size);
	maybe_free_pgt(utc, r);
	umap_remove_region(utc->vm_info, r);

	/*
	 * Synchronize change to translation tables. Even though the pager
	 * case unmaps immediately we may still free a translation table.
	 */
	tee_mmu_set_ctx(&utc->ctx);

	return TEE_SUCCESS;
}

static TEE_Result map_kinit(struct user_ta_ctx *utc __maybe_unused)
{
	TEE_Result res;
	struct mobj *mobj;
	size_t offs;
	vaddr_t va;
	size_t sz;

	thread_get_user_kcode(&mobj, &offs, &va, &sz);
	if (sz) {
		res = vm_map(utc, &va, sz, TEE_MATTR_PRX, VM_FLAG_PERMANENT,
			     mobj, offs);
		if (res)
			return res;
	}

	thread_get_user_kdata(&mobj, &offs, &va, &sz);
	if (sz)
		return vm_map(utc, &va, sz, TEE_MATTR_PRW, VM_FLAG_PERMANENT,
			      mobj, offs);

	return TEE_SUCCESS;
}

TEE_Result vm_info_init(struct user_ta_ctx *utc)
{
	TEE_Result res;
	uint32_t asid = asid_alloc();

	if (!asid) {
		DMSG("Failed to allocate ASID");
		return TEE_ERROR_GENERIC;
	}

	utc->vm_info = calloc(1, sizeof(*utc->vm_info));
	if (!utc->vm_info) {
		asid_free(asid);
		return TEE_ERROR_OUT_OF_MEMORY;
	}
	TAILQ_INIT(&utc->vm_info->regions);
	utc->vm_info->asid = asid;

	res = map_kinit(utc);
	if (res)
		vm_info_final(utc);
	return res;
}

void tee_mmu_clean_param(struct user_ta_ctx *utc)
{
	struct vm_region *next_r;
	struct vm_region *r;

	TAILQ_FOREACH_SAFE(r, &utc->vm_info->regions, link, next_r) {
		if (r->flags & VM_FLAG_EPHEMERAL) {
			if (mobj_is_paged(r->mobj))
				tee_pager_rem_uta_region(utc, r->va, r->size);
			maybe_free_pgt(utc, r);
			umap_remove_region(utc->vm_info, r);
		}
	}
}

static void check_param_map_empty(struct user_ta_ctx *utc __maybe_unused)
{
	struct vm_region *r = NULL;

	TAILQ_FOREACH(r, &utc->vm_info->regions, link)
		assert(!(r->flags & VM_FLAG_EPHEMERAL));
}

static TEE_Result param_mem_to_user_va(struct user_ta_ctx *utc,
				       struct param_mem *mem, void **user_va)
{
	struct vm_region *region;

	TAILQ_FOREACH(region, &utc->vm_info->regions, link) {
		vaddr_t va;
		size_t phys_offs;

		if (!(region->flags & VM_FLAG_EPHEMERAL))
			continue;
		if (mem->mobj != region->mobj)
			continue;
		if (mem->offs < region->offset)
			continue;
		if (mem->offs >= (region->offset + region->size))
			continue;
		phys_offs = mobj_get_phys_offs(mem->mobj,
					       CORE_MMU_USER_PARAM_SIZE);
		va = region->va + mem->offs + phys_offs - region->offset;
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
	if (!m0->size && !m1->size)
		return 0;
	if (!m0->size)
		return 1;
	if (!m1->size)
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

TEE_Result tee_mmu_map_param(struct user_ta_ctx *utc,
		struct tee_ta_param *param, void *param_va[TEE_NUM_PARAMS])
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
	}

	/*
	 * Sort arguments so size = 0 is last, secure mobjs first, then by
	 * mobj pointer value since those entries can't be merged either,
	 * finally by offset.
	 *
	 * This should result in a list where all mergeable entries are
	 * next to each other and unused/invalid entries are at the end.
	 */
	qsort(mem, TEE_NUM_PARAMS, sizeof(struct param_mem), cmp_param_mem);

	for (n = 1, m = 0; n < TEE_NUM_PARAMS && mem[n].size; n++) {
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
	if (mem[0].size)
		m++;

	check_param_map_empty(utc);

	for (n = 0; n < m; n++) {
		vaddr_t va = 0;

		res = vm_map(utc, &va, mem[n].size,
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
		if (param->u[n].mem.size == 0)
			continue;

		res = param_mem_to_user_va(utc, &param->u[n].mem, param_va + n);
		if (res != TEE_SUCCESS)
			goto out;
	}

	res = alloc_pgt(utc);
out:
	if (res)
		tee_mmu_clean_param(utc);

	return res;
}

TEE_Result tee_mmu_add_rwmem(struct user_ta_ctx *utc, struct mobj *mobj,
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

	res = umap_add_region(utc->vm_info, reg, 0, 0);
	if (res) {
		free(reg);
		return res;
	}

	res = alloc_pgt(utc);
	if (res)
		umap_remove_region(utc->vm_info, reg);
	else
		*va = reg->va;

	return res;
}

void tee_mmu_rem_rwmem(struct user_ta_ctx *utc, struct mobj *mobj, vaddr_t va)
{
	struct vm_region *r;

	TAILQ_FOREACH(r, &utc->vm_info->regions, link) {
		if (r->mobj == mobj && r->va == va) {
			if (mobj_is_paged(r->mobj))
				tee_pager_rem_uta_region(utc, r->va, r->size);
			maybe_free_pgt(utc, r);
			umap_remove_region(utc->vm_info, r);
			return;
		}
	}
}

void vm_info_final(struct user_ta_ctx *utc)
{
	if (!utc->vm_info)
		return;

	/* clear MMU entries to avoid clash when asid is reused */
	tlbi_asid(utc->vm_info->asid);

	asid_free(utc->vm_info->asid);
	while (!TAILQ_EMPTY(&utc->vm_info->regions))
		umap_remove_region(utc->vm_info,
				   TAILQ_FIRST(&utc->vm_info->regions));
	free(utc->vm_info);
	utc->vm_info = NULL;
}

/* return true only if buffer fits inside TA private memory */
bool tee_mmu_is_vbuf_inside_ta_private(const struct user_ta_ctx *utc,
				  const void *va, size_t size)
{
	struct vm_region *r = NULL;

	TAILQ_FOREACH(r, &utc->vm_info->regions, link) {
		if (r->flags & VM_FLAGS_NONPRIV)
			continue;
		if (core_is_buffer_inside(va, size, r->va, r->size))
			return true;
	}

	return false;
}

/* return true only if buffer intersects TA private memory */
bool tee_mmu_is_vbuf_intersect_ta_private(const struct user_ta_ctx *utc,
					  const void *va, size_t size)
{
	struct vm_region *r = NULL;

	TAILQ_FOREACH(r, &utc->vm_info->regions, link) {
		if (r->attr & VM_FLAGS_NONPRIV)
			continue;
		if (core_is_buffer_intersect(va, size, r->va, r->size))
			return true;
	}

	return false;
}

TEE_Result tee_mmu_vbuf_to_mobj_offs(const struct user_ta_ctx *utc,
				     const void *va, size_t size,
				     struct mobj **mobj, size_t *offs)
{
	struct vm_region *r;

	TAILQ_FOREACH(r, &utc->vm_info->regions, link) {
		if (!r->mobj)
			continue;
		if (core_is_buffer_inside(va, size, r->va, r->size)) {
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

static TEE_Result tee_mmu_user_va2pa_attr(const struct user_ta_ctx *utc,
			void *ua, paddr_t *pa, uint32_t *attr)
{
	struct vm_region *region;

	TAILQ_FOREACH(region, &utc->vm_info->regions, link) {
		if (!core_is_buffer_inside(ua, 1, region->va, region->size))
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

TEE_Result tee_mmu_user_va2pa_helper(const struct user_ta_ctx *utc, void *ua,
				     paddr_t *pa)
{
	return tee_mmu_user_va2pa_attr(utc, ua, pa, NULL);
}

/* */
TEE_Result tee_mmu_user_pa2va_helper(const struct user_ta_ctx *utc,
				      paddr_t pa, void **va)
{
	TEE_Result res;
	paddr_t p;
	struct vm_region *region;

	TAILQ_FOREACH(region, &utc->vm_info->regions, link) {
		size_t granule;
		size_t size;
		size_t ofs;

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
			} else
				size = region->size;

			res = mobj_get_pa(region->mobj, ofs, granule, &p);
			if (res != TEE_SUCCESS)
				return res;

			if (core_is_buffer_inside(pa, 1, p, size)) {
				/* Remove region offset (mobj phys offset) */
				ofs -= region->offset;
				/* Get offset-in-granule */
				p = pa - p;

				*va = (void *)(region->va + ofs + (vaddr_t)p);
				return TEE_SUCCESS;
			}
		}
	}

	return TEE_ERROR_ACCESS_DENIED;
}

TEE_Result tee_mmu_check_access_rights(const struct user_ta_ctx *utc,
				       uint32_t flags, uaddr_t uaddr,
				       size_t len)
{
	uaddr_t a;
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
	   !tee_mmu_is_vbuf_inside_ta_private(utc, (void *)uaddr, len))
		return TEE_ERROR_ACCESS_DENIED;

	for (a = ROUNDDOWN(uaddr, addr_incr); a < end_addr; a += addr_incr) {
		uint32_t attr;
		TEE_Result res;

		res = tee_mmu_user_va2pa_attr(utc, (void *)a, NULL, &attr);
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

void tee_mmu_set_ctx(struct tee_ta_ctx *ctx)
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

	if (is_user_ta_ctx(ctx)) {
		struct core_mmu_user_map map;
		struct user_ta_ctx *utc = to_user_ta_ctx(ctx);

		core_mmu_create_user_map(utc, &map);
		core_mmu_set_user_map(&map);
		tee_pager_assign_uta_tables(utc);
	}
	tsd->ctx = ctx;
}

struct tee_ta_ctx *tee_mmu_get_ctx(void)
{
	return thread_get_tsd()->ctx;
}

void teecore_init_ta_ram(void)
{
	vaddr_t s;
	vaddr_t e;
	paddr_t ps;
	paddr_t pe;

	/* get virtual addr/size of RAM where TA are loaded/executedNSec
	 * shared mem allcated from teecore */
#ifndef CFG_VIRTUALIZATION
	core_mmu_get_mem_by_type(MEM_AREA_TA_RAM, &s, &e);
#else
	virt_get_ta_ram(&s, &e);
#endif
	ps = virt_to_phys((void *)s);
	pe = virt_to_phys((void *)(e - 1)) + 1;

	if (!ps || (ps & CORE_MMU_USER_CODE_MASK) ||
	    !pe || (pe & CORE_MMU_USER_CODE_MASK))
		panic("invalid TA RAM");

	/* extra check: we could rely on  core_mmu_get_mem_by_type() */
	if (!tee_pbuf_is_sec(ps, pe - ps))
		panic("TA RAM is not secure");

	if (!tee_mm_is_empty(&tee_mm_sec_ddr))
		panic("TA RAM pool is not empty");

	/* remove previous config and init TA ddr memory pool */
	tee_mm_final(&tee_mm_sec_ddr);
	tee_mm_init(&tee_mm_sec_ddr, ps, pe, CORE_MMU_USER_CODE_SHIFT,
		    TEE_MM_POOL_NO_FLAGS);
}

#ifdef CFG_CORE_RESERVED_SHM
void teecore_init_pub_ram(void)
{
	vaddr_t s;
	vaddr_t e;

	/* get virtual addr/size of NSec shared mem allcated from teecore */
	core_mmu_get_mem_by_type(MEM_AREA_NSEC_SHM, &s, &e);

	if (s >= e || s & SMALL_PAGE_MASK || e & SMALL_PAGE_MASK)
		panic("invalid PUB RAM");

	/* extra check: we could rely on  core_mmu_get_mem_by_type() */
	if (!tee_vbuf_is_non_sec(s, e - s))
		panic("PUB RAM is not non-secure");

#ifdef CFG_PL310
	/* Allocate statically the l2cc mutex */
	tee_l2cc_store_mutex_boot_pa(virt_to_phys((void *)s));
	s += sizeof(uint32_t);			/* size of a pl310 mutex */
	s =  ROUNDUP(s, SMALL_PAGE_SIZE);	/* keep required alignment */
#endif

	default_nsec_shm_paddr = virt_to_phys((void *)s);
	default_nsec_shm_size = e - s;
}
#endif /*CFG_CORE_RESERVED_SHM*/

uint32_t tee_mmu_user_get_cache_attr(struct user_ta_ctx *utc, void *va)
{
	uint32_t attr;

	if (tee_mmu_user_va2pa_attr(utc, va, NULL, &attr) != TEE_SUCCESS)
		panic("cannot get attr");

	return (attr >> TEE_MATTR_CACHE_SHIFT) & TEE_MATTR_CACHE_MASK;
}
