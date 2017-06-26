/*
 * Copyright (c) 2016, Linaro Limited
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

#include <arm.h>
#include <assert.h>
#include <kernel/panic.h>
#include <kernel/tlb_helpers.h>
#include <kernel/tee_common.h>
#include <kernel/tee_misc.h>
#include <mm/tee_mmu.h>
#include <mm/tee_mmu_types.h>
#include <mm/pgt_cache.h>
#include <mm/tee_mm.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <mm/mobj.h>
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

/* Support for 31 concurrent sessions */
static uint32_t g_asid = 0xffffffff;

static TEE_Result tee_mmu_umap_add_param(struct tee_mmu_info *mmu,
					 struct param_mem *mem)
{
	TEE_Result res;
	struct tee_ta_region *last_entry = NULL;
	size_t n;
	uint32_t attr = TEE_MMU_UDATA_ATTR;
	size_t nsz;
	size_t noffs;

	if (!mobj_is_paged(mem->mobj)) {
		uint32_t cattr;

		res = mobj_get_cattr(mem->mobj, &cattr);
		if (res != TEE_SUCCESS)
			return res;
		attr |= cattr << TEE_MATTR_CACHE_SHIFT;
	}

	if (!mobj_is_secure(mem->mobj))
		attr &= ~TEE_MATTR_SECURE;

	/* Check that we can map memory using this attribute */
	if (!core_mmu_mattr_is_ok(attr))
		return TEE_ERROR_BAD_PARAMETERS;

	/* Find empty entry */
	for (n = TEE_MMU_UMAP_PARAM_IDX; n < TEE_MMU_UMAP_MAX_ENTRIES; n++)
		if (!mmu->regions[n].size)
			break;

	if (n == TEE_MMU_UMAP_MAX_ENTRIES) {
		/* No entries left "can't happen" */
		return TEE_ERROR_EXCESS_DATA;
	}

	mmu->regions[n].mobj = mem->mobj;
	mmu->regions[n].offset = ROUNDDOWN(mem->offs, CORE_MMU_USER_PARAM_SIZE);
	mmu->regions[n].size = ROUNDUP(mem->offs - mmu->regions[n].offset +
				       mem->size,
				       CORE_MMU_USER_PARAM_SIZE);
	mmu->regions[n].attr = attr;

	/* Try to coalesce some entries */
	while (true) {
		/* Find last param */
		n = TEE_MMU_UMAP_MAX_ENTRIES - 1;

		while (!mmu->regions[n].size) {
			n--;
			if (n < TEE_MMU_UMAP_PARAM_IDX) {
				/* No param entries found, "can't happen" */
				return TEE_ERROR_BAD_STATE;
			}
		}

		if (last_entry == mmu->regions + n)
			return TEE_SUCCESS; /* Can't coalesc more */
		last_entry = mmu->regions + n;

		n--;
		while (n >= TEE_MMU_UMAP_PARAM_IDX) {
			struct tee_ta_region *entry = mmu->regions + n;

			n--;
			if (last_entry->mobj != entry->mobj)
				continue;

			if ((last_entry->offset + last_entry->size) ==
			    entry->offset ||
			    (entry->offset + entry->size) ==
			    last_entry->offset ||
			    core_is_buffer_intersect(last_entry->offset,
						     last_entry->size,
						     entry->offset,
						     entry->size)) {
				noffs = MIN(last_entry->offset, entry->offset);
				nsz = MAX(last_entry->offset + last_entry->size,
					  entry->offset + entry->size) - noffs;
				entry->offset = noffs;
				entry->size = nsz;
				last_entry->mobj = NULL;
				last_entry->size = 0;
				last_entry->attr = 0;
				break;
			}
		}
	}
}

static TEE_Result tee_mmu_umap_set_vas(struct tee_mmu_info *mmu)
{
	const size_t granule = CORE_MMU_USER_PARAM_SIZE;
	vaddr_t va_range_base;
	vaddr_t va;
	size_t va_range_size;
	size_t n;

	/* Find last table entry used to map code and data */
	n = TEE_MMU_UMAP_PARAM_IDX - 1;
	while (n && !mmu->regions[n].size)
		n--;
	va = mmu->regions[n].va + mmu->regions[n].size;
	assert(va);

	core_mmu_get_user_va_range(&va_range_base, &va_range_size);
	assert(va_range_base == mmu->ta_private_vmem_start);

	/*
	 * Assign parameters in secure memory.
	 */
	va = ROUNDUP(va, granule);
	for (n = TEE_MMU_UMAP_PARAM_IDX; n < TEE_MMU_UMAP_MAX_ENTRIES; n++) {
		if (!mmu->regions[n].size ||
		    !(mmu->regions[n].attr & TEE_MATTR_SECURE))
			continue;
		mmu->regions[n].va = va;
		va += mmu->regions[n].size;
		/* Put some empty space between each area */
		va += granule;
		if ((va - va_range_base) >= va_range_size)
			return TEE_ERROR_EXCESS_DATA;
	}

	/*
	 * Assign parameters in nonsecure shared memory.
	 * Note that we're making sure that they will reside in a new page
	 * directory as they are to be mapped nonsecure.
	 */
	va = ROUNDUP(va, CORE_MMU_PGDIR_SIZE);
	for (n = TEE_MMU_UMAP_PARAM_IDX; n < TEE_MMU_UMAP_MAX_ENTRIES; n++) {
		if (!mmu->regions[n].size ||
		    (mmu->regions[n].attr & TEE_MATTR_SECURE))
			continue;
		mmu->regions[n].va = va;
		va += mmu->regions[n].size;
		/* Put some empty space between each area */
		va += granule;
		if ((va - va_range_base) >= va_range_size)
			return TEE_ERROR_EXCESS_DATA;
	}

	return TEE_SUCCESS;
}

TEE_Result tee_mmu_init(struct user_ta_ctx *utc)
{
	uint32_t asid = 1;

	if (!utc->context) {
		utc->context = 1;

		/* Find available ASID */
		while (!(asid & g_asid) && (asid != 0)) {
			utc->context++;
			asid = asid << 1;
		}

		if (asid == 0) {
			DMSG("Failed to allocate ASID");
			return TEE_ERROR_GENERIC;
		}
		g_asid &= ~asid;
	}

	utc->mmu = calloc(1, sizeof(struct tee_mmu_info));
	if (!utc->mmu)
		return TEE_ERROR_OUT_OF_MEMORY;
	core_mmu_get_user_va_range(&utc->mmu->ta_private_vmem_start, NULL);
	return TEE_SUCCESS;
}

static TEE_Result alloc_pgt(struct user_ta_ctx *utc __maybe_unused,
			    vaddr_t base, vaddr_t end)
{
	struct thread_specific_data *tsd __maybe_unused;
	vaddr_t b = ROUNDDOWN(base, CORE_MMU_PGDIR_SIZE);
	vaddr_t e = ROUNDUP(end, CORE_MMU_PGDIR_SIZE);
	size_t ntbl = (e - b) >> CORE_MMU_PGDIR_SHIFT;

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

static void free_pgt(struct user_ta_ctx *utc, vaddr_t base, size_t size)
{
	struct thread_specific_data *tsd = thread_get_tsd();
	struct pgt_cache *pgt_cache = NULL;

	if (&utc->ctx == tsd->ctx)
		pgt_cache = &tsd->pgt_cache;

	pgt_flush_ctx_range(pgt_cache, &utc->ctx, base, base + size);
}

void tee_mmu_map_stack(struct user_ta_ctx *utc, struct mobj *mobj)
{
	const size_t granule = CORE_MMU_USER_CODE_SIZE;
	struct tee_ta_region *region = utc->mmu->regions +
				       TEE_MMU_UMAP_STACK_IDX;

	region->mobj = mobj;
	region->offset = 0;
	region->va = utc->mmu->ta_private_vmem_start;
	region->size = ROUNDUP(utc->mobj_stack->size, granule);
	region->attr = TEE_MATTR_VALID_BLOCK | TEE_MATTR_SECURE |
		       TEE_MATTR_URW | TEE_MATTR_PRW |
		       (TEE_MATTR_CACHE_CACHED << TEE_MATTR_CACHE_SHIFT);
}

TEE_Result tee_mmu_map_add_segment(struct user_ta_ctx *utc, struct mobj *mobj,
				   size_t offs, size_t size, uint32_t prot)
{
	const uint32_t attr = TEE_MATTR_VALID_BLOCK | TEE_MATTR_SECURE |
			      (TEE_MATTR_CACHE_CACHED << TEE_MATTR_CACHE_SHIFT);
	const size_t granule = CORE_MMU_USER_CODE_SIZE;
	struct tee_ta_region *tbl = utc->mmu->regions;
	vaddr_t va;
	vaddr_t end_va;
	size_t n = TEE_MMU_UMAP_CODE_IDX;
	size_t o;

	if (!tbl[n].size) {
		/* We're continuing the va space from previous entry. */
		assert(tbl[n - 1].size);

		/* This is the first segment */
		va = tbl[n - 1].va + tbl[n - 1].size;
		end_va = ROUNDUP((offs & (granule - 1)) + size, granule) + va;
		o = ROUNDDOWN(offs, granule);
		goto set_entry;
	}

	/*
	 * mobj of code segments must not change once the first is
	 * assigned.
	 */
	if (mobj != tbl[n].mobj)
		return TEE_ERROR_SECURITY;

	/*
	 * Let's find an entry we overlap with or if we need to add a new
	 * entry.
	 */
	o = offs - tbl[n].offset;
	va = ROUNDDOWN(o, granule) + tbl[n].va;
	end_va = ROUNDUP(o + size, granule) + tbl[n].va;
	o = ROUNDDOWN(offs, granule);
	while (true) {
		if (va >= (tbl[n].va + tbl[n].size)) {
			n++;
			if (n >= TEE_MMU_UMAP_PARAM_IDX)
				return TEE_ERROR_SECURITY;
			if (!tbl[n].size)
				goto set_entry;
			continue;
		}

		/*
		 * There's at least partial overlap with this entry
		 *
		 * Since we're overlapping there should be at least one
		 * free entry after this.
		 */
		if (((n + 1) >= TEE_MMU_UMAP_PARAM_IDX) || tbl[n + 1].size)
			return TEE_ERROR_SECURITY;

		/* offset must match or the segments aren't added in order */
		if (o != (va - tbl[n].va + tbl[n].offset))
			return TEE_ERROR_SECURITY;
		/* We should only overlap in the last granule of the entry. */
		if ((va + granule) < (tbl[n].va + tbl[n].size))
			return TEE_ERROR_SECURITY;

		/* Merge protection attribute for this entry */
		tbl[n].attr |= prot;

		va += granule;
		/* If the segment was completely overlapped, we're done. */
		if (va == end_va)
			return TEE_SUCCESS;
		o += granule;
		n++;
		goto set_entry;
	}

set_entry:
	tbl[n].mobj = mobj;
	tbl[n].va = va;
	tbl[n].offset = o;
	tbl[n].size = end_va - va;
	tbl[n].attr = prot | attr;

	utc->mmu->ta_private_vmem_end = tbl[n].va + tbl[n].size;
	/*
	 * Check that we have enough translation tables available to map
	 * this TA.
	 */
	return alloc_pgt(utc, utc->mmu->ta_private_vmem_start,
			 utc->mmu->ta_private_vmem_end);
}

void tee_mmu_map_clear(struct user_ta_ctx *utc)
{
	utc->mmu->ta_private_vmem_end = 0;
	memset(utc->mmu->regions, 0, sizeof(utc->mmu->regions));
}

static void clear_param_map(struct user_ta_ctx *utc)
{
	const size_t n = TEE_MMU_UMAP_PARAM_IDX;
	const size_t array_size = ARRAY_SIZE(utc->mmu->regions);

	memset(utc->mmu->regions + n, 0,
	       (array_size - n) * sizeof(utc->mmu->regions[0]));
}

static TEE_Result param_mem_to_user_va(struct user_ta_ctx *utc,
				       struct param_mem *mem, void **user_va)
{
	size_t n;

	for (n = TEE_MMU_UMAP_PARAM_IDX; n < TEE_MMU_UMAP_MAX_ENTRIES; n++) {
		struct tee_ta_region *region = utc->mmu->regions + n;
		vaddr_t va;

		if (mem->mobj != region->mobj)
			continue;
		if (mem->offs < region->offset)
			continue;
		if (mem->offs >= (region->offset + region->size))
			continue;
		va = region->va + mem->offs - region->offset;
		*user_va = (void *)va;
		return TEE_SUCCESS;
	}
	return TEE_ERROR_GENERIC;
}

TEE_Result tee_mmu_map_param(struct user_ta_ctx *utc,
		struct tee_ta_param *param, void *param_va[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_SUCCESS;
	size_t n;

	/* Clear all the param entries as they can hold old information */
	clear_param_map(utc);

	/* Map secure memory params first then nonsecure memory params */
	for (n = 0; n < TEE_NUM_PARAMS; n++) {
		uint32_t param_type = TEE_PARAM_TYPE_GET(param->types, n);
		struct param_mem *mem = &param->u[n].mem;

		if (param_type != TEE_PARAM_TYPE_MEMREF_INPUT &&
		    param_type != TEE_PARAM_TYPE_MEMREF_OUTPUT &&
		    param_type != TEE_PARAM_TYPE_MEMREF_INOUT)
			continue;
		if (!mem->size)
			continue;
		if (mobj_is_nonsec(mem->mobj))
			continue;

		res = tee_mmu_umap_add_param(utc->mmu, mem);
		if (res != TEE_SUCCESS)
			return res;
	}
	for (n = 0; n < TEE_NUM_PARAMS; n++) {
		uint32_t param_type = TEE_PARAM_TYPE_GET(param->types, n);
		struct param_mem *mem = &param->u[n].mem;

		if (param_type != TEE_PARAM_TYPE_MEMREF_INPUT &&
		    param_type != TEE_PARAM_TYPE_MEMREF_OUTPUT &&
		    param_type != TEE_PARAM_TYPE_MEMREF_INOUT)
			continue;
		if (!mem->size)
			continue;
		if (!mobj_is_nonsec(mem->mobj))
			continue;

		res = tee_mmu_umap_add_param(utc->mmu, mem);
		if (res != TEE_SUCCESS)
			return res;
	}

	res = tee_mmu_umap_set_vas(utc->mmu);
	if (res != TEE_SUCCESS)
		return res;

	for (n = 0; n < TEE_NUM_PARAMS; n++) {
		uint32_t param_type = TEE_PARAM_TYPE_GET(param->types, n);
		struct param_mem *mem = &param->u[n].mem;

		if (param_type != TEE_PARAM_TYPE_MEMREF_INPUT &&
		    param_type != TEE_PARAM_TYPE_MEMREF_OUTPUT &&
		    param_type != TEE_PARAM_TYPE_MEMREF_INOUT)
			continue;
		if (mem->size == 0)
			continue;

		res = param_mem_to_user_va(utc, mem, param_va + n);
		if (res != TEE_SUCCESS)
			return res;
	}

	utc->mmu->ta_private_vmem_start = utc->mmu->regions[0].va;

	n = ARRAY_SIZE(utc->mmu->regions);
	do {
		n--;
	} while (n && !utc->mmu->regions[n].size);

	return alloc_pgt(utc, utc->mmu->ta_private_vmem_start,
			 utc->mmu->regions[n].va + utc->mmu->regions[n].size);
}

TEE_Result tee_mmu_add_rwmem(struct user_ta_ctx *utc, struct mobj *mobj,
			     int pgdir_offset, vaddr_t *va)
{
	struct tee_ta_region *reg = NULL;
	struct tee_ta_region *last_reg;
	vaddr_t v;
	vaddr_t end_v;
	size_t n;

	assert(pgdir_offset < CORE_MMU_PGDIR_SIZE);

	/*
	 * Avoid the corner case when no regions are assigned, currently
	 * stack and code areas are always assigned before we end up here.
	 */
	if (!utc->mmu->regions[0].size)
		return TEE_ERROR_GENERIC;

	for (n = 1; n < ARRAY_SIZE(utc->mmu->regions); n++) {
		if (!reg && utc->mmu->regions[n].size)
			continue;
		last_reg = utc->mmu->regions + n;

		if (!reg) {
			reg = last_reg;
			v = ROUNDUP((reg - 1)->va + (reg - 1)->size,
				    SMALL_PAGE_SIZE);
#ifndef CFG_WITH_LPAE
			/*
			 * Non-LPAE mappings can't mix secure and
			 * non-secure in a single pgdir.
			 */
			if (mobj_is_secure((reg - 1)->mobj) !=
			    mobj_is_secure(mobj))
				v = ROUNDUP(v, CORE_MMU_PGDIR_SIZE);
#endif

			/*
			 * If mobj needs to span several page directories
			 * the offset into the first pgdir need to match
			 * the supplied offset or some area used by the
			 * pager may not fit into a single pgdir.
			 */
			if (pgdir_offset >= 0 &&
			    mobj->size > CORE_MMU_PGDIR_SIZE) {
				if ((v & CORE_MMU_PGDIR_MASK) <
				    (size_t)pgdir_offset)
					v = ROUNDDOWN(v, CORE_MMU_PGDIR_SIZE);
				else
					v = ROUNDUP(v, CORE_MMU_PGDIR_SIZE);
				v += pgdir_offset;
			}
			end_v = ROUNDUP(v + mobj->size, SMALL_PAGE_SIZE);
			continue;
		}

		if (!last_reg->size)
			continue;
		/*
		 * There's one registered region after our selected spot,
		 * check if we can still fit or if we need a later spot.
		 */
		if (end_v > last_reg->va) {
			reg = NULL;
			continue;
		}
#ifndef CFG_WITH_LPAE
		if (mobj_is_secure(mobj) != mobj_is_secure(last_reg->mobj) &&
		    end_v > ROUNDDOWN(last_reg->va, CORE_MMU_PGDIR_SIZE))
			reg = NULL;
#endif
	}

	if (reg) {
		TEE_Result res;

		end_v = MAX(end_v, last_reg->va + last_reg->size);
		res = alloc_pgt(utc, utc->mmu->ta_private_vmem_start, end_v);
		if (res != TEE_SUCCESS)
			return res;

		*va = v;
		reg->va = v;
		reg->mobj = mobj;
		reg->offset = 0;
		reg->size = ROUNDUP(mobj->size, SMALL_PAGE_SIZE);
		if (mobj_is_secure(mobj))
			reg->attr = TEE_MATTR_SECURE;
		else
			reg->attr = 0;
		return TEE_SUCCESS;
	}

	return TEE_ERROR_OUT_OF_MEMORY;
}

void tee_mmu_rem_rwmem(struct user_ta_ctx *utc, struct mobj *mobj, vaddr_t va)
{
	size_t n;

	for (n = 0; n < ARRAY_SIZE(utc->mmu->regions); n++) {
		struct tee_ta_region *reg = utc->mmu->regions + n;

		if (reg->mobj == mobj && reg->va == va) {
			free_pgt(utc, reg->va, reg->size);
			memset(reg, 0, sizeof(*reg));
			return;
		}
	}
}

/*
 * tee_mmu_final - finalise and free ctx mmu
 */
void tee_mmu_final(struct user_ta_ctx *utc)
{
	uint32_t asid = 1 << ((utc->context - 1) & 0xff);

	/* return ASID */
	g_asid |= asid;

	/* clear MMU entries to avoid clash when asid is reused */
	tlbi_asid(utc->context & 0xff);
	utc->context = 0;

	free(utc->mmu);
	utc->mmu = NULL;
}

/* return true only if buffer fits inside TA private memory */
bool tee_mmu_is_vbuf_inside_ta_private(const struct user_ta_ctx *utc,
				  const void *va, size_t size)
{
	return core_is_buffer_inside(va, size,
	  utc->mmu->ta_private_vmem_start,
	  utc->mmu->ta_private_vmem_end - utc->mmu->ta_private_vmem_start);
}

/* return true only if buffer intersects TA private memory */
bool tee_mmu_is_vbuf_intersect_ta_private(const struct user_ta_ctx *utc,
					  const void *va, size_t size)
{
	return core_is_buffer_intersect(va, size,
	  utc->mmu->ta_private_vmem_start,
	  utc->mmu->ta_private_vmem_end - utc->mmu->ta_private_vmem_start);
}

TEE_Result tee_mmu_vbuf_to_mobj_offs(const struct user_ta_ctx *utc,
				     const void *va, size_t size,
				     struct mobj **mobj, size_t *offs)
{
	size_t n;

	for (n = 0; n < ARRAY_SIZE(utc->mmu->regions); n++) {
		if (!utc->mmu->regions[n].mobj)
			continue;
		if (core_is_buffer_inside(va, size, utc->mmu->regions[n].va,
					  utc->mmu->regions[n].size)) {
			*mobj = utc->mmu->regions[n].mobj;
			*offs = (vaddr_t)va - utc->mmu->regions[n].va +
				utc->mmu->regions[n].offset;
			return TEE_SUCCESS;
		}
	}

	return TEE_ERROR_BAD_PARAMETERS;
}

static TEE_Result tee_mmu_user_va2pa_attr(const struct user_ta_ctx *utc,
			void *ua, paddr_t *pa, uint32_t *attr)
{
	size_t n;

	for (n = 0; n < ARRAY_SIZE(utc->mmu->regions); n++) {
		if (core_is_buffer_inside(ua, 1, utc->mmu->regions[n].va,
					  utc->mmu->regions[n].size)) {
			if (pa) {
				TEE_Result res;
				paddr_t p;

				res = mobj_get_pa(utc->mmu->regions[n].mobj,
						  utc->mmu->regions[n].offset,
						  0, &p);
				if (res != TEE_SUCCESS)
					return res;

				*pa = (paddr_t)ua - utc->mmu->regions[n].va + p;
			}
			if (attr)
				*attr = utc->mmu->regions[n].attr;
			return TEE_SUCCESS;
		}
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
	size_t n;

	for (n = 0; n < ARRAY_SIZE(utc->mmu->regions); n++) {
		if (!utc->mmu->regions[n].mobj)
			continue;

		res = mobj_get_pa(utc->mmu->regions[n].mobj,
				  utc->mmu->regions[n].offset, 0, &p);
		if (res != TEE_SUCCESS)
			return res;

		if (core_is_buffer_inside(pa, 1, p,
					  utc->mmu->regions[n].size)) {
			*va = (void *)(pa - p + utc->mmu->regions[n].va);
			return TEE_SUCCESS;
		}
	}

	return TEE_ERROR_ACCESS_DENIED;
}

TEE_Result tee_mmu_check_access_rights(const struct user_ta_ctx *utc,
				       uint32_t flags, uaddr_t uaddr,
				       size_t len)
{
	uaddr_t a;
	size_t addr_incr = MIN(CORE_MMU_USER_CODE_SIZE,
			       CORE_MMU_USER_PARAM_SIZE);

	if (ADD_OVERFLOW(uaddr, len, &a))
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

	for (a = uaddr; a < (uaddr + len); a += addr_incr) {
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
	pgt_free(&tsd->pgt_cache, tsd->ctx && is_user_ta_ctx(tsd->ctx));

	if (ctx && is_user_ta_ctx(ctx)) {
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

uintptr_t tee_mmu_get_load_addr(const struct tee_ta_ctx *const ctx)
{
	const struct user_ta_ctx *utc = to_user_ta_ctx((void *)ctx);

	assert(utc->mmu);
	return utc->mmu->regions[TEE_MMU_UMAP_CODE_IDX].va;
}

void teecore_init_ta_ram(void)
{
	vaddr_t s;
	vaddr_t e;
	paddr_t ps;
	paddr_t pe;

	/* get virtual addr/size of RAM where TA are loaded/executedNSec
	 * shared mem allcated from teecore */
	core_mmu_get_mem_by_type(MEM_AREA_TA_RAM, &s, &e);
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

uint32_t tee_mmu_user_get_cache_attr(struct user_ta_ctx *utc, void *va)
{
	uint32_t attr;

	if (tee_mmu_user_va2pa_attr(utc, va, NULL, &attr) != TEE_SUCCESS)
		panic("cannot get attr");

	return (attr >> TEE_MATTR_CACHE_SHIFT) & TEE_MATTR_CACHE_MASK;
}
