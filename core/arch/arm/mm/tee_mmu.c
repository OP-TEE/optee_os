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
#include <kernel/tee_common.h>
#include <kernel/tee_misc.h>
#include <kernel/tz_ssvce.h>
#include <mm/tee_mmu.h>
#include <mm/tee_mmu_types.h>
#include <mm/tee_mmu_defs.h>
#include <mm/pgt_cache.h>
#include <mm/tee_mm.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <mm/tee_pager.h>
#include <sm/optee_smc.h>
#include <stdlib.h>
#include <trace.h>
#include <types_ext.h>
#include <user_ta_header.h>
#include <util.h>
#include "tee_api_types.h"

#ifdef CFG_PL310
#include <kernel/tee_l2cc_mutex.h>
#endif

#define TEE_MMU_UMAP_STACK_IDX	0
#define TEE_MMU_UMAP_CODE_IDX	1
#define TEE_MMU_UMAP_NUM_CODE_SEGMENTS	3

#define TEE_MMU_UMAP_PARAM_IDX		(TEE_MMU_UMAP_CODE_IDX + \
					 TEE_MMU_UMAP_NUM_CODE_SEGMENTS)
#define TEE_MMU_UMAP_MAX_ENTRIES	(TEE_MMU_UMAP_PARAM_IDX + 4)

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

static void tee_mmu_umap_set_pa(struct tee_mmap_region *tbl,
			size_t granule, paddr_t pa, size_t size, uint32_t attr)
{
	paddr_t upa = ROUNDDOWN(pa, granule);
	size_t usz = ROUNDUP(pa - upa + size, granule);

	tbl->pa = upa;
	tbl->size = usz;
	tbl->attr = attr;
}

static TEE_Result tee_mmu_umap_add_param(struct tee_mmu_info *mmu, paddr_t pa,
			size_t size, uint32_t attr)
{
	struct tee_mmap_region *last_entry = NULL;
	size_t n;
	paddr_t npa;
	size_t nsz;

	/* Check that we can map memory using this attribute */
	if (!core_mmu_mattr_is_ok(attr))
		return TEE_ERROR_BAD_PARAMETERS;

	/* Find empty entry */
	for (n = TEE_MMU_UMAP_PARAM_IDX; n < TEE_MMU_UMAP_MAX_ENTRIES; n++)
		if (!mmu->table[n].size)
			break;

	if (n == TEE_MMU_UMAP_MAX_ENTRIES) {
		/* No entries left "can't happen" */
		return TEE_ERROR_EXCESS_DATA;
	}

	tee_mmu_umap_set_pa(mmu->table + n, CORE_MMU_USER_PARAM_SIZE,
			    pa, size, attr);

	/* Try to coalesce some entries */
	while (true) {
		/* Find last param */
		n = TEE_MMU_UMAP_MAX_ENTRIES - 1;

		while (!mmu->table[n].size) {
			n--;
			if (n < TEE_MMU_UMAP_PARAM_IDX) {
				/* No param entries found, "can't happen" */
				return TEE_ERROR_BAD_STATE;
			}
		}

		if (last_entry == mmu->table + n)
			return TEE_SUCCESS; /* Can't coalesc more */
		last_entry = mmu->table + n;

		n--;
		while (n >= TEE_MMU_UMAP_PARAM_IDX) {
			struct tee_mmap_region *entry = mmu->table + n;

			n--;
			if (last_entry->attr != entry->attr) {
				if (core_is_buffer_intersect(last_entry->pa,
							     last_entry->size,
							     entry->pa,
							     entry->size))
					return TEE_ERROR_ACCESS_CONFLICT;
				continue;
			}

			if ((last_entry->pa + last_entry->size) == entry->pa ||
			    (entry->pa + entry->size) == last_entry->pa ||
			    core_is_buffer_intersect(last_entry->pa,
						     last_entry->size,
						     entry->pa, entry->size)) {
				npa = MIN(last_entry->pa, entry->pa);
				nsz = MAX(last_entry->pa + last_entry->size,
					  entry->pa + entry->size) - npa;
				entry->pa = npa;
				entry->size = nsz;
				last_entry->pa = 0;
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
	while (n && !mmu->table[n].size)
		n--;
	va = mmu->table[n].va + mmu->table[n].size;
	assert(va);

	core_mmu_get_user_va_range(&va_range_base, &va_range_size);
	assert(va_range_base == mmu->ta_private_vmem_start);

	/*
	 * Assign parameters in secure memory.
	 */
	va = ROUNDUP(va, granule);
	for (n = TEE_MMU_UMAP_PARAM_IDX; n < TEE_MMU_UMAP_MAX_ENTRIES; n++) {
		if (!mmu->table[n].size ||
		    !(mmu->table[n].attr & TEE_MATTR_SECURE))
			continue;
		mmu->table[n].va = va;
		va += mmu->table[n].size;
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
		if (!mmu->table[n].size ||
		    (mmu->table[n].attr & TEE_MATTR_SECURE))
			continue;
		mmu->table[n].va = va;
		va += mmu->table[n].size;
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
	utc->mmu->table = calloc(TEE_MMU_UMAP_MAX_ENTRIES,
				 sizeof(struct tee_mmap_region));
	if (!utc->mmu->table)
		return TEE_ERROR_OUT_OF_MEMORY;
	utc->mmu->size = TEE_MMU_UMAP_MAX_ENTRIES;
	core_mmu_get_user_va_range(&utc->mmu->ta_private_vmem_start, NULL);
	return TEE_SUCCESS;
}

#ifdef CFG_SMALL_PAGE_USER_TA
static TEE_Result check_pgt_avail(vaddr_t base, vaddr_t end)
{
	vaddr_t b = ROUNDDOWN(base, CORE_MMU_PGDIR_SIZE);
	vaddr_t e = ROUNDUP(end, CORE_MMU_PGDIR_SIZE);
	size_t ntbl = (e - b) >> CORE_MMU_PGDIR_SHIFT;

	if (!pgt_check_avail(ntbl)) {
		EMSG("%zu page tables not available", ntbl);
		return TEE_ERROR_OUT_OF_MEMORY;
	}
	return TEE_SUCCESS;
}
#else
static TEE_Result check_pgt_avail(vaddr_t base __unused, vaddr_t end __unused)
{
	return TEE_SUCCESS;
}
#endif

void tee_mmu_map_stack(struct user_ta_ctx *utc, paddr_t pa, size_t size,
		       uint32_t prot)
{
	const uint32_t attr = TEE_MATTR_VALID_BLOCK | TEE_MATTR_SECURE |
			      (TEE_MATTR_CACHE_CACHED << TEE_MATTR_CACHE_SHIFT);
	const size_t granule = CORE_MMU_USER_CODE_SIZE;
	struct tee_mmap_region *tbl = utc->mmu->table;

	tbl[TEE_MMU_UMAP_STACK_IDX].pa = pa;
	tbl[TEE_MMU_UMAP_STACK_IDX].va = utc->mmu->ta_private_vmem_start;
	tbl[TEE_MMU_UMAP_STACK_IDX].size = ROUNDUP(size, granule);
	tbl[TEE_MMU_UMAP_STACK_IDX].attr = prot | attr;
}

TEE_Result tee_mmu_map_add_segment(struct user_ta_ctx *utc, paddr_t base_pa,
			size_t offs, size_t size, uint32_t prot)
{
	const uint32_t attr = TEE_MATTR_VALID_BLOCK | TEE_MATTR_SECURE |
			      (TEE_MATTR_CACHE_CACHED << TEE_MATTR_CACHE_SHIFT);
	const size_t granule = CORE_MMU_USER_CODE_SIZE;
	struct tee_mmap_region *tbl = utc->mmu->table;
	vaddr_t va;
	vaddr_t end_va;
	paddr_t pa;
	size_t n = TEE_MMU_UMAP_CODE_IDX;

	if (!tbl[n].size) {
		/* We're continuing the va space from previous entry. */
		assert(tbl[n - 1].size);

		/* This is the first segment */
		assert(offs < granule);
		va = tbl[n - 1].va + tbl[n - 1].size;
		end_va = ROUNDUP(offs + size, granule) + va;
		pa = base_pa;
		goto set_entry;
	}

	/*
	 * base_pa of code segments must not change once the first is
	 * assigned.
	 */
	if (base_pa != tbl[n].pa)
		return TEE_ERROR_SECURITY;

	/*
	 * Let's find an entry we overlap with or if we need to add a new
	 * entry.
	 */
	va = ROUNDDOWN(offs, granule) + tbl[n].va;
	end_va = ROUNDUP(offs + size, granule) + tbl[n].va;
	pa = ROUNDDOWN(offs, granule) + base_pa;
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

		/* pa must match or the segments aren't added in order */
		if (pa != (va - tbl[n].va + tbl[n].pa))
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
		pa += granule;
		n++;
		goto set_entry;
	}

set_entry:
	tbl[n].pa = pa;
	tbl[n].va = va;
	tbl[n].size = end_va - va;
	tbl[n].attr = prot | attr;

	utc->mmu->ta_private_vmem_end = tbl[n].va + tbl[n].size;
	/*
	 * Check that we have enough translation tables available to map
	 * this TA.
	 */
	return check_pgt_avail(utc->mmu->ta_private_vmem_start,
			       utc->mmu->ta_private_vmem_end);
}

void tee_mmu_map_clear(struct user_ta_ctx *utc)
{
	utc->mmu->ta_private_vmem_end = 0;
	memset(utc->mmu->table, 0,
	       TEE_MMU_UMAP_MAX_ENTRIES * sizeof(struct tee_mmap_region));
}

TEE_Result tee_mmu_map_param(struct user_ta_ctx *utc,
		struct tee_ta_param *param)
{
	TEE_Result res = TEE_SUCCESS;
	size_t n;

	/* Clear all the param entries as they can hold old information */
	memset(utc->mmu->table + TEE_MMU_UMAP_PARAM_IDX, 0,
		(TEE_MMU_UMAP_MAX_ENTRIES - TEE_MMU_UMAP_PARAM_IDX) *
		sizeof(struct tee_mmap_region));

	for (n = 0; n < 4; n++) {
		uint32_t param_type = TEE_PARAM_TYPE_GET(param->types, n);
		TEE_Param *p = &param->params[n];
		uint32_t attr = TEE_MMU_UDATA_ATTR;

		if (param_type != TEE_PARAM_TYPE_MEMREF_INPUT &&
		    param_type != TEE_PARAM_TYPE_MEMREF_OUTPUT &&
		    param_type != TEE_PARAM_TYPE_MEMREF_INOUT)
			continue;
		if (p->memref.size == 0)
			continue;

		if (tee_pbuf_is_non_sec(p->memref.buffer, p->memref.size))
			attr &= ~TEE_MATTR_SECURE;

		if (param->param_attr[n] == OPTEE_SMC_SHM_CACHED)
			attr |= TEE_MATTR_CACHE_CACHED << TEE_MATTR_CACHE_SHIFT;
		else
			attr |= TEE_MATTR_CACHE_NONCACHE <<
				TEE_MATTR_CACHE_SHIFT;

		res = tee_mmu_umap_add_param(utc->mmu,
				(paddr_t)p->memref.buffer, p->memref.size,
				attr);
		if (res != TEE_SUCCESS)
			return res;
	}

	res = tee_mmu_umap_set_vas(utc->mmu);
	if (res != TEE_SUCCESS)
		return res;

	for (n = 0; n < 4; n++) {
		uint32_t param_type = TEE_PARAM_TYPE_GET(param->types, n);
		TEE_Param *p = &param->params[n];

		if (param_type != TEE_PARAM_TYPE_MEMREF_INPUT &&
		    param_type != TEE_PARAM_TYPE_MEMREF_OUTPUT &&
		    param_type != TEE_PARAM_TYPE_MEMREF_INOUT)
			continue;
		if (p->memref.size == 0)
			continue;

		res = tee_mmu_user_pa2va_helper(utc, (paddr_t)p->memref.buffer,
					 &p->memref.buffer);
		if (res != TEE_SUCCESS)
			return res;
	}

	utc->mmu->ta_private_vmem_start = utc->mmu->table[0].va;

	n = TEE_MMU_UMAP_MAX_ENTRIES;
	do {
		n--;
	} while (n && !utc->mmu->table[n].size);
	utc->mmu->ta_private_vmem_end = utc->mmu->table[n].va +
					utc->mmu->table[n].size;

	return check_pgt_avail(utc->mmu->ta_private_vmem_start,
			       utc->mmu->ta_private_vmem_end);
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
	secure_mmu_unifiedtlbinv_byasid(utc->context & 0xff);
	utc->context = 0;

	if (utc->mmu) {
		free(utc->mmu->table);
		free(utc->mmu);
	}
	utc->mmu = NULL;
}

/* return true only if buffer fits inside TA private memory */
bool tee_mmu_is_vbuf_inside_ta_private(const struct user_ta_ctx *utc,
				  const void *va, size_t size)
{
	return core_is_buffer_inside(va, size,
	  utc->mmu->ta_private_vmem_start,
	  utc->mmu->ta_private_vmem_end - utc->mmu->ta_private_vmem_start + 1);
}

/* return true only if buffer intersects TA private memory */
bool tee_mmu_is_vbuf_intersect_ta_private(const struct user_ta_ctx *utc,
					  const void *va, size_t size)
{
	return core_is_buffer_intersect(va, size,
	  utc->mmu->ta_private_vmem_start,
	  utc->mmu->ta_private_vmem_end - utc->mmu->ta_private_vmem_start + 1);
}

static TEE_Result tee_mmu_user_va2pa_attr(const struct user_ta_ctx *utc,
			void *ua, paddr_t *pa, uint32_t *attr)
{
	size_t n;

	if (!utc->mmu->table)
		return TEE_ERROR_ACCESS_DENIED;

	for (n = 0; n < utc->mmu->size; n++) {
		if (core_is_buffer_inside(ua, 1, utc->mmu->table[n].va,
					  utc->mmu->table[n].size)) {
			*pa = (paddr_t)ua - utc->mmu->table[n].va +
				utc->mmu->table[n].pa;
			if (attr)
				*attr = utc->mmu->table[n].attr;
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
	size_t n;

	if (!utc->mmu->table)
		return TEE_ERROR_ACCESS_DENIED;

	for (n = 0; n < utc->mmu->size; n++) {
		if (core_is_buffer_inside(pa, 1, utc->mmu->table[n].pa,
					  utc->mmu->table[n].size)) {
			*va = (void *)((paddr_t)pa - utc->mmu->table[n].pa +
					utc->mmu->table[n].va);
			return TEE_SUCCESS;
		}
	}
	return TEE_ERROR_ACCESS_DENIED;
}

TEE_Result tee_mmu_check_access_rights(const struct user_ta_ctx *utc,
				       uint32_t flags, tee_uaddr_t uaddr,
				       size_t len)
{
	tee_uaddr_t a;
	size_t addr_incr = MIN(CORE_MMU_USER_CODE_SIZE,
			       CORE_MMU_USER_PARAM_SIZE);

	/* Address wrap */
	if ((uaddr + len) < uaddr)
		return TEE_ERROR_ACCESS_DENIED;

	for (a = uaddr; a < (uaddr + len); a += addr_incr) {
		paddr_t pa;
		uint32_t attr;
		TEE_Result res;

		res = tee_mmu_user_va2pa_attr(utc, (void *)a, &pa, &attr);
		if (res != TEE_SUCCESS)
			return res;

		if (!(flags & TEE_MEMORY_ACCESS_ANY_OWNER)) {
			/*
			 * Strict check that no one else (wich equal or
			 * less trust) may can access this memory.
			 *
			 * Parameters are shared with normal world if they
			 * aren't in secure DDR.
			 *
			 * If the parameters are in secure DDR it's because one
			 * TA is invoking another TA and in that case there's
			 * new memory allocated privately for the paramters to
			 * this TA.
			 *
			 * If we do this check for an address on TA
			 * internal memory it's harmless as it will always
			 * be in secure DDR.
			 */
			if (!tee_mm_addr_is_within_range(&tee_mm_sec_ddr, pa))
				return TEE_ERROR_ACCESS_DENIED;

		}

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
#ifdef CFG_SMALL_PAGE_USER_TA
	/*
	 * No matter what happens below, the current user TA will not be
	 * current any longer. Make sure pager is in sync with that.
	 * This function has to be called before there's a chance that
	 * pgt_free_unlocked() is called.
	 *
	 * Save translation tables in a cache if it's a user TA.
	 */
	pgt_free(&tsd->pgt_cache, tsd->ctx && is_user_ta_ctx(tsd->ctx));
#endif

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

	assert(utc->mmu && utc->mmu->table);
	if (utc->mmu->size != TEE_MMU_UMAP_MAX_ENTRIES)
		panic("invalid size");

	return utc->mmu->table[1].va;
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
	tee_l2cc_store_mutex_boot_pa(s);
	s += sizeof(uint32_t);		/* size of a pl310 mutex */
#endif

	default_nsec_shm_paddr = virt_to_phys((void *)s);
	default_nsec_shm_size = e - s;
}

uint32_t tee_mmu_user_get_cache_attr(struct user_ta_ctx *utc, void *va)
{
	paddr_t pa;
	uint32_t attr;

	if (tee_mmu_user_va2pa_attr(utc, va, &pa, &attr) != TEE_SUCCESS)
		panic("cannot get attr");

	return (attr >> TEE_MATTR_CACHE_SHIFT) & TEE_MATTR_CACHE_MASK;
}
