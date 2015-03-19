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
#include <assert.h>
#include <stdlib.h>
#include <types_ext.h>

#include <arm.h>
#include <util.h>
#include <kernel/tee_common.h>
#include <mm/tee_mmu.h>
#include <mm/tee_mmu_types.h>
#include <mm/tee_mmu_defs.h>
#include <user_ta_header.h>
#include <mm/tee_mm_def.h>
#include <mm/tee_mm.h>
#include "tee_api_types.h"
#include <kernel/tee_ta_manager_unpg.h>
#include <kernel/tee_misc.h>
#include <trace.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <mm/tee_mmu_io.h>
#include <sm/teesmc.h>
#include <kernel/tz_ssvce.h>
#include <kernel/panic.h>

#define TEE_MMU_UMAP_HEAP_STACK_IDX	0
#define TEE_MMU_UMAP_CODE_IDX		1
#define TEE_MMU_UMAP_PARAM_IDX		2
#define TEE_MMU_UMAP_MAX_ENTRIES	6

#define TEE_MMU_UDATA_ATTR		(TEE_MATTR_VALID_BLOCK | \
					 TEE_MATTR_PRW | TEE_MATTR_URW | \
					 TEE_MATTR_SECURE)
#define TEE_MMU_UCODE_ATTR		(TEE_MATTR_VALID_BLOCK | \
					 TEE_MATTR_PRW | TEE_MATTR_URWX | \
					 TEE_MATTR_SECURE)

#define TEE_MMU_UCACHE_DEFAULT_ATTR	(TEE_MATTR_I_WRITE_BACK | \
					 TEE_MATTR_O_WRITE_BACK)

/* Support for 31 concurrent sessions */
static uint32_t g_asid = 0xffffffff;

static tee_mm_pool_t tee_mmu_virt_kmap;


static void tee_mmu_umap_clear(struct tee_mmu_info *mmu)
{
	if (mmu->table && mmu->size != TEE_MMU_UMAP_MAX_ENTRIES) {
		free(mmu->table);
		mmu->table = NULL;
	}

	if (!mmu->table)
		return;

	memset(mmu->table, 0, sizeof(struct tee_mmap_region) *
				TEE_MMU_UMAP_MAX_ENTRIES);
}



static TEE_Result tee_mmu_umap_init(struct tee_mmu_info *mmu)
{
	tee_mmu_umap_clear(mmu);

	if (!mmu->table) {
		mmu->table = calloc(TEE_MMU_UMAP_MAX_ENTRIES,
				    sizeof(struct tee_mmap_region));
		if (!mmu->table)
			return TEE_ERROR_OUT_OF_MEMORY;
		mmu->size = TEE_MMU_UMAP_MAX_ENTRIES;
	}

	return TEE_SUCCESS;
}

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
	size_t n;
	vaddr_t va;
	vaddr_t va_range_base;
	size_t va_range_size;

	assert(mmu->table && mmu->size == TEE_MMU_UMAP_MAX_ENTRIES);

	core_mmu_get_user_va_range(&va_range_base, &va_range_size);
	va = va_range_base;
	for (n = 0; n < TEE_MMU_UMAP_PARAM_IDX; n++) {
		assert(mmu->table[n].size); /* PA must be assigned by now */
		mmu->table[n].va = va;
		va += CORE_MMU_USER_CODE_SIZE;
	}

	va = ROUNDUP(va, CORE_MMU_USER_PARAM_SIZE);
	for (; n < TEE_MMU_UMAP_MAX_ENTRIES; n++) {
		if (!mmu->table[n].size)
			continue;
		mmu->table[n].va = va;
		va += mmu->table[n].size;
		/* Put some empty space between each area */
		va += CORE_MMU_USER_PARAM_SIZE;
		if ((va - va_range_base) >= va_range_size)
			return TEE_ERROR_EXCESS_DATA;
	}

	return TEE_SUCCESS;
}


TEE_Result tee_mmu_init(struct tee_ta_ctx *ctx)
{
	uint32_t asid = 1;

	if (ctx->context == 0) {
		ctx->context = 1;

		/* Find available ASID */
		while (!(asid & g_asid) && (asid != 0)) {
			ctx->context++;
			asid = asid << 1;
		}

		if (asid == 0) {
			DMSG("Failed to allocate ASID");
			return TEE_ERROR_GENERIC;
		}
		g_asid &= ~asid;
	}

	ctx->mmu = calloc(1, sizeof(struct tee_mmu_info));
	if (!ctx->mmu)
		return TEE_ERROR_OUT_OF_MEMORY;

	return TEE_SUCCESS;
}

/*
 * tee_mmu_map - alloc and fill mmu mapping table for a user TA (uTA).
 *
 * param - Contains the physical addr of the input buffers
 *         Returns logical addresses
 *
 * Allocate a table to store the N first section entries of the MMU L1 table
 * used to map the target user TA, and clear table to 0.
 * Load mapping for the TA stack_heap area, code area and params area (params
 * are the 4 GP TEE TA invoke parameters buffer).
 */
TEE_Result tee_mmu_map(struct tee_ta_ctx *ctx, struct tee_ta_param *param)
{
	TEE_Result res = TEE_SUCCESS;
	paddr_t pa;
	uintptr_t smem;
	size_t n;

	TEE_ASSERT((ctx->flags & TA_FLAG_EXEC_DDR) != 0);

	res = tee_mmu_umap_init(ctx->mmu);
	if (res != TEE_SUCCESS)
		goto exit;

	/*
	 * Map heap and stack
	 */
	smem = tee_mm_get_smem(ctx->mm_heap_stack);
	if (core_va2pa((void *)smem, &pa)) {
		res = TEE_ERROR_SECURITY;
		goto exit;
	}
	tee_mmu_umap_set_pa(ctx->mmu->table + TEE_MMU_UMAP_HEAP_STACK_IDX,
			    CORE_MMU_USER_CODE_SIZE,
			    pa, tee_mm_get_bytes(ctx->mm_heap_stack),
			    TEE_MMU_UDATA_ATTR | TEE_MMU_UCACHE_DEFAULT_ATTR);

	/*
	 * Map code
	 */
	smem = tee_mm_get_smem(ctx->mm);
	if (core_va2pa((void *)smem, &pa)) {
		res = TEE_ERROR_SECURITY;
		goto exit;
	}
	tee_mmu_umap_set_pa(ctx->mmu->table + TEE_MMU_UMAP_CODE_IDX,
			    CORE_MMU_USER_CODE_SIZE,
			    pa, tee_mm_get_bytes(ctx->mm),
			    TEE_MMU_UCODE_ATTR | TEE_MMU_UCACHE_DEFAULT_ATTR);


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

		if (param->param_attr[n] & TEESMC_ATTR_CACHE_I_WRITE_THR)
			attr |= TEE_MATTR_I_WRITE_THR;
		if (param->param_attr[n] & TEESMC_ATTR_CACHE_I_WRITE_BACK)
			attr |= TEE_MATTR_I_WRITE_BACK;
		if (param->param_attr[n] & TEESMC_ATTR_CACHE_O_WRITE_THR)
			attr |= TEE_MATTR_O_WRITE_THR;
		if (param->param_attr[n] & TEESMC_ATTR_CACHE_O_WRITE_BACK)
			attr |= TEE_MATTR_O_WRITE_BACK;


		res = tee_mmu_umap_add_param(ctx->mmu,
				(paddr_t)p->memref.buffer, p->memref.size,
				attr);
		if (res != TEE_SUCCESS)
			goto exit;
	}

	res = tee_mmu_umap_set_vas(ctx->mmu);
	if (res != TEE_SUCCESS)
		goto exit;

	for (n = 0; n < 4; n++) {
		uint32_t param_type = TEE_PARAM_TYPE_GET(param->types, n);
		TEE_Param *p = &param->params[n];

		if (param_type != TEE_PARAM_TYPE_MEMREF_INPUT &&
		    param_type != TEE_PARAM_TYPE_MEMREF_OUTPUT &&
		    param_type != TEE_PARAM_TYPE_MEMREF_INOUT)
			continue;
		if (p->memref.size == 0)
			continue;

		res = tee_mmu_user_pa2va(ctx, p->memref.buffer,
					 &p->memref.buffer);
		if (res != TEE_SUCCESS)
			goto exit;
	}

	ctx->mmu->ta_private_vmem_start = ctx->mmu->table[0].va;

	n = TEE_MMU_UMAP_MAX_ENTRIES;
	do {
		n--;
	} while (n && !ctx->mmu->table[n].size);
	ctx->mmu->ta_private_vmem_end = ctx->mmu->table[n].va +
					ctx->mmu->table[n].size;

exit:
	if (res != TEE_SUCCESS)
		tee_mmu_umap_clear(ctx->mmu);

	return res;
}

/*
 * tee_mmu_final - finalise and free ctx mmu
 */
void tee_mmu_final(struct tee_ta_ctx *ctx)
{
	uint32_t asid = 1 << ((ctx->context - 1) & 0xff);

	/* return ASID */
	g_asid |= asid;

	/* clear MMU entries to avoid clash when asid is reused */
	secure_mmu_unifiedtlbinv_byasid(ctx->context & 0xff);
	ctx->context = 0;

	if (ctx->mmu != NULL) {
		free(ctx->mmu->table);
		free(ctx->mmu);
	}
	ctx->mmu = NULL;
}

/* return true only if buffer fits inside TA private memory */
bool tee_mmu_is_vbuf_inside_ta_private(const struct tee_ta_ctx *ctx,
				  const void *va, size_t size)
{
	return core_is_buffer_inside(va, size,
	  ctx->mmu->ta_private_vmem_start,
	  ctx->mmu->ta_private_vmem_end - ctx->mmu->ta_private_vmem_start + 1);
}

/* return true only if buffer intersects TA private memory */
bool tee_mmu_is_vbuf_intersect_ta_private(const struct tee_ta_ctx *ctx,
					  const void *va, size_t size)
{
	return core_is_buffer_intersect(va, size,
	  ctx->mmu->ta_private_vmem_start,
	  ctx->mmu->ta_private_vmem_end - ctx->mmu->ta_private_vmem_start + 1);
}

TEE_Result tee_mmu_kernel_to_user(const struct tee_ta_ctx *ctx,
				  const vaddr_t kaddr, tee_uaddr_t *uaddr)
{
	TEE_Result res;
	void *ua;
	paddr_t pa;

	if (core_va2pa((void *)kaddr, &pa))
		return TEE_ERROR_ACCESS_DENIED;

	res = tee_mmu_user_pa2va(ctx, (void *)pa, &ua);
	if (res == TEE_SUCCESS)
		*uaddr = (tee_uaddr_t)ua;
	return res;
}

static TEE_Result tee_mmu_user_va2pa_attr(const struct tee_ta_ctx *ctx,
			void *ua, paddr_t *pa, uint32_t *attr)
{
	size_t n;

	if (!ctx->mmu->table)
		return TEE_ERROR_ACCESS_DENIED;

	for (n = 0; n < ctx->mmu->size; n++) {
		if (core_is_buffer_inside(ua, 1, ctx->mmu->table[n].va,
					  ctx->mmu->table[n].size)) {
			*pa = (paddr_t)ua - ctx->mmu->table[n].va +
				ctx->mmu->table[n].pa;
			if (attr)
				*attr = ctx->mmu->table[n].attr;
			return TEE_SUCCESS;
		}
	}
	return TEE_ERROR_ACCESS_DENIED;
}

TEE_Result tee_mmu_user_va2pa_helper(const struct tee_ta_ctx *ctx, void *ua,
				     paddr_t *pa)
{
	return tee_mmu_user_va2pa_attr(ctx, ua, pa, NULL);
}

/* */
TEE_Result tee_mmu_user_pa2va_helper(const struct tee_ta_ctx *ctx, void *pa,
				     void **va)
{
	size_t n;

	if (!ctx->mmu->table)
		return TEE_ERROR_ACCESS_DENIED;

	for (n = 0; n < ctx->mmu->size; n++) {
		if (core_is_buffer_inside(pa, 1, ctx->mmu->table[n].pa,
					  ctx->mmu->table[n].size)) {
			*va = (void *)((paddr_t)pa - ctx->mmu->table[n].pa +
					ctx->mmu->table[n].va);
			return TEE_SUCCESS;
		}
	}
	return TEE_ERROR_ACCESS_DENIED;
}

TEE_Result tee_mmu_check_access_rights(struct tee_ta_ctx *ctx,
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

		res = tee_mmu_user_va2pa_attr(ctx, (void *)a, &pa, &attr);
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
	if (!ctx) {
		core_mmu_set_user_map(NULL);
	} else {
		struct core_mmu_user_map map;

		core_mmu_create_user_map(ctx->mmu, ctx->context, &map);
		core_mmu_set_user_map(&map);
	}
}

uintptr_t tee_mmu_get_load_addr(const struct tee_ta_ctx *const ctx)
{
	TEE_ASSERT((ctx->flags & TA_FLAG_EXEC_DDR) != 0);
	TEE_ASSERT(ctx->mmu && ctx->mmu->table &&
		   ctx->mmu->size >= TEE_MMU_UMAP_CODE_IDX);

	return ctx->mmu->table[TEE_MMU_UMAP_CODE_IDX].va;
}

/*
 * tee_mmu_kmap_init - init TA mapping support
 *
 * TAs are mapped in virtual space [0 32MB].
 * The TA MMU L1 table is always located at TEE_MMU_UL1_BASE.
 * The MMU table for a target TA instance will be copied to this address
 * when tee core sets up TA context.
 */
void tee_mmu_kmap_init(void)
{
	vaddr_t s = TEE_MMU_KMAP_START_VA;
	vaddr_t e = TEE_MMU_KMAP_END_VA;
	struct core_mmu_table_info tbl_info;

	if (!core_mmu_find_table(s, UINT_MAX, &tbl_info))
		panic();

	if (!tee_mm_init(&tee_mmu_virt_kmap, s, e, tbl_info.shift,
			 TEE_MM_POOL_NO_FLAGS)) {
		DMSG("Failed to init kmap. Trap CPU!");
		panic();
	}
}

TEE_Result tee_mmu_kmap_helper(tee_paddr_t pa, size_t len, void **va)
{
	tee_mm_entry_t *mm;
	uint32_t attr;
	struct core_mmu_table_info tbl_info;
	uint32_t pa_s;
	uint32_t pa_e;
	size_t n;
	size_t offs;

	if (!core_mmu_find_table(TEE_MMU_KMAP_START_VA, UINT_MAX, &tbl_info))
		panic();

	pa_s = ROUNDDOWN(pa, 1 << tbl_info.shift);
	pa_e = ROUNDUP(pa + len, 1 << tbl_info.shift);

	mm = tee_mm_alloc(&tee_mmu_virt_kmap, pa_e - pa_s);
	if (!mm)
		return TEE_ERROR_OUT_OF_MEMORY;

	attr = TEE_MATTR_VALID_BLOCK | TEE_MATTR_PRW | TEE_MATTR_GLOBAL;
	if (tee_pbuf_is_sec(pa, len)) {
		attr |= TEE_MATTR_SECURE;
		attr |= TEE_MATTR_I_WRITE_BACK | TEE_MATTR_O_WRITE_BACK;
	} else if (tee_pbuf_is_non_sec(pa, len)) {
		if (core_mmu_is_shm_cached())
			attr |= TEE_MATTR_I_WRITE_BACK | TEE_MATTR_O_WRITE_BACK;
	} else
		return TEE_ERROR_GENERIC;


	offs = (tee_mm_get_smem(mm) - tbl_info.va_base) >> tbl_info.shift;
	for (n = 0; n < tee_mm_get_size(mm); n++)
		core_mmu_set_entry(&tbl_info, n + offs,
				   pa_s + (n << tbl_info.shift), attr);

	core_tlb_maintenance(TLBINV_UNIFIEDTLB, 0);

	*va = (void *)(tee_mm_get_smem(mm) +
		       core_mmu_get_block_offset(&tbl_info, pa));
	return TEE_SUCCESS;
}

void tee_mmu_kunmap(void *va, size_t len)
{
	size_t n;
	tee_mm_entry_t *mm;
	struct core_mmu_table_info tbl_info;
	size_t offs;

	if (!core_mmu_find_table(TEE_MMU_KMAP_START_VA, UINT_MAX, &tbl_info))
		panic();

	mm = tee_mm_find(&tee_mmu_virt_kmap, (vaddr_t)va);
	if (mm == NULL || len > tee_mm_get_bytes(mm))
		return;		/* Invalid range, not much to do */

	/* Clear the mmu entries */
	offs = (tee_mm_get_smem(mm) - tbl_info.va_base) >> tbl_info.shift;
	for (n = 0; n < tee_mm_get_size(mm); n++)
		core_mmu_set_entry(&tbl_info, n + offs, 0, 0);

	core_tlb_maintenance(TLBINV_UNIFIEDTLB, 0);
	tee_mm_free(mm);
}

TEE_Result tee_mmu_kmap_pa2va_helper(void *pa, void **va)
{
	size_t n;
	struct core_mmu_table_info tbl_info;
	size_t shift;
	paddr_t match_pa;

	if (!core_mmu_find_table(TEE_MMU_KMAP_START_VA, UINT_MAX, &tbl_info))
		panic();

	shift = tbl_info.shift;
	match_pa = ROUNDDOWN((paddr_t)pa, 1 << shift);

	for (n = core_mmu_va2idx(&tbl_info, TEE_MMU_KMAP_START_VA);
	     n < core_mmu_va2idx(&tbl_info, TEE_MMU_KMAP_END_VA); n++) {
		uint32_t attr;
		paddr_t npa;

		core_mmu_get_entry(&tbl_info, n, &npa, &attr);
		if (!(attr & TEE_MATTR_VALID_BLOCK))
			continue;
		assert(!(attr & TEE_MATTR_TABLE));

		if (npa == match_pa) {
			*va = (void *)(core_mmu_idx2va(&tbl_info, n) +
				       ((paddr_t)pa - match_pa));
			return TEE_SUCCESS;
		}
	}

	return TEE_ERROR_ACCESS_DENIED;
}

static TEE_Result tee_mmu_kmap_va2pa_attr(void *va, void **pa, uint32_t *attr)
{
	struct core_mmu_table_info tbl_info;
	size_t block_offset;
	size_t n;
	paddr_t npa;
	uint32_t nattr;

	if (!core_mmu_find_table(TEE_MMU_KMAP_START_VA, UINT_MAX, &tbl_info))
		panic();

	if (!tee_mm_addr_is_within_range(&tee_mmu_virt_kmap, (vaddr_t)va))
		return TEE_ERROR_ACCESS_DENIED;

	n = core_mmu_va2idx(&tbl_info, (vaddr_t)va);
	core_mmu_get_entry(&tbl_info, n, &npa, &nattr);
	if (!(nattr & TEE_MATTR_VALID_BLOCK))
		return TEE_ERROR_ACCESS_DENIED;

	block_offset = core_mmu_get_block_offset(&tbl_info, (vaddr_t)va);
	*pa = (void *)(npa + block_offset);

	if (attr)
		*attr = nattr;

	return TEE_SUCCESS;
}

TEE_Result tee_mmu_kmap_va2pa_helper(void *va, void **pa)
{
	return tee_mmu_kmap_va2pa_attr(va, pa, NULL);
}

bool tee_mmu_kmap_is_mapped(void *va, size_t len)
{
	tee_vaddr_t a = (tee_vaddr_t)va;
	tee_mm_entry_t *mm = tee_mm_find(&tee_mmu_virt_kmap, a);

	if (mm == NULL)
		return false;

	if ((a + len) > (tee_mm_get_smem(mm) + tee_mm_get_bytes(mm)))
		return false;

	return true;
}

void teecore_init_ta_ram(void)
{
	vaddr_t s;
	vaddr_t e;

	/* get virtual addr/size of RAM where TA are loaded/executedNSec
	 * shared mem allcated from teecore */
	core_mmu_get_mem_by_type(MEM_AREA_TA_RAM, &s, &e);

	TEE_ASSERT((s & (CORE_MMU_USER_CODE_SIZE - 1)) == 0);
	TEE_ASSERT((e & (CORE_MMU_USER_CODE_SIZE - 1)) == 0);
	/* extra check: we could rely on  core_mmu_get_mem_by_type() */
	TEE_ASSERT(tee_vbuf_is_sec(s, e - s) == true);

	TEE_ASSERT(tee_mm_is_empty(&tee_mm_sec_ddr));

	/* remove previous config and init TA ddr memory pool */
	tee_mm_final(&tee_mm_sec_ddr);
	tee_mm_init(&tee_mm_sec_ddr, s, e, CORE_MMU_USER_CODE_SHIFT,
		    TEE_MM_POOL_NO_FLAGS);
}

void teecore_init_pub_ram(void)
{
	vaddr_t s;
	vaddr_t e;
	unsigned int nsec_tee_size = 32 * 1024;

	/* get virtual addr/size of NSec shared mem allcated from teecore */
	core_mmu_get_mem_by_type(MEM_AREA_NSEC_SHM, &s, &e);

	TEE_ASSERT(s < e);
	TEE_ASSERT((s & SMALL_PAGE_MASK) == 0);
	TEE_ASSERT((e & SMALL_PAGE_MASK) == 0);
	/* extra check: we could rely on  core_mmu_get_mem_by_type() */
	TEE_ASSERT(tee_vbuf_is_non_sec(s, e - s) == true);

	/*
	 * 32kByte first bytes are allocated from teecore.
	 * Remaining is under control of the NSec allocator.
	 */
	TEE_ASSERT((e - s) > nsec_tee_size);

	TEE_ASSERT(tee_mm_is_empty(&tee_mm_pub_ddr));
	tee_mm_final(&tee_mm_pub_ddr);
	tee_mm_init(&tee_mm_pub_ddr, s, s + nsec_tee_size, SMALL_PAGE_SHIFT,
		    TEE_MM_POOL_NO_FLAGS);

	s += nsec_tee_size;
	default_nsec_shm_paddr = s;
	default_nsec_shm_size = e - s;
}

void *tee_mmu_ioremap(tee_paddr_t pa __unused, size_t len __unused)
{
	/* return (void *)ioremap((void *)pa, len); */
	return (void *)NULL;
}

void tee_mmu_iounmap(void *va __unused)
{
	/* linux API */
	/* iounmap(va); */
}

static uint32_t mattr_to_teesmc_cache_attr(uint32_t mattr)
{
	uint32_t attr = 0;

	if (mattr & TEE_MATTR_I_WRITE_THR)
		attr |= TEESMC_ATTR_CACHE_I_WRITE_THR;
	if (mattr & TEE_MATTR_I_WRITE_BACK)
		attr |= TEESMC_ATTR_CACHE_I_WRITE_BACK;
	if (mattr & TEE_MATTR_O_WRITE_THR)
		attr |= TEESMC_ATTR_CACHE_O_WRITE_THR;
	if (mattr & TEE_MATTR_O_WRITE_BACK)
		attr |= TEESMC_ATTR_CACHE_O_WRITE_BACK;

	return attr;
}

uint32_t tee_mmu_kmap_get_cache_attr(void *va)
{
	TEE_Result res;
	void *pa;
	uint32_t attr;

	res = tee_mmu_kmap_va2pa_attr(va, &pa, &attr);
	assert(res == TEE_SUCCESS);

	return mattr_to_teesmc_cache_attr(attr);
}


uint32_t tee_mmu_user_get_cache_attr(struct tee_ta_ctx *ctx, void *va)
{
	TEE_Result res;
	paddr_t pa;
	uint32_t attr;

	res = tee_mmu_user_va2pa_attr(ctx, va, &pa, &attr);
	assert(res == TEE_SUCCESS);

	return mattr_to_teesmc_cache_attr(attr);
}
