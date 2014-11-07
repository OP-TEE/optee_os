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

#include <arm32.h>
#include <kernel/util.h>
#include <kernel/tee_common.h>
#include <mm/tee_mmu.h>
#include <mm/tee_mmu_unpg.h>
#include <mm/tee_mmu_types.h>
#include <mm/tee_mmu_defs.h>
#include <user_ta_header.h>
#include <mm/tee_mm_def.h>
#include <mm/tee_mm.h>
#include "tee_api_types.h"
#include <kernel/tee_ta_manager_unpg.h>
#include <kernel/tee_misc.h>
#include <kernel/tee_core_trace.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <mm/tee_mmu_io.h>
#include <sm/teesmc.h>
#include <kernel/tz_ssvce.h>
#include <kernel/panic.h>

#define TEE_MMU_PAGE_TEX_SHIFT 6

/* MMU table page flags */
#define TEE_MMU_PAGE_NG (1 << 11)
#define TEE_MMU_PAGE_S (1 << 10)
#define TEE_MMU_PAGE_AP2 (1 << 9)
#define TEE_MMU_PAGE_TEX(x) (x << TEE_MMU_PAGE_TEX_SHIFT)
#define TEE_MMU_PAGE_AP1 (1 << 5)
#define TEE_MMU_PAGE_AP0 (1 << 4)
#define TEE_MMU_PAGE_C (1 << 3)
#define TEE_MMU_PAGE_B (1 << 2)
#define TEE_MMU_PAGE (1 << 1)
#define TEE_MMU_PAGE_XN (1 << 0)

#define TEE_MMU_PAGE_CACHE_MASK                             \
		(TEE_MMU_PAGE_TEX(7) | TEE_MMU_PAGE_C | TEE_MMU_PAGE_B)

#define TEE_MMU_PAGE_MASK ((1 << 12) - 1)

/* For legacy */
#define TEE_MMU_PAGE_LEGACY 0

/* MMU table section flags */
#define TEE_MMU_SECTION_NS (1 << 19)
#define TEE_MMU_SECTION_NG (1 << 17)
#define TEE_MMU_SECTION_S  (1 << 16)
#define TEE_MMU_SECTION_AP2 (1 << 15)
#define TEE_MMU_SECTION_TEX(x) (x << 12)
#define TEE_MMU_SECTION_AP1 (1 << 11)
#define TEE_MMU_SECTION_AP0 (1 << 10)
#define TEE_MMU_SECTION_DOMAIN(x) (x << 5)
#define TEE_MMU_SECTION_XN (1 << 4)
#define TEE_MMU_SECTION_C (1 << 3)
#define TEE_MMU_SECTION_B (1 << 2)
#define TEE_MMU_SECTION (1 << 1)

/* User data, no cache attributes */
#define TEE_MMU_SECTION_UDATA						\
	(TEE_MMU_SECTION_NG | TEE_MMU_SECTION_S |			\
	TEE_MMU_SECTION_AP1 | TEE_MMU_SECTION_AP0 | TEE_MMU_SECTION_XN |\
	TEE_MMU_SECTION_DOMAIN(1) | TEE_MMU_SECTION)

/* User code, no cache attributes */
#define TEE_MMU_SECTION_UCODE						\
	(TEE_MMU_SECTION_NG | TEE_MMU_SECTION_S |			\
	TEE_MMU_SECTION_AP1 | TEE_MMU_SECTION_AP0 |			\
	TEE_MMU_SECTION_DOMAIN(1) | TEE_MMU_SECTION)

/* Kernel data, global, privonly access, no exec, no cache attributes */
#define TEE_MMU_SECTION_KDATA						\
	(TEE_MMU_SECTION_S |						\
	TEE_MMU_SECTION_AP0 | TEE_MMU_SECTION_XN |			\
	TEE_MMU_SECTION_DOMAIN(1) | TEE_MMU_SECTION)

/* Kernel data, global, privonly access, no exec, no cache attributes */
#define TEE_MMU_SECTION_KCODE						\
	(TEE_MMU_SECTION_S |						\
	TEE_MMU_SECTION_AP0 |						\
	TEE_MMU_SECTION_DOMAIN(1) | TEE_MMU_SECTION)

/* Outer & Inner Write-Back, Write-Allocate. Default cache settings */
#define TEE_MMU_SECTION_CACHEMASK					\
		(TEE_MMU_SECTION_TEX(7) | TEE_MMU_SECTION_C | TEE_MMU_SECTION_B)
#define TEE_MMU_SECTION_OIWBWA						\
		(TEE_MMU_SECTION_TEX(1) | TEE_MMU_SECTION_C | TEE_MMU_SECTION_B)
#define TEE_MMU_SECTION_NOCACHE						\
		TEE_MMU_SECTION_TEX(1)

#define TEE_MMU_KL2_ENTRY(page_num) \
	    (*(uint32_t *)(SEC_VIRT_MMU_L2_BASE + ((uint32_t)(page_num)) * 4))

#define TEE_MMU_UL1_ENTRY(page_num) \
	    (*(uint32_t *)(TEE_MMU_UL1_BASE + ((uint32_t)(page_num)) * 4))

/* Extract AP[2] and AP[1:0] */
#define TEE_MMU_L1_AP(e) (((e >> 13) & 1) | ((e >> 10) & 3))

#define TEE_MMU_AP_USER_RO  0x02
#define TEE_MMU_AP_USER_RW  0x03

/* Support for 31 concurrent sessions */
static uint32_t g_asid = 0xffffffff;

static tee_mm_pool_t tee_mmu_virt_kmap;

static uint32_t tee_mmu_get_io_size(const struct tee_ta_param *param)
{
	uint32_t i;
	uint32_t res = 0;

	for (i = 0; i < 4; i++) {
		uint32_t param_type = TEE_PARAM_TYPE_GET(param->types, i);

		if ((param_type == TEE_PARAM_TYPE_MEMREF_INPUT ||
		     param_type == TEE_PARAM_TYPE_MEMREF_OUTPUT ||
		     param_type == TEE_PARAM_TYPE_MEMREF_INOUT) &&
		    param->params[i].memref.size != 0) {
			res +=
			    ((((uint32_t) param->params[i].memref.
			       buffer & SECTION_MASK) +
			      param->params[i].memref.size) >> SECTION_SHIFT) +
			    1;
		}
	}

	return res;
}

/*
 * tee_mmu_is_mapped - Check if range defined by input params is mapped.
 */
static bool tee_mmu_is_mapped(const struct tee_ta_ctx *ctx, const paddr_t addr,
			      const uint32_t length, const uint32_t type)
{
	size_t nbr_sections;
	size_t n;
	uint32_t *t;
	void *va;

	if (!ctx || !ctx->mmu || !ctx->mmu->table)
		return false;	/* No user mapping initialized */

	if (((addr + length) >> SECTION_SHIFT) > ctx->mmu->size)
		return false;	/* Range too large to be mapped */

	/* Try to look up start of range */
	if (tee_mmu_user_pa2va(ctx, (void *)addr, &va))
		return false;

	/* Assign the base section */
	t = ctx->mmu->table + ((vaddr_t)va >> SECTION_SHIFT);

	/*
	 * Check all sections maps contigous memory and have the correct
	 * type.
	 */
	nbr_sections = (((addr & SECTION_MASK) + length) >> SECTION_SHIFT) + 1;
	for (n = 0; n < nbr_sections; n++) {
		if ((t[n] & SECTION_MASK) != type)
			return false;	/* Incorrect type */

		if (t[n] >> SECTION_SHIFT != (addr >> SECTION_SHIFT) + n)
			return false;	/* PA doesn't match */
	}

	return true;
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

	ctx->mmu = malloc(sizeof(tee_mmu_info_t));
	if (ctx->mmu) {
		tee_mmu_info_t *p = ctx->mmu;
		p->table = 0;
		p->size = 0;
	} else {
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	return TEE_SUCCESS;
}

static TEE_Result tee_mmu_map_io(struct tee_ta_ctx *ctx, uint32_t **buffer,
				 const uint32_t vio, struct tee_ta_param *param)
{
	uint32_t i;
	uint32_t vi_offset = vio;
	TEE_Result res = TEE_SUCCESS;
	uint32_t nbr_sections, py_offset, v, section, sect_prot;

	/* Map IO buffers in public memory */
	for (i = 0; i < 4; i++) {
		uint32_t param_type = TEE_PARAM_TYPE_GET(param->types, i);
		TEE_Param *p = &param->params[i];

		if ((!((param_type == TEE_PARAM_TYPE_MEMREF_INPUT) ||
		       (param_type == TEE_PARAM_TYPE_MEMREF_OUTPUT) ||
		       (param_type == TEE_PARAM_TYPE_MEMREF_INOUT))) ||
		    (p->memref.size == 0))
			    continue;

		nbr_sections =
		    (((uint32_t)p->memref.buffer + p->memref.size) >> SECTION_SHIFT) + 1;
		py_offset = (uint32_t) p->memref.buffer >> SECTION_SHIFT;
		nbr_sections -= py_offset;
		v = ((vi_offset << SECTION_SHIFT) +
			      ((uint32_t) p->memref.buffer & SECTION_MASK));
		section = 0;

		if ((ctx->flags & TA_FLAG_USER_MODE) ==
		    TA_FLAG_USER_MODE) {
			sect_prot = TEE_MMU_SECTION_UDATA;
		} else {
			sect_prot = TEE_MMU_SECTION_KDATA;
		}
#ifdef PAGER_DEBUG_PRINT
		DMSG("tee_mmu_map: i 0x%x ph %p -> v %p\n nbr_sections %u", i,
		     p->memref.buffer, v, nbr_sections);
#endif
		/* Set NS bit if buffer is not secure */
		if (tee_pbuf_is_non_sec
		    (p->memref.buffer, p->memref.size) == true) {
			sect_prot |= TEE_MMU_SECTION_NS;
		} else {
			/*
			 * TODO
			 * Security checks shouldn't be done here,
			 * tee_ta_verify_param() should take care of that.
			 */
#if 0
			/*
			 * If secure, check here if security level is
			 * reached. This operation is likely to be
			 * platform dependent.
			 */

			/* case STTEE on Orly2: it has to be TEE external DDR */
			if (core_pbuf_is(CORE_MEM_EXTRAM,
					(tee_paddr_t) p->memref.buffer,
					p->memref.size) == false)
				return TEE_ERROR_SECURITY;
#endif
		}

		/*
		 * Configure inner and outer cache settings.
		 */
		sect_prot &= ~TEE_MMU_SECTION_CACHEMASK;
		sect_prot |= TEE_MMU_SECTION_TEX(4);
		if (param->param_attr[i] & TEESMC_ATTR_CACHE_O_WRITE_THR)
			sect_prot |= TEE_MMU_SECTION_TEX(2);
		if (param->param_attr[i] & TEESMC_ATTR_CACHE_I_WRITE_BACK)
			sect_prot |= TEE_MMU_SECTION_TEX(1);
		if (param->param_attr[i] & TEESMC_ATTR_CACHE_O_WRITE_THR)
			sect_prot |= TEE_MMU_SECTION_C;
		if (param->param_attr[i] & TEESMC_ATTR_CACHE_O_WRITE_BACK)
			sect_prot |= TEE_MMU_SECTION_B;

		if (((sect_prot & TEE_MMU_SECTION_NS) == TEE_MMU_SECTION_NS) &&
		    ((sect_prot & TEE_MMU_SECTION_XN) == 0)) {
			EMSG("invalid map config: nsec mem map as executable!");
			sect_prot |= TEE_MMU_SECTION_XN;
		}

		if (tee_mmu_is_mapped(ctx, (uint32_t) p->memref.buffer,
				      p->memref.size, sect_prot)) {
			res = tee_mmu_user_pa2va(ctx, p->memref.buffer,
						 &p->memref.buffer);
			if (res != TEE_SUCCESS)
				return res;
		} else {
			p->memref.buffer = (void *)v;

			while (section < nbr_sections) {
				**buffer =
				    ((section + py_offset) << SECTION_SHIFT) |
						sect_prot;
				(*buffer)++;
				section++;
			}

			vi_offset += nbr_sections;
		}
	}

	return res;
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
	uint32_t py_offset;
	paddr_t p;
	uintptr_t smem;
	uint32_t *buffer;
	uint32_t section = 0, section_cnt = 0;

	TEE_ASSERT((ctx->flags & TA_FLAG_EXEC_DDR) != 0);

	ctx->mmu->size = tee_mm_get_size(ctx->mm_heap_stack) +
	    tee_mm_get_size(ctx->mm) + tee_mmu_get_io_size(param) +
	    TEE_DDR_VLOFFSET;

	if (ctx->mmu->size > TEE_MMU_UL1_NUM_ENTRIES) {
		res = TEE_ERROR_EXCESS_DATA;
		goto exit;
	}

	if (ctx->mmu->table)
		free(ctx->mmu->table);

	ctx->mmu->table = malloc(ctx->mmu->size * 4);
	if (ctx->mmu->table == NULL) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto exit;
	}
	memset(ctx->mmu->table, 0, ctx->mmu->size * 4);

	/*
	 * Map heap and stack
	 */
	smem = tee_mm_get_smem(ctx->mm_heap_stack);
	if (core_va2pa((void *)smem, &p)) {
		res = TEE_ERROR_SECURITY;
		goto exit;
	}

	py_offset = (uint32_t)p >> SECTION_SHIFT;

	buffer = (uint32_t *)ctx->mmu->table + TEE_DDR_VLOFFSET;
	while (section < tee_mm_get_size(ctx->mm_heap_stack)) {
		*buffer++ = ((section++ + py_offset) << SECTION_SHIFT) |
		    TEE_MMU_SECTION_UDATA | TEE_MMU_SECTION_OIWBWA;
		section_cnt++;
	}

	/*
	 * Map code
	 */
	smem = tee_mm_get_smem(ctx->mm);
	if (core_va2pa((void *)smem, &p)) {
		res = TEE_ERROR_SECURITY;
		goto exit;
	}

	py_offset = (uint32_t) p >> SECTION_SHIFT;

	section = 0;
	while (section < tee_mm_get_size(ctx->mm)) {
		*buffer++ = ((section++ + py_offset) << SECTION_SHIFT) |
		    (TEE_MMU_SECTION_UCODE | TEE_MMU_SECTION_OIWBWA);
		section_cnt++;
	}

	ctx->mmu->ta_private_vmem_start = TEE_DDR_VLOFFSET << SECTION_SHIFT;
	ctx->mmu->ta_private_vmem_end = (TEE_DDR_VLOFFSET + section_cnt) <<
					SECTION_SHIFT;

	/*
	 * Map io parameters
	 */
	res =
	    tee_mmu_map_io(ctx, &buffer,
			   ((uint32_t) buffer - (uint32_t) ctx->mmu->table) / 4,
			   param);

exit:
	if (res != TEE_SUCCESS) {
		free(ctx->mmu->table);
		ctx->mmu->table = NULL;
		ctx->mmu->size = 0;
	}

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
		tee_mmu_info_t *p = ctx->mmu;
		free(p->table);
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
				  const uint32_t kaddr, uint32_t *uaddr)
{
	uint32_t i = 0;
	uint32_t pa;

	if (core_va2pa((void *)kaddr, &pa))
		return TEE_ERROR_SECURITY;

	while (i < ctx->mmu->size) {
		if ((pa & (~SECTION_MASK)) ==
		    (ctx->mmu->table[i] & (~SECTION_MASK))) {
			*uaddr = (i << SECTION_SHIFT) + (kaddr & SECTION_MASK);
			return TEE_SUCCESS;
		}
		i++;
	}

	return TEE_ERROR_ITEM_NOT_FOUND;
}

TEE_Result tee_mmu_user_va2pa_helper(const struct tee_ta_ctx *ctx, void *ua,
				     paddr_t *pa)
{
	uint32_t n = (uint32_t) ua >> SECTION_SHIFT;

	if (n >= ctx->mmu->size)
		return TEE_ERROR_ACCESS_DENIED;

	*pa = (ctx->mmu->table[n] & ~SECTION_MASK) |
		       ((uint32_t) ua & SECTION_MASK);
	return TEE_SUCCESS;
}

/* */
TEE_Result tee_mmu_user_pa2va_helper(const struct tee_ta_ctx *ctx, void *pa,
				     void **va)
{
	uint32_t i = 0;

	while (i < ctx->mmu->size) {
		if (ctx->mmu->table[i] != 0 &&
		    (uint32_t) pa >= (ctx->mmu->table[i] & ~SECTION_MASK) &&
		    (uint32_t) pa < ((ctx->mmu->table[i] & ~SECTION_MASK)
				     + (1 << SECTION_SHIFT))) {
			*va = (void *)((i << SECTION_SHIFT) +
				       ((uint32_t) pa & SECTION_MASK));
			return TEE_SUCCESS;
		}
		i++;
	}
	return TEE_ERROR_ACCESS_DENIED;
}

TEE_Result tee_mmu_check_access_rights(struct tee_ta_ctx *ctx,
				       uint32_t flags, tee_uaddr_t uaddr,
				       size_t len)
{
	tee_uaddr_t a;
	uint32_t param_section;

	/* Address wrap */
	if (uaddr + len < uaddr)
		return TEE_ERROR_ACCESS_DENIED;

	param_section = TEE_DDR_VLOFFSET +
	    tee_mm_get_size(ctx->mm_heap_stack) + tee_mm_get_size(ctx->mm);

	for (a = uaddr; a < (uaddr + len); a += SECTION_SIZE) {
		uint32_t n = a >> SECTION_SHIFT;

		if (n >= ctx->mmu->size)
			return TEE_ERROR_ACCESS_DENIED;

		if ((flags & TEE_MEMORY_ACCESS_ANY_OWNER) !=
		    TEE_MEMORY_ACCESS_ANY_OWNER && n >= param_section) {
			paddr_t pa;
			TEE_Result res =
			    tee_mmu_user_va2pa(ctx, (void *)a, &pa);

			if (res != TEE_SUCCESS)
				return res;
			/*
			 * Parameters are shared with normal world if they
			 * aren't in secure DDR.
			 *
			 * If the parameters are in secure DDR it's because one
			 * TA is invoking another TA and in that case there's
			 * new memory allocated privately for the paramters to
			 * this TA.
			 */
			if (!tee_mm_addr_is_within_range(&tee_mm_sec_ddr, pa))
				return TEE_ERROR_ACCESS_DENIED;
		}

		/* Check Access Protection from L1 entry */
		switch (TEE_MMU_L1_AP(ctx->mmu->table[n])) {
		case TEE_MMU_AP_USER_RO:
			if ((flags & TEE_MEMORY_ACCESS_WRITE) != 0)
				return TEE_ERROR_ACCESS_DENIED;
			break;
		case TEE_MMU_AP_USER_RW:
			break;
		default:
			return TEE_ERROR_ACCESS_DENIED;
		}
	}

	return TEE_SUCCESS;
}

void tee_mmu_set_ctx(struct tee_ta_ctx *ctx)
{
	if (ctx == NULL) {
		tee_mmu_switch(read_ttbr1(), 0);
	} else {
		paddr_t base = core_mmu_get_ul1_ttb_pa();
		void *va = (void *)core_mmu_get_ul1_ttb_va();

		/* copy uTA mapping at begning of mmu table */
		memcpy(va, ctx->mmu->table, ctx->mmu->size * 4);

		/* Change ASID to new value */
		tee_mmu_switch(base | TEE_MMU_DEFAULT_ATTRS, ctx->context);
	}
	core_tlb_maintenance(TLBINV_CURRENT_ASID, 0);
}

uintptr_t tee_mmu_get_load_addr(const struct tee_ta_ctx *const ctx)
{
	TEE_ASSERT((ctx->flags & TA_FLAG_EXEC_DDR) != 0);

	return (TEE_DDR_VLOFFSET + tee_mm_get_size(ctx->mm_heap_stack)) <<
	    SECTION_SHIFT;
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
	tee_vaddr_t s = TEE_MMU_KMAP_START_VA;
	tee_vaddr_t e = TEE_MMU_KMAP_END_VA;

	if (!tee_mm_init(&tee_mmu_virt_kmap, s, e, SECTION_SHIFT,
			 TEE_MM_POOL_NO_FLAGS)) {
		DMSG("Failed to init kmap. Trap CPU!");
		TEE_ASSERT(0);
	}
}

static uint32_t *get_kmap_l1_base(void)
{
	uint32_t *l1 = (uint32_t *)core_mmu_get_main_ttb_va();

	/* Return address where kmap entries start */
	return l1 + TEE_MMU_KMAP_OFFS;
}

TEE_Result tee_mmu_kmap_helper(tee_paddr_t pa, size_t len, void **va)
{
	tee_mm_entry_t *mm;
	size_t n;
	uint32_t *l1 = get_kmap_l1_base();
	uint32_t py_offset = (uint32_t) pa >> SECTION_SHIFT;
	uint32_t pa_s = ROUNDDOWN(pa, SECTION_SIZE);
	uint32_t pa_e = ROUNDUP(pa + len, SECTION_SIZE);
	uint32_t flags;

	mm = tee_mm_alloc(&tee_mmu_virt_kmap, pa_e - pa_s);
	if (mm == NULL)
		return TEE_ERROR_OUT_OF_MEMORY;

	/*
	 * check memory attributes (must either secure or unsecured)
	 *
	 * Warning: platform depedancy: was is cached and uncached.
	 */
	flags = TEE_MMU_SECTION_KDATA;
	if (tee_pbuf_is_sec(pa, len) == true) {
		flags |= TEE_MMU_SECTION_OIWBWA;
	} else if (tee_pbuf_is_non_sec(pa, len) == true) {
		flags |= TEE_MMU_SECTION_NS;
		if (core_mmu_is_shm_cached())
			flags |= TEE_MMU_SECTION_OIWBWA;
		else
			flags |= TEE_MMU_SECTION_NOCACHE;
	} else {
		return TEE_ERROR_GENERIC;
	}

	for (n = 0; n < tee_mm_get_size(mm); n++)
		l1[n + tee_mm_get_offset(mm)] =
		    ((n + py_offset) << SECTION_SHIFT) | flags;

	core_tlb_maintenance(TLBINV_UNIFIEDTLB, 0);

	*va = (void *)(tee_mm_get_smem(mm) + (pa & SECTION_MASK));
	return TEE_SUCCESS;
}

void tee_mmu_kunmap(void *va, size_t len)
{
	size_t n;
	tee_mm_entry_t *mm;
	uint32_t *l1 = get_kmap_l1_base();

	mm = tee_mm_find(&tee_mmu_virt_kmap, (uint32_t)va);
	if (mm == NULL || len > tee_mm_get_bytes(mm))
		return;		/* Invalid range, not much to do */

	/* Clear the mmu entries */
	for (n = 0; n < tee_mm_get_size(mm); n++)
		l1[n + tee_mm_get_offset(mm)] = 0;

	core_tlb_maintenance(TLBINV_UNIFIEDTLB, 0);
	tee_mm_free(mm);
}

TEE_Result tee_mmu_kmap_pa2va_helper(void *pa, void **va)
{
	size_t n;
	uint32_t *l1 = (uint32_t *)core_mmu_get_main_ttb_va();

	for (n = TEE_MMU_KMAP_OFFS;
	     n < (TEE_MMU_KMAP_OFFS + TEE_MMU_KMAP_NUM_ENTRIES); n++) {
		if (l1[n] != 0 &&
		    (uint32_t)pa >= (l1[n] & ~SECTION_MASK) &&
		    (uint32_t)pa < ((l1[n] & ~SECTION_MASK)
				     + (1 << SECTION_SHIFT))) {
			*va = (void *)((n << SECTION_SHIFT) +
				       ((uint32_t)pa & SECTION_MASK));
			return TEE_SUCCESS;
		}
	}
	return TEE_ERROR_ACCESS_DENIED;
}

TEE_Result tee_mmu_kmap_va2pa_helper(void *va, void **pa)
{
	uint32_t n = (uint32_t)va >> SECTION_SHIFT;
	uint32_t *l1 = (uint32_t *)core_mmu_get_main_ttb_va();

	if (n < TEE_MMU_KMAP_OFFS &&
	    n >= (TEE_MMU_KMAP_OFFS + TEE_MMU_KMAP_NUM_ENTRIES))
		return TEE_ERROR_ACCESS_DENIED;
	*pa = (void *)((l1[n] & ~SECTION_MASK) | ((uint32_t)va & SECTION_MASK));

	return TEE_SUCCESS;
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

bool tee_mmu_is_kernel_mapping(void)
{
	/* TODO use ASID instead */
	return read_ttbr0() == read_ttbr1();
}

void teecore_init_ta_ram(void)
{
	unsigned int s, e;

	/* get virtual addr/size of RAM where TA are loaded/executedNSec
	 * shared mem allcated from teecore */
	core_mmu_get_mem_by_type(MEM_AREA_TA_RAM, &s, &e);

	TEE_ASSERT((s & (SECTION_SIZE - 1)) == 0);
	TEE_ASSERT((e & (SECTION_SIZE - 1)) == 0);
	/* extra check: we could rely on  core_mmu_get_mem_by_type() */
	TEE_ASSERT(tee_vbuf_is_sec(s, e - s) == true);

	TEE_ASSERT(tee_mm_is_empty(&tee_mm_sec_ddr));

	/* remove previous config and init TA ddr memory pool */
	tee_mm_final(&tee_mm_sec_ddr);
	tee_mm_init(&tee_mm_sec_ddr, s, e, SECTION_SHIFT, TEE_MM_POOL_NO_FLAGS);
}

void teecore_init_pub_ram(void)
{
	unsigned int s, e;
	unsigned int nsec_tee_size = 32 * 1024;

	/* get virtual addr/size of NSec shared mem allcated from teecore */
	core_mmu_get_mem_by_type(MEM_AREA_NSEC_SHM, &s, &e);

	TEE_ASSERT(s < e);
	TEE_ASSERT((s & (SECTION_SIZE - 1)) == 0);
	TEE_ASSERT((e & (SECTION_SIZE - 1)) == 0);
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

static uint32_t section_to_teesmc_cache_attr(uint32_t sect)
{

	if (sect & TEE_MMU_SECTION_TEX(4)) {
		uint32_t attr = 0;

		if (sect & TEE_MMU_SECTION_TEX(2))
			attr |= TEESMC_ATTR_CACHE_O_WRITE_THR;
		if (sect & TEE_MMU_SECTION_TEX(1))
			attr |= TEESMC_ATTR_CACHE_I_WRITE_BACK;
		if (sect & TEE_MMU_SECTION_C)
			attr |= TEESMC_ATTR_CACHE_O_WRITE_THR;
		if (sect & TEE_MMU_SECTION_B)
			attr |= TEESMC_ATTR_CACHE_O_WRITE_BACK;
		assert(attr == TEESMC_ATTR_CACHE_DEFAULT);
		return attr;
	}

	switch (sect & TEE_MMU_SECTION_CACHEMASK) {
	/* outer and inner write-back */
	/* no write-allocate */
	case TEE_MMU_SECTION_TEX(0) | TEE_MMU_SECTION_B:
	/* write-allocate */
	case TEE_MMU_SECTION_TEX(1) | TEE_MMU_SECTION_B | TEE_MMU_SECTION_C:
		return TEESMC_ATTR_CACHE_I_WRITE_BACK |
		       TEESMC_ATTR_CACHE_O_WRITE_BACK;

	/* outer and inner write-through */
	case TEE_MMU_SECTION_TEX(0) | TEE_MMU_SECTION_C:
		panic();
		return TEESMC_ATTR_CACHE_I_WRITE_THR |
		       TEESMC_ATTR_CACHE_O_WRITE_THR;

	/* outer and inner no-cache */
	case TEE_MMU_SECTION_TEX(1):
		panic();
		return TEESMC_ATTR_CACHE_I_NONCACHE |
		       TEESMC_ATTR_CACHE_O_NONCACHE;
	default:
		panic();
	}
}

uint32_t tee_mmu_kmap_get_cache_attr(void *va)
{
	uint32_t n = (vaddr_t)va >> SECTION_SHIFT;
	uint32_t *l1 = (uint32_t *)core_mmu_get_main_ttb_va();

	assert(n >= TEE_MMU_KMAP_OFFS &&
	       n < (TEE_MMU_KMAP_OFFS + TEE_MMU_KMAP_NUM_ENTRIES));

	return section_to_teesmc_cache_attr(l1[n]);
}

uint32_t tee_mmu_user_get_cache_attr(struct tee_ta_ctx *ctx, void *va)
{
	uint32_t n = (vaddr_t)va >> SECTION_SHIFT;

	assert(n < ctx->mmu->size);

	return section_to_teesmc_cache_attr(ctx->mmu->table[n]);
}
