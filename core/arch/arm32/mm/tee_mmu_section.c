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
 * For information, refer to documentation/user-ta-armv7-memory-mapping.txt
 */

#include <assert.h>
#include <stdlib.h>

#include <kernel/tee_common.h>
#include <mm/tee_mmu.h>
#include <mm/tee_mmu_unpg.h>
#include <mm/tee_mmu_defs.h>
#include <user_ta_header.h>

#include <mm/tee_mm_def.h>

#include <mm/tee_mm.h>
#include <tee_api_types.h>
#include <kernel/tee_ta_manager_unpg.h>
#include <kernel/tee_misc.h>
#include <trace.h>
#include <util.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <mm/tee_mmu_io.h>
#include <mm/tee_arm32_mmu.h>
#include <sm/teesmc.h>
#include <kernel/panic.h>

/*
 * tee_mmu_info: struct to handle uTA mapping for section based mapping.
 *
 * @table: partial level1 table for uTA mapping
 * @size: size in 32bit cells of the level1 table
 * @ta_private_vstart: virtual start address of data private to TA
 * @ta_private_vend: virtual end address of data private to TA
 */
struct tee_mmu_info {
	uint32_t *table;
	uint32_t size;
	uint32_t ta_private_vstart;
	uint32_t ta_private_vend;
};

static uint32_t get_io_size(const struct tee_ta_param *param)
{
	uint32_t i;
	uint32_t res = 0;

	/* compute the nb of 1MB section for all GP params */
	for (i = 0; i < 4; i++) {
		uint32_t param_type = TEE_PARAM_TYPE_GET(param->types, i);

		if ((param_type == TEE_PARAM_TYPE_MEMREF_INPUT ||
		     param_type == TEE_PARAM_TYPE_MEMREF_OUTPUT ||
		     param_type == TEE_PARAM_TYPE_MEMREF_INOUT) &&
		     param->params[i].memref.size != 0) {
			res += 1 + ((((uint32_t)param->params[i].memref.buffer &
				SECTION_MASK) +
				param->params[i].memref.size) >> SECTION_SHIFT);
		}
	}

	return res;
}

/*
 * is_mapped - Check if range defined by input params is mapped.
 */
static bool is_mapped(const struct tee_ta_ctx *ctx, const paddr_t addr,
		      const uint32_t length, const uint32_t type)
{
	uint32_t n;
	uint32_t section_start;
	uint32_t section_end;
	uint32_t *t;
	void *va;
	struct tee_mmu_info *mmu;

	if (!ctx || !ctx->mmu)
		return false;

	mmu = ctx->mmu;
	if (!mmu->table || mmu->size < ((addr + length) >> SECTION_SHIFT))
		return false;

	/* Try to look up start of range */
	if (tee_mmu_user_pa2va(ctx, addr, &va))
		return false;

	/* Assign the base section */
	t = mmu->table + ((vaddr_t)va >> SECTION_SHIFT);

	/*
	 * Check all sections maps contiguous memory and have the correct type.
	 */
	section_start = addr >> SECTION_SHIFT;
	section_end = (addr + length - 1) >> SECTION_SHIFT;
	for (n = 0; n <= section_end - section_start; n++) {
		if ((t[n] & SECTION_MASK) != type)
			return false;	/* Incorrect type */

		if (t[n] >> SECTION_SHIFT !=
		    ((n + section_start) >> SECTION_SHIFT))
			return false;	/* PA doesn't match */
	}

	return true;
}

/*
 * Prepare some static configuration of the TA instance mapping
 */
TEE_Result tee_mmu_init_with_asid(struct tee_ta_ctx *ctx,
				  uint32_t asid __unused)
{
	ctx->mmu = malloc(sizeof(struct tee_mmu_info));
	if (ctx->mmu) {
		struct tee_mmu_info *p = ctx->mmu;

		p->table = 0;
		p->size = 0;
	} else {
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	return TEE_SUCCESS;
}

static TEE_Result map_io(struct tee_ta_ctx *ctx, uint32_t **buffer,
			 const uint32_t vio, struct tee_ta_param *param)
{
	uint32_t nbr_sections;
	uint32_t py_offset;
	uint32_t v;
	uint32_t section;
	uint32_t sect_prot;
	uint32_t vi_offset = vio;
	uint32_t i;
	paddr_t pa;
	TEE_Result res = TEE_SUCCESS;

	/* Map IO buffers in public memory */
	for (i = 0; i < 4; i++) {
		uint32_t param_type = TEE_PARAM_TYPE_GET(param->types, i);
		TEE_Param *p = &param->params[i];

		/* don't care if it's not a memory reference */
		if (!((param_type == TEE_PARAM_TYPE_MEMREF_INPUT) ||
			(param_type == TEE_PARAM_TYPE_MEMREF_OUTPUT) ||
			(param_type == TEE_PARAM_TYPE_MEMREF_INOUT)))
			continue;

		/* empty buffer => hide behind a non-NULL addr its phys addr */
		if (p->memref.size == 0) {
			p->memref.buffer = (void *)1;
			continue;
		}

		nbr_sections = ((((uint32_t)p->memref.buffer & SECTION_MASK) +
					p->memref.size) >> SECTION_SHIFT) + 1;
		py_offset = (uint32_t)p->memref.buffer >> SECTION_SHIFT;
		v = ((vi_offset << SECTION_SHIFT) +
				((uint32_t)p->memref.buffer & SECTION_MASK));
		section = 0;

		if ((ctx->flags & TA_FLAG_USER_MODE) == TA_FLAG_USER_MODE)
			sect_prot = TEE_MMU_SECTION_UDATA;
		else
			sect_prot = TEE_MMU_SECTION_KDATA;
#ifdef PAGER_DEBUG_PRINT
		DMSG("tee_mmu_map: i 0x%x ph %p -> v %p\n nbr_sections %u",
			i, p->memref.buffer, v, nbr_sections);
#endif
		/* Set NS bit if buffer is not secure */
		if (tee_pbuf_is_non_sec(p->memref.buffer, p->memref.size)) {
			sect_prot |= TEE_MMU_SECTION_NS;
		} else {
			/*
			 * If secure, check here if security level is
			 * reached. This operation is likely to be
			 * platform dependent.
			 */

			/* case STTEE on Orly2: it has to be TEE external DDR */
			if (core_pbuf_is(CORE_MEM_EXTRAM,
					(tee_paddr_t)p->memref.buffer,
					p->memref.size) == false)
				return TEE_ERROR_SECURITY;
		}

		sect_prot &= ~TEE_MMU_SECTION_CACHEMASK;
		if ((sect_prot & TEE_MMU_SECTION_NS) == TEE_MMU_SECTION_NS) {
			if (core_mmu_is_shm_cached())
				sect_prot |= TEE_MMU_SECTION_OIWBWA;
			else
				sect_prot |= TEE_MMU_SECTION_NOCACHE;
		} else
			sect_prot |= TEE_MMU_SECTION_OIWBWA;

		if (((sect_prot & TEE_MMU_SECTION_NS) == TEE_MMU_SECTION_NS) &&
				((sect_prot & TEE_MMU_SECTION_XN) == 0)) {
			EMSG("invalid map config: nsec mem map as executable!");
			sect_prot |= TEE_MMU_SECTION_XN;
		}

		if (is_mapped(ctx, (uint32_t)p->memref.buffer,
				p->memref.size, sect_prot)) {
			pa = (paddr_t)p->memref.buffer;
			res = tee_mmu_user_pa2va(ctx, pa, &p->memref.buffer);
			if (res != TEE_SUCCESS)
				return res;
		} else {
			p->memref.buffer = (void *)v;

			while (section < nbr_sections) {
				**buffer = ((section + py_offset) <<
					SECTION_SHIFT) | sect_prot;
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
	uint32_t section;
	uint32_t sect_cnt = 0;
	struct tee_mmu_info *mmu = ctx->mmu;

	TEE_ASSERT((ctx->flags & TA_FLAG_EXEC_DDR) != 0);

	mmu->size = tee_mm_get_size(ctx->mm_heap_stack) +
		    tee_mm_get_size(ctx->mm) + get_io_size(param) +
		    TEE_DDR_VLOFFSET;
	if (mmu->size > TEE_MMU_UL1_NUM_ENTRIES) {
		res = TEE_ERROR_EXCESS_DATA;
		goto exit;
	}

	if (mmu->table)
		free(mmu->table);
	mmu->table = malloc(mmu->size * 4);
	if (!mmu->table) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto exit;
	}
	memset(mmu->table, 0, mmu->size * 4);

	/* Map heap and stack */
	smem = tee_mm_get_smem(ctx->mm_heap_stack);
	if (core_va2pa((void *)smem, &p)) {
		res = TEE_ERROR_SECURITY;
		goto exit;
	}

	buffer = (uint32_t *)mmu->table + TEE_DDR_VLOFFSET;
	py_offset = (uint32_t)p >> SECTION_SHIFT;
	section = 0;
	while (section < tee_mm_get_size(ctx->mm_heap_stack))
		*buffer++ = ((section++ + py_offset) << SECTION_SHIFT) |
			    TEE_MMU_SECTION_UDATA | TEE_MMU_SECTION_OIWBWA;
	sect_cnt = section;

	/* Map code */
	smem = tee_mm_get_smem(ctx->mm);
	if (core_va2pa((void *)smem, &p)) {
		res = TEE_ERROR_SECURITY;
		goto exit;
	}

	py_offset = (uint32_t)p >> SECTION_SHIFT;
	section = 0;
	while (section < tee_mm_get_size(ctx->mm))
		*buffer++ = ((section++ + py_offset) << SECTION_SHIFT) |
			    TEE_MMU_SECTION_UCODE | TEE_MMU_SECTION_OIWBWA;
	sect_cnt += section;

	mmu->ta_private_vstart = TEE_DDR_VLOFFSET << SECTION_SHIFT;
	mmu->ta_private_vend = (TEE_DDR_VLOFFSET + sect_cnt) << SECTION_SHIFT;
	/* Map io parameters */
	res = map_io(ctx, &buffer,
		     ((uint32_t)buffer - (uint32_t)mmu->table) / 4,
		     param);

exit:
	if (res != TEE_SUCCESS) {
		free(mmu->table);
		mmu->table = NULL;
		mmu->size = 0;
	}

	return res;
}

/*
 * tee_mmu_final_reset - finalise and free ctx mmu
 */
void tee_mmu_final_reset(struct tee_ta_ctx *ctx)
{
	if (ctx->mmu) {
		struct tee_mmu_info *p = ctx->mmu;

		free(p->table);
		free(ctx->mmu);
	}
	ctx->mmu = NULL;
}

TEE_Result tee_mmu_kernel_to_user(const struct tee_ta_ctx *ctx,
				  const uint32_t kaddr, uint32_t *uaddr)
{
	uint32_t i = 0;
	paddr_t pa;
	struct tee_mmu_info *mmu = ctx->mmu;

	if (core_va2pa((void *)kaddr, &pa))
		return TEE_ERROR_SECURITY;

	while (i < mmu->size) {
		if ((pa & (~SECTION_MASK)) ==
		    (mmu->table[i] & (~SECTION_MASK))) {
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
	struct tee_mmu_info *mmu = ctx->mmu;
	uint32_t n = (uint32_t)ua >> SECTION_SHIFT;

	if (n >= mmu->size)
		return TEE_ERROR_ACCESS_DENIED;

	*pa = ((mmu->table[n] & ~SECTION_MASK) |
	       ((uint32_t)ua & SECTION_MASK));
	return TEE_SUCCESS;
}

/* */
TEE_Result tee_mmu_user_pa2va_helper(const struct tee_ta_ctx *ctx, paddr_t pa,
				     void **va)
{
	uint32_t i = 0;
	struct tee_mmu_info *mmu = ctx->mmu;

	while (i < mmu->size) {
		if (mmu->table[i] != 0 &&
		    pa >= (mmu->table[i] & ~SECTION_MASK) &&
		    pa < ((mmu->table[i] & ~SECTION_MASK) +
				    (1 << SECTION_SHIFT))) {
			*va = (void *)((i << SECTION_SHIFT) +
				       ((uint32_t)pa & SECTION_MASK));
			return TEE_SUCCESS;
		}
		i++;
	}
	return TEE_ERROR_ACCESS_DENIED;
}

uint32_t tee_mmu_user_get_cache_attr(struct tee_ta_ctx *ctx, void *va)
{
	uint32_t n = (vaddr_t)va >> SECTION_SHIFT;
	uint32_t sect;
	struct tee_mmu_info *mmu = ctx->mmu;

	/* weird way of trapping invalid address */
	assert(n < mmu->size);
	sect = mmu->table[n];

	/* TEX[2]=1 => inner/outer specific attributes */
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

TEE_Result tee_mmu_check_access_rights(const struct tee_ta_ctx *ctx,
				       uint32_t flags, tee_uaddr_t uaddr,
				       size_t len)
{
	uint32_t param_section;
	TEE_Result res;
	tee_uaddr_t a;
	struct tee_mmu_info *mmu = ctx->mmu;

	/* Address wrap */
	if (uaddr + len < uaddr)
		return TEE_ERROR_ACCESS_DENIED;

	param_section = TEE_DDR_VLOFFSET +
		tee_mm_get_size(ctx->mm_heap_stack) + tee_mm_get_size(ctx->mm);

	for (a = uaddr; a < (uaddr + len); a += SECTION_SIZE) {
		uint32_t n = a >> SECTION_SHIFT;

		if (n >= mmu->size)
			return TEE_ERROR_ACCESS_DENIED;

		if ((flags & TEE_MEMORY_ACCESS_ANY_OWNER) !=
			TEE_MEMORY_ACCESS_ANY_OWNER && n >= param_section) {
			paddr_t pa;

			res = tee_mmu_user_va2pa(ctx, (void *)a, &pa);

			if (res != TEE_SUCCESS)
				return res;
			/*
			 * Parameters are shared with normal world if they
			 * aren't in secure DDR.
			 *
			 * If the parameters are in secure DDR it's because one
			 * TA is invoking another TA and in that case there's
			 * new memory allocated privately for the parameters to
			 * this TA.
			 */
			if (!tee_mm_addr_is_within_range(&tee_mm_sec_ddr,
							(uint32_t)pa))
				return TEE_ERROR_ACCESS_DENIED;
		}

		/* Check Access Protection from L1 entry */
		switch (TEE_MMU_SECTION_AP(mmu->table[n])) {
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

/* return true only if buffer fits inside TA private memory */
bool tee_mmu_is_vbuf_inside_ta_private(const struct tee_ta_ctx *ctx,
				       const void *va, size_t size)
{
	struct tee_mmu_info *mmu = ctx->mmu;

	return core_is_buffer_inside(va, size,
			mmu->ta_private_vstart,
			mmu->ta_private_vend - mmu->ta_private_vstart);
}

/* return true only if buffer fits outside TA private memory */
bool tee_mmu_is_vbuf_outside_ta_private(const struct tee_ta_ctx *ctx,
					const void *va, size_t size)
{
	struct tee_mmu_info *mmu = ctx->mmu;

	return core_is_buffer_outside(va, size, mmu->ta_private_vstart,
			mmu->ta_private_vend - mmu->ta_private_vstart);
}

/* return true only if buffer fits outside TA private memory */
bool tee_mmu_is_vbuf_intersect_ta_private(const struct tee_ta_ctx *ctx,
					  const void *va, size_t size)
{
	struct tee_mmu_info *mmu = ctx->mmu;

	return core_is_buffer_intersect(va, size, mmu->ta_private_vstart,
			mmu->ta_private_vend - mmu->ta_private_vstart);
}

void tee_mmu_copy_table(void *va, const struct tee_ta_ctx *ctx)
{
	struct tee_mmu_info *mmu = ctx->mmu;

	memcpy(va, mmu->table, mmu->size * 4);
}

/* returns the virtual address (as seen by the TA) when TA is loaded */
uintptr_t tee_mmu_get_load_addr(const struct tee_ta_ctx *const ctx)
{
	TEE_ASSERT((ctx->flags & TA_FLAG_EXEC_DDR) != 0);
	return (TEE_DDR_VLOFFSET +
		tee_mm_get_size(ctx->mm_heap_stack)) << SECTION_SHIFT;
}

uint8_t tee_mmu_get_page_shift(void)
{
	return SECTION_SHIFT;
}

