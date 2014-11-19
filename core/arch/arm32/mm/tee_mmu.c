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
#include <util.h>
#include <kernel/tee_common.h>
#include <mm/tee_mmu.h>
#include <mm/tee_mmu_unpg.h>
#include <mm/tee_mm_def.h>
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
#include <mm/tee_arm32_mmu.h>
#include <sm/teesmc.h>
#include <kernel/tz_ssvce.h>
#include <kernel/panic.h>

/* Support for 31 concurrent sessions */
static uint32_t g_asid = 0xffffffff;

static tee_mm_pool_t tee_mmu_virt_kmap;

/*
 * Prepare some static configuration of the TA instance mapping
 */
TEE_Result tee_mmu_init(struct tee_ta_ctx *ctx)
{
	uint32_t asid = 1;

	if (!ctx->context) {
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

	/* prepare user TA mapping support */
	return tee_mmu_init_with_asid(ctx, asid);
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

	tee_mmu_final_reset(ctx);
}

void tee_mmu_set_ctx(struct tee_ta_ctx *ctx)
{
	if (ctx == NULL) {
		tee_mmu_switch(read_ttbr1(), 0);
	} else {
		paddr_t base = core_mmu_get_ul1_ttb_pa();
		void *va = (void *)core_mmu_get_ul1_ttb_va();

		/* copy uTA mapping at beginning of mmu table */
		tee_mmu_copy_table(va, ctx);

		/* Change ASID to new value */
		tee_mmu_switch(base | TEE_MMU_DEFAULT_ATTRS, ctx->context);
	}
	core_tlb_maintenance(TLBINV_CURRENT_ASID, 0);
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

/* dynamic map in teecore */
TEE_Result tee_mmu_kmap_helper(tee_paddr_t pa, size_t len, void **va)
{
	tee_mm_entry_t *mm;
	size_t n;
	uint32_t *l1 = get_kmap_l1_base();
	uint32_t py_offset = (uint32_t)pa >> SECTION_SHIFT;
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

/* dynamic unmap in teecore */
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

/* pa/va conversion on dynamic map in teecore */
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

/* va/pa conversion on dynamic map in teecore */
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

/* dynamic map in teecore */
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

#if (CFG_TEE_FW_DEBUG == 1)
	{
		/* load some non null values in TA RAM */
		uint32_t *p = (uint32_t *)s;

		while (p < (uint32_t *)e)
			*p++ = 0x55555555;
	}
#endif

	TEE_ASSERT((s & (SECTION_SIZE - 1)) == 0);
	TEE_ASSERT((e & (SECTION_SIZE - 1)) == 0);
	/* extra check: we could rely on  core_mmu_get_mem_by_type() */
	TEE_ASSERT(tee_vbuf_is_sec(s, e - s) == true);

	TEE_ASSERT(tee_mm_is_empty(&tee_mm_sec_ddr));

	/* remove previous config and init TA ddr memory pool */
	tee_mm_final(&tee_mm_sec_ddr);
	tee_mm_init(&tee_mm_sec_ddr, s, e,
		    tee_mmu_get_page_shift(), TEE_MM_POOL_NO_FLAGS);
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
