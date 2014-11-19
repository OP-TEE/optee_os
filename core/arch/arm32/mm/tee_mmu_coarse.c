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
 * For mapping strategy info, see documentation/user-ta-armv7-memory-mapping.txt
 *
 * Following are some add info:
 *
 * The current code aims at:
 * - lowering at most cost in TEE_RAM (mainly prevent allocation of level2
 *   mmu tables.
 * - prevent teecore from requesting memory aligned allocation (l2 mmu table)
 *   at TA command invocation, where performance may be expected:
 *   - at TA instance creation (tee_mmu_init), we can spend time allocating
 *     and setting up things.
 *   - at TA invocation (tee_mmu_map), try to reuse allocated tables.
 * - pa/va conversion if based on:
 *   - va-to-pa => use cpu support (cp15 registers)
 *   - pa-to-va => brutly convert from SW info and confirm with va-to-pa.
 *
 * Mapping is based on:
 * - A partial level1 mmu table statically allocated at TA instance creation.
 *   When teecore applied the TA mapping: it is copied to efective level1 mmu
 *   table first cells.
 * - A level2 mmu table statically allocated at TA instance creation.
 *   It is used to map the TA code and data ('code/data' + 'stack/heap') based
 *   on large pages (armv7: 64kB).
 *   The remaining of the table can be used to map 'secure' memory references
 *   to be mapped using large or small page.
 * - A level2 mmu table eventually allocated at TA invocation.
 *   It is used to map "secure" coarse pages that do not fit in the l2_static
 *   free cells.
 *
 * The memory reference parameters at TA invocation can be mapped using one
 * of the 3 tables listed above:
 *   - non-secure shared memory is mapped by section in level1 table (l1_tbl).
 *   - unsafe shared memory is mapped by section in level1 table (l1_tbl).
 *   - secure memory (if caller is a TA) is always mapped by large page. Secure
 *     memory is mapped from in l2_static (if enougth room) or in l2_param, in
 *     which case, it must be allocated.
 */
#include <assert.h>
#include <stdlib.h>

#include <kernel/tee_common.h>
#include <mm/tee_mmu.h>
#include <mm/tee_mmu_unpg.h>
#include <mm/tee_mmu_defs.h>
#include <kernel/tee_ta_manager.h>
#include <kernel/tee_ta_manager_unpg.h>
#include <kernel/tee_misc.h>
#include <trace.h>
#include <util.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <mm/tee_mmu_io.h>
#include <mm/tee_arm32_mmu.h>
#include <mm/tee_mm.h>
#include <mm/tee_mm_def.h>
#include <kernel/tz_proc.h>
#include <kernel/tz_proc_def.h>
#include <sm/teesmc.h>

#define MAP_TA_LARGE_PAGE
/* #define MAP_TA_SMALL_PAGE  not supported */

#define LOG(...)
/* #define LOG(...) SMSG(__VA_ARGS__) */
/* #define LOG(...) DMSG(__VA_ARGS__) */

/* mapping attributes: flags in field 'type' of tee_mmu_l2_info */
#define UTA_TYPE_CACHED		(1 << 0)
#define UTA_TYPE_NS		(1 << 1)
#define UTA_TYPE_SECTION	(1 << 2)
#define UTA_TYPE_LARGE_PAGE	(1 << 3)
#define UTA_TYPE_SMALL_PAGE	(1 << 4)

/*
 * A L2 mmu table must covers a 1MB section aligned memory area.
 * L2 mmu table size are multiples of 1kByte.
 */
#define L2_TBL_SIZE		(256 * sizeof(uint32_t))

/* teecore offers (to allowed TA) up to 64kB mappable by 4kB pages */
#define TA_REMAP_PAGES	16
#define TA_REMAP_VSIZE	(TA_REMAP_PAGES * SMALL_PAGE_SIZE)

/*
 * struct tee_mmu_l2_info - store mmu level2 mapping info
 *
 * @pa: physical addresss of mapped region
 * @va: virtual address of mapped region
 * @size: size of mapped region
 * @type: bit field for mapping attirutes (UTA_TYPE_xxx)
 */
struct tee_mmu_l2_info {
	paddr_t pa;
	uint32_t va;
	uint32_t size;
	unsigned int type;
};

/*
 * struct tee_remap_info - store TA dyn remap requests
 *
 * @mm: addr of allocated tee_mm_entry_t
 * @va: virtual start address of requested mapped memory.
 * @size: size of the full mapped area.
 * @cache: true is memory is mapped cached
 */
struct tee_remap_info {
	tee_mm_entry_t *mm;
	void *va;
	size_t size;
	bool cache;
};

/*
 * struct tee_mmu_info - store all TA mapping information to
 * build/install TA mapping context at TA invocation.
 *
 * @l1_tbl - first bytes of the MMU L1 table for TA context
 * @l1_size - size of the l1_tbl table in bytes
 *
 * @heap - pa/va/size/info for TA heap/stack memory area
 * @code - pa/va/size/info for TA text/ro/rw/bss memory area
 * @param[] - pa/va/size/info for each TA memref parameter(s) (if any)
 *
 * @l2_static - ptr to the level2 mmu table statically alloc at TA creation.
 * @l2_static_size - size of the l2_static table in bytes
 *
 * @l2_param - ptr to the level2 mmu table statically alloc at TA creation.
 * @l2_param_size - size of the l2_param table in bytes
 *
 * @ta_private_vstart: virt start address of data private to TA (stack bottom)
 * @ta_remap_vstart: virt start address of remap memory (code/data top)
 * @ta_private_vend: virtual end address of data private to TA (remap top)
 * @l2_param_vstart: section aligned virt start address for TA memref params
 *
 * @mm_remap - tee_mm block allocation for handling TA remap requests.
 * @remap_ref - array of references of TA requested mapped areas.
 */
struct tee_mmu_info {
	uint32_t *l1_tbl;
	size_t l1_size;

	struct tee_mmu_l2_info heap;
	struct tee_mmu_l2_info code;
	struct tee_mmu_l2_info param[4];

	uint32_t *l2_static;
	size_t l2_static_size;

	uint32_t *l2_param;
	size_t l2_param_size;

	uint32_t ta_private_vstart;
	uint32_t ta_remap_vstart;
	uint32_t ta_private_vend;
	uint32_t l2_param_vstart;

	tee_mm_pool_t *mm_remap;
	struct tee_remap_info remap_ref[TA_REMAP_PAGES];
};

/* get uTA heap user virtual start address */
void *tee_mmu_get_heap_uaddr(struct tee_ta_ctx *ctx, size_t heap_size)
{
	struct tee_mmu_info *mmu;
	if (!ctx || !ctx->mmu)
		return NULL;

	mmu = ctx->mmu;
	return (void *)(mmu->heap.va + mmu->heap.size - heap_size);
}

/* return true if buffer fits in memory currently mapped by uta l2 mmu */
static bool l2_lp_is_mapped(struct tee_mmu_l2_info *mmu_l2, void *va, size_t len)
{
	if (!mmu_l2 || !mmu_l2->va)
		return false;
	if ((uint32_t)va + len < (uint32_t)va)
		return false;
	if ((uint32_t)va < mmu_l2->va)
		return false;
	if ((uint32_t)va + len > mmu_l2->va + mmu_l2->size)
		return false;
	return true;
}

/*
 * map_l2_lp - load target mapping in target level2 mmu table.
 *
 * @l2_tbl: level2 mmu table address
 * @s_va: virtual start address of section related to the L2 table.
 * @map: info on target memory to be mapped
 * @attr: mmu (large page) attributes bitfield.
 */
static void map_l2_lp(uint32_t *l2_tbl, uint32_t s_va,
		      struct tee_mmu_l2_info *map, uint32_t attr)
{
	paddr_t pa;
	paddr_t pe;
	uint32_t *l2;

	l2 = l2_tbl;
	pa = map->pa;
	pe = map->pa + map->size;

	l2 = l2_tbl + ((map->va - s_va) >> SMALL_PAGE_SHIFT);
	while (pa < pe) {
		*l2++ = (pa & ~LARGE_PAGE_MASK) | attr;
		pa += SMALL_PAGE_SIZE;
	}
}

static TEE_Result prepare_remap_mmu(struct tee_ta_ctx *ctx,
				    uint32_t va, size_t l)
{
	TEE_Result ret;
	struct tee_mmu_info *mmu = ctx->mmu;

	mmu->mm_remap = malloc(sizeof(tee_mm_pool_t));
	if (mmu->mm_remap == NULL) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	memset(mmu->mm_remap, 0, sizeof(tee_mm_pool_t));
	tee_mm_final(mmu->mm_remap);

	if (!tee_mm_init(mmu->mm_remap, va, va + l,
			 SMALL_PAGE_SHIFT, TEE_MM_POOL_NO_FLAGS)) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	memset(mmu->remap_ref, 0, sizeof(mmu->remap_ref));
	ret = TEE_SUCCESS;
out:
	return ret;
}

/*
 * Prepare some static configuration of the TA instance mapping
 */
TEE_Result tee_mmu_init_with_asid(struct tee_ta_ctx *ctx,
				  uint32_t asid __unused)
{
	TEE_Result ret;
	uint32_t *ptr;
	paddr_t pa;
	size_t cnt, n;
	struct tee_mmu_info *mmu;

	ctx->mmu = malloc(sizeof(struct tee_mmu_info));
	if (!ctx->mmu)
		return TEE_ERROR_OUT_OF_MEMORY;
	mmu = ctx->mmu;
	memset(mmu, 0, sizeof(struct tee_mmu_info));

	/* first mapped memory area starts at first 1MB of vmem */
	mmu->ta_private_vstart = SECTION_SIZE;

	/*
	 * alloc/fill L2 MMU table for TA instance stack/heap and code/data
	 */
	pa = tee_mm_get_smem(ctx->mm_heap_stack);
	if (pa & LARGE_PAGE_MASK) {
		EMSG("heap_stack memory is not aligned: %X", (unsigned int)pa);
		ret = TEE_ERROR_SECURITY;
		goto error;
	}
	cnt = ROUNDUP(ctx->heap_size + ctx->stack_size, LARGE_PAGE_SIZE) +
		ROUNDUP(tee_mm_get_bytes(ctx->mm), LARGE_PAGE_SIZE);
	if (ctx->flags & TA_FLAG_REMAP_SUPPORT) {
		cnt += TA_REMAP_VSIZE;
	}
	cnt = (((cnt - 1) >> SECTION_SHIFT) + 1) * L2_TBL_SIZE;
	if (cnt == 0) {
		ret = TEE_ERROR_SECURITY;
		goto error;
	}
	mmu->l2_static = memalign(COARSE_ALIGN, cnt);
	if (!mmu->l2_static) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto error;
	}
	mmu->l2_static_size = cnt;
	memset(mmu->l2_static, 0, cnt);

	mmu->heap.type = UTA_TYPE_LARGE_PAGE | UTA_TYPE_CACHED;
	mmu->heap.pa = pa;
	mmu->heap.va = SECTION_SIZE;
	mmu->heap.size =
		ROUNDUP(ctx->heap_size + ctx->stack_size, LARGE_PAGE_SIZE);

	map_l2_lp(mmu->l2_static, SECTION_SIZE, &mmu->heap,
			TEE_MMU_LPAGE_UDATA | TEE_MMU_LPAGE_OIWBWA);
	LOG("heap map: va=0x%x pa=0x%x size=0x%x - data cacheable",
		mmu->heap.va, mmu->heap.pa, mmu->heap.size);

	pa = tee_mm_get_smem(ctx->mm);
	if (pa & LARGE_PAGE_MASK) {
		EMSG("heap_stack memory is not aligned: %X", (unsigned int)pa);
		ret = TEE_ERROR_SECURITY;
		goto error;
	}
	mmu->code.type = UTA_TYPE_LARGE_PAGE | UTA_TYPE_CACHED;
	mmu->code.pa = pa;
	mmu->code.va = mmu->heap.va + mmu->heap.size;
	mmu->code.size = ROUNDUP(tee_mm_get_bytes(ctx->mm), LARGE_PAGE_SIZE);

	map_l2_lp(mmu->l2_static, SECTION_SIZE, &mmu->code,
		  TEE_MMU_LPAGE_UCODE | TEE_MMU_LPAGE_OIWBWA);
	LOG("code map: va=0x%x pa=0x%x size=0x%x - code/data cacheable",
		mmu->code.va, mmu->code.pa, mmu->code.size);

	mmu->ta_private_vend =
		mmu->ta_private_vstart + mmu->heap.size + mmu->code.size;

	/* remap support ? */
	if (ctx->flags & TA_FLAG_REMAP_SUPPORT) {
		ret = prepare_remap_mmu(ctx, mmu->ta_private_vend,
					TA_REMAP_VSIZE);
		if (ret != TEE_SUCCESS)
			goto error;

		mmu->ta_remap_vstart = mmu->ta_private_vend;
		mmu->ta_private_vend += TA_REMAP_VSIZE;
		LOG("remap map: va=0x%x size=0x%x",
		    mmu->ta_remap_vstart, TA_REMAP_VSIZE);
	}

	mmu->l2_param_vstart =
		ROUNDUP(mmu->ta_private_vend, SECTION_SIZE);

	/*
	 * alloc/fill L1 MMU table: only the first bytes (32bit aligned)
	 */
	mmu->l1_size = TEE_MMU_UL1_SIZE;
	mmu->l1_tbl = memalign(4, mmu->l1_size);
	if (!mmu->l1_tbl) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto error;
	}

	ptr = (uint32_t *)mmu->l1_tbl;
	memset(ptr, 0, mmu->l1_size);

	/* fist 1mb (section) is unmap for debug/protection */
	ptr++;

	if (core_va2pa(mmu->l2_static, &pa)) {
		ret = TEE_ERROR_SECURITY;
		goto error;
	}

	cnt = mmu->heap.size + mmu->code.size - 1;
	if ((ctx->flags & TA_FLAG_REMAP_SUPPORT) != 0)
		cnt += TA_REMAP_VSIZE;
	cnt = (cnt >> SECTION_SHIFT) + 1;

	for (n = 0; n < cnt; n++)
		*ptr++ = TEE_MMU_COARSE | TEE_MMU_COARSE_DOMAIN(1) |
			(pa + (n << 10));

	return TEE_SUCCESS;
error:
	tee_mmu_final_reset(ctx);
	return ret;
}

#if (CFG_TEE_FW_DEBUG == 0)

static void log_l1_tbl(struct tee_mmu_info *mmu __unused) {}
static void log_l2_static(struct tee_mmu_info *mmu __unused) {}
static void log_l2_param(struct tee_mmu_info *mmu __unused) {}
static void log_tee_mmu(struct tee_mmu_info *mmu __unused) {}

#else

static void log_l1_tbl(struct tee_mmu_info *mmu __unused)
{
	LOG("l1_tbl: %08X %08X %08X %08X %08X %08X %08X %08X",
		mmu->l1_tbl[0], mmu->l1_tbl[1],
		mmu->l1_tbl[2], mmu->l1_tbl[3],
		mmu->l1_tbl[4], mmu->l1_tbl[5],
		mmu->l1_tbl[6], mmu->l1_tbl[7]);
	LOG("        %08X %08X %08X %08X %08X %08X %08X %08X",
		mmu->l1_tbl[8], mmu->l1_tbl[9],
		mmu->l1_tbl[10], mmu->l1_tbl[11],
		mmu->l1_tbl[12], mmu->l1_tbl[13],
		mmu->l1_tbl[14], mmu->l1_tbl[15]);
}

static void log_l2_static(struct tee_mmu_info *mmu __unused)
{
	LOG("l2_static: v[  0k  60k]=p[%08X %08X]  v[ 64k 124k]=p[%08X %08X]",
		mmu->l2_static[0], mmu->l2_static[15],
		mmu->l2_static[16], mmu->l2_static[31]);
	LOG("           v[128k 188k]=p[%08X %08X]  v[192k 255k]=p[%08X %08X]",
		mmu->l2_static[32], mmu->l2_static[47],
		mmu->l2_static[48], mmu->l2_static[63]);
	LOG("           v[256k 316k]=p[%08X %08X]  v[320k 380k]=p[%08X %08X]",
		mmu->l2_static[64], mmu->l2_static[79],
		mmu->l2_static[80], mmu->l2_static[95]);
}

static void log_l2_param(struct tee_mmu_info *mmu __unused)
{
	if (mmu->l2_param == NULL)
		return;

	LOG("l2_param: v[   0k  60k]=p[%08X %08X]  v[ 64k 124k]=p[%08X %08X]",
		mmu->l2_param[0], mmu->l2_param[15],
		mmu->l2_param[16], mmu->l2_param[31]);
	LOG("           v[128k 188k]=p[%08X %08X]  v[192k 255k]=p[%08X %08X]",
		mmu->l2_param[32], mmu->l2_param[47],
		mmu->l2_param[48], mmu->l2_param[63]);
	LOG("           v[256k 316k]=p[%08X %08X]  v[320k 380k]=p[%08X %08X]",
		mmu->l2_param[64], mmu->l2_param[79],
		mmu->l2_param[80], mmu->l2_param[95]);
}

static void log_tee_mmu(struct tee_mmu_info *mmu __unused)
{
	LOG("l1_tbl=%d@%p, l2_static=%d@%p, l2_param=%d@%p",
		mmu->l1_size, mmu->l1_tbl,
		mmu->l2_static_size, mmu->l2_static,
		mmu->l2_param_size, mmu->l2_param);
	LOG("heap = p0x%08X v0x%08X l%d t0x%x",
		mmu->heap.pa, mmu->heap.va,
		mmu->heap.size, mmu->heap.type);
	LOG("code = p0x%08X v0x%08X l%d t0x%x",
		mmu->code.pa, mmu->code.va,
		mmu->code.size, mmu->code.type);
	LOG("param[0] = p0x%08X v0x%08X l%d t0x%x",
		mmu->param[0].pa, mmu->param[0].va,
		mmu->param[0].size, mmu->param[0].type);
	LOG("param[1] = p0x%08X v0x%08X l%d t0x%x",
		mmu->param[1].pa, mmu->param[1].va,
		mmu->param[1].size, mmu->param[1].type);
	LOG("param[2] = p0x%08X v0x%08X l%d t0x%x",
		mmu->param[2].pa, mmu->param[2].va,
		mmu->param[2].size, mmu->param[2].type);
	LOG("param[3] = p0x%08X v0x%08X l%d t0x%x",
		mmu->param[3].pa, mmu->param[3].va,
		mmu->param[3].size, mmu->param[3].type);
	LOG("ta_priv_vstart=%08X  ta_priv_vend=%08X",
		mmu->ta_private_vstart, mmu->ta_private_vend);
	LOG("l2_param_vstart=%08X  ta_remap_vstart=%08X",
		mmu->l2_param_vstart, mmu->ta_remap_vstart);
}
#endif

static void log_all(struct tee_mmu_info *mmu)
{
	log_tee_mmu(mmu);
	log_l1_tbl(mmu);
	log_l2_static(mmu);
	log_l2_param(mmu);
}

/*
 * Map memory reference paramters.
 * All NonSecure SHM buffers are mapped by sections, cached unsecure.
 * All TA_RAM memref are mapped by 64kB page, cached, secure.
 * All UnSafe memory memref are mapped by 64kB page, cahced, secure.
 *
 * Non secure and secure memory cannot shared the same L2 table (armv7).
 *
 * Inits: check if old param mapping to be cleared l1_tbl and l2_static.
 * 1st pass: map all nsec_shm memrefs by sections, set l2_param_vstart
 *           (virt addr start for param mapped from a l2 table)
 * 2nd pass: map secure memref in l2_static (if enougth room) and
 *           required size for a new L2 table.
 * 3rd pass: allocate a l2 table and map remaining memref params.
 */
static TEE_Result map_io(struct tee_ta_ctx *ctx, struct tee_ta_param *param)
{
	TEE_Result ret = TEE_SUCCESS;
	struct tee_mmu_info *mmu;
	struct tee_mmu_l2_info *map;
	uint32_t l2_param_vstart, l2_param_vaddr;
	size_t l2_param_size;
	uint32_t l2_static_vstart;
	uint32_t id;
	uint32_t attr;
	uint32_t *tbl;
	paddr_t pe;
	paddr_t pa;
	uint32_t param_type;
	TEE_Param *p;
	size_t n, m;

	mmu = ctx->mmu;
	attr = 0;

	/* cleanup previous memref mappings */
	LOG("Cleanup previous mapping:");
	log_all(mmu);
	for (id = 0; id < TEE_NUM_PARAMS; id++) {
		if (mmu->param[id].va == 0)
			continue;

		if (mmu->param[id].va < mmu->l2_param_vstart) {
			/* params is mapped from the l2_static table */
			n = mmu->param[id].size >> SMALL_PAGE_SHIFT;
			tbl = mmu->l2_static;
			tbl += (mmu->param[id].va - mmu->ta_private_vstart) >>
				SMALL_PAGE_SHIFT;
		} else if (mmu->param[id].type & UTA_TYPE_LARGE_PAGE) {
			/* params is mapped from the l2_param table */
			if (mmu->l2_param == NULL) {
				ret = TEE_ERROR_SECURITY;
				goto error;
			}
			n = mmu->param[id].size >> SMALL_PAGE_SHIFT;
			tbl = mmu->l2_param;
			tbl += (mmu->param[id].va - mmu->l2_param_vstart) >>
							SMALL_PAGE_SHIFT;
		} else if (mmu->param[id].type & UTA_TYPE_SECTION) {
			/* params is mapped from the l1_tbl by section */
			n = mmu->param[id].size >> SECTION_SHIFT;
			tbl = mmu->l1_tbl;
			tbl += (mmu->param[id].va >> SECTION_SHIFT);
		} else {
			ret = TEE_ERROR_SECURITY;
			goto error;
		}
		memset(tbl, 0, n * sizeof(uint32_t));

		mmu->param[id].pa = 0;
		mmu->param[id].va = 0;
		mmu->param[id].size = 0;
		mmu->param[id].type = 0;
	}

	l2_static_vstart = mmu->ta_private_vend;
	l2_param_vstart = mmu->l2_param_vstart;

	/*
	 * 1st pass: map all "section based" and prepare large page map
	 */
	for (id = 0; id < TEE_NUM_PARAMS; id++) {
		param_type = TEE_PARAM_TYPE_GET(param->types, id);
		p = &param->params[id];
		map = &mmu->param[id];

		/* don't care if it's not a memory reference */
		if (!((param_type == TEE_PARAM_TYPE_MEMREF_INPUT) ||
			(param_type == TEE_PARAM_TYPE_MEMREF_OUTPUT) ||
			(param_type == TEE_PARAM_TYPE_MEMREF_INOUT)))
			continue;

		/* if it's an empty buffer then hide its phys addr */
		if (p->memref.size == 0) {
			p->memref.buffer = (void *)1;
			continue;
		}

		/* NS_SHM => maped by section. TA/UNSAFE => maped 64kB */
		if (core_pbuf_is(CORE_MEM_NSEC_SHM,
			(tee_paddr_t)p->memref.buffer, p->memref.size)) {

			map->pa = ROUNDDOWN((uint32_t)p->memref.buffer,
						SECTION_SIZE);
			map->size = ROUNDUP((uint32_t)p->memref.buffer +
						p->memref.size - map->pa,
						SECTION_SIZE);

			if (((l2_param_vstart + map->size) >> SECTION_SHIFT) >
				TEE_MMU_UL1_NUM_ENTRIES) {
				ret = TEE_ERROR_EXCESS_DATA;
				goto error;
			}

			map->type = UTA_TYPE_SECTION | UTA_TYPE_NS;
			attr = TEE_MMU_SECTION_UDATA | TEE_MMU_SECTION_NS;
			if (core_mmu_is_shm_cached()) {
				attr |= TEE_MMU_SECTION_OIWBWA;
				map->type |= UTA_TYPE_CACHED;
			} else {
				attr |= TEE_MMU_SECTION_NOCACHE;
			}

			tbl = mmu->l1_tbl + (l2_param_vstart >> SECTION_SHIFT);
			m = (((uint32_t)p->memref.buffer & SECTION_MASK) +
				p->memref.size - 1) >> SECTION_SHIFT;
			for (n = 0; n <= m; n++)
				*tbl++ = (map->pa  + (n << SECTION_SHIFT)) |
									attr;
			map->va = l2_param_vstart;

			LOG("NS-shm param map: pa=0x%x va=0x%x mapped size=0x%x",
				(unsigned int)p->memref.buffer, map->va |
				((uint32_t)p->memref.buffer & SECTION_MASK),
				map->size);

			p->memref.buffer = (void *)(map->va |
				((uint32_t)p->memref.buffer & SECTION_MASK));
			l2_param_vstart += map->size;

			continue;

		}
		if (core_pbuf_is(CORE_MEM_TA_RAM,
				(tee_paddr_t)p->memref.buffer,
				p->memref.size) ||
			core_pbuf_is(CORE_MEM_MULTPURPOSE,
				(tee_paddr_t)p->memref.buffer,
				p->memref.size)) {
			/* store only the target mapped pa/size */
			map->pa = ROUNDDOWN((uint32_t)p->memref.buffer,
						LARGE_PAGE_SIZE);
			map->size = ROUNDUP((uint32_t)p->memref.buffer +
						p->memref.size - map->pa,
						LARGE_PAGE_SIZE);
			map->type = UTA_TYPE_LARGE_PAGE | UTA_TYPE_CACHED;

			continue;
		}

		EMSG("invalid TA parameter location");
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto error;
	}

	/*
	 * 2nd pass: map all "large page based" is l2_static table
	 * and prepare for allocation of another l2 tbl if required.
	 */
	l2_param_size = 0;
	for (id = 0; id < TEE_NUM_PARAMS; id++) {

		p = &param->params[id];
		map = &mmu->param[id];

		if ((map->type & UTA_TYPE_LARGE_PAGE) == 0)
			continue;

		if ((l2_static_vstart + map->size) <= mmu->l2_param_vstart) {
			/* map in l2_static */
			pa = map->pa;
			pe = map->pa + map->size;
			attr = TEE_MMU_LPAGE_UDATA;
			if (map->type & UTA_TYPE_CACHED)
				attr |= TEE_MMU_LPAGE_OIWBWA;
			tbl = mmu->l2_static +
				((l2_static_vstart - mmu->ta_private_vstart) >>
				SMALL_PAGE_SHIFT);
			while (pa < pe) {
				*tbl++ = pa | attr;
				pa += SMALL_PAGE_SIZE;
			}

			map->va = l2_static_vstart;

			LOG("Map sec param (1): pa=0x%x va=0x%x size=0x%x",
				(unsigned int)p->memref.buffer, map->va |
				((uint32_t)p->memref.buffer & SECTION_MASK),
				map->size);

			p->memref.buffer = (void *)(map->va |
				((uint32_t)p->memref.buffer &
				 LARGE_PAGE_MASK));
			l2_static_vstart += map->size;

			continue;
		}
		if (l2_param_vstart + l2_param_size + map->size <
				(TEE_MMU_UL1_NUM_ENTRIES << SECTION_SHIFT)) {
			/* map in l2_param */
			l2_param_size += map->size;
			continue;
		}
		ret = TEE_ERROR_EXCESS_DATA;
		goto error;
	}
	if (l2_param_size == 0)
		goto ok;

	/*
	 * last, we definitely need to allocate a level2 table.
	 * Map all remaining as LargePage/secure in an allocated l2_param.
	 * Virtual start address right above NSec shm vmem (section mapped)
	 */

	/* alloc and reset a l2 table */
	l2_param_size = ROUNDUP(l2_param_size, SECTION_SIZE) >>
								SECTION_SHIFT;
	if (mmu->l2_param) {
		/* TODO: find a better way to optimse memory ! */
		if (mmu->l2_param_size <=
				(l2_param_size * L2_TBL_SIZE)) {
			free(mmu->l2_param);
			mmu->l2_param = NULL;
		}
	}
	if (mmu->l2_param == NULL) {
		mmu->l2_param = memalign(l2_param_size * L2_TBL_SIZE,
						SMALL_PAGE_SIZE);
		if (mmu->l2_param == NULL) {
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto error;
		}
		mmu->l2_param_size = l2_param_size * L2_TBL_SIZE;
		memset(mmu->l2_param, 0, l2_param_size * L2_TBL_SIZE);
	}
	if (core_va2pa(mmu->l2_param, &pa)) {
		ret = TEE_ERROR_SECURITY;
		goto error;
	}

	/* fill l1 (assume here only Secure memory is mapped) */
	tbl = mmu->l1_tbl + (l2_param_vstart >> SECTION_SHIFT);
	for (n = 0; n < l2_param_size; n++)
		*tbl = ((uint32_t)pa + (n << 10)) | TEE_MMU_COARSE_USER;

	/* process remaining memref */
	l2_param_vaddr = l2_param_vstart;
	for (id = 0; id < TEE_NUM_PARAMS; id++) {

		p = &param->params[id];
		map = &mmu->param[id];
		if (((map->type & UTA_TYPE_LARGE_PAGE) == 0) ||
			(map->va != 0))
			continue;

		/* map in l2_static */
		pa = map->pa;
		pe = map->pa + map->size;
		attr = TEE_MMU_LPAGE_UDATA | TEE_MMU_LPAGE_OIWBWA;
		tbl = mmu->l2_param +
			((l2_param_vaddr - l2_param_vstart) >>
			SMALL_PAGE_SHIFT);
		while (pa < pe) {
			*tbl++ = pa | attr;
			pa += SMALL_PAGE_SIZE;
		}

		map->va = l2_param_vaddr;

		LOG("Map sec param (2): pa=0x%x va=0x%x size=0x%x",
			(unsigned int)p->memref.buffer, map->va |
			((uint32_t)p->memref.buffer & SECTION_MASK),
			map->size);

		p->memref.buffer = (void *)(map->va |
			((uint32_t)p->memref.buffer &
			LARGE_PAGE_MASK));
		l2_param_vaddr += map->size;
	}

ok:
	LOG("map io done");
	log_all(mmu);
	return TEE_SUCCESS;

error:
	LOG("Error 0x%X / %d", ret, ret);
	log_all(mmu);

	/*
	 * Reset loaded mapping and free ressources:
	 * - in l1_tbl: clear all entries after l2_param_vstart
	 * - in l2_static: clear all entries after l2_private_vend
	 * - reset all 'param' l2 structures and free l2_param table
	 *
	 * Clear MMU table entries by writing non 0 values but yet unmaped
	 * region attributes (bit[1..0]=2b00).
	 */
	tbl = mmu->l1_tbl + (mmu->l2_param_vstart >> SECTION_SHIFT);
	n = TEE_MMU_UL1_NUM_ENTRIES -
		(mmu->l2_param_vstart >> SECTION_SHIFT);
	memset(tbl, 0x8, n * sizeof(uint32_t));

	tbl = mmu->l2_static +
		((mmu->ta_private_vend - mmu->ta_private_vstart) >>
			SMALL_PAGE_SHIFT);
	n = mmu->l2_static_size - (tbl - mmu->l2_static);
	memset(tbl, 0xC, n * sizeof(uint32_t));

	memset(mmu->param, 0, sizeof(struct tee_mmu_l2_info) * TEE_NUM_PARAMS);
	if (mmu->l2_param) {
		free(mmu->l2_param);
		mmu->l2_param = NULL;
	}

	return ret;
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
	TEE_ASSERT((ctx->flags & TA_FLAG_USER_MODE) != 0);
	TEE_ASSERT((ctx->flags & TA_FLAG_EXEC_DDR) != 0);

	return map_io(ctx, param);
}

/*
 * tee_mmu_final_reset - finalise and free ctx mmu
 */
void tee_mmu_final_reset(struct tee_ta_ctx *ctx)
{
	struct tee_mmu_info *mmu = ctx->mmu;

	if (!mmu)
		return;

	free(mmu->l1_tbl);
	free(mmu->l2_static);
	free(mmu->l2_param);
	free(mmu->mm_remap);
	free(mmu);
	ctx->mmu = NULL;
}

TEE_Result tee_mmu_user_va2pa_helper(const struct tee_ta_ctx *ctx,
				     void *va, paddr_t *pa)
{
	struct tee_mmu_info *mmu = ctx->mmu;
	struct tee_mmu_l2_info *mmu_l2;
	uint32_t n, v, mask;

	if (pa == NULL)
		return TEE_ERROR_SECURITY;

	v = (uint32_t)va;

	/* va2pa are allowed only on TA data and params */
	for (n = 0; n < TEE_NUM_PARAMS; n++) {
		mmu_l2 = &mmu->param[n];
		if ((v >= mmu_l2->va) && (v < (mmu_l2->va + mmu_l2->size)))
			goto found;
	}
	mmu_l2 = &mmu->heap;
	if ((v >= mmu_l2->va) && (v < (mmu_l2->va + mmu_l2->size)))
		goto found;
	mmu_l2 = &mmu->code;
	if ((v >= mmu_l2->va) && (v < (mmu_l2->va + mmu_l2->size)))
		goto found;

#if (CFG_TEE_FW_DEBUG == 1)
	{
		uint32_t p;
		if (cpu_mmu_va2pa(CPU_V2P_SEC_USR_RD, va, &p) == 0) {
			EMSG("mapping error: TA va %p => n.a != %X", va, p);
			TEE_ASSERT(0);
		}
	}
#endif
	return TEE_ERROR_ACCESS_DENIED;

found:
	if (mmu_l2->type & UTA_TYPE_LARGE_PAGE)
		mask = LARGE_PAGE_MASK;
	else if (mmu_l2->type & UTA_TYPE_SECTION)
		mask = SECTION_MASK;
	else
		return TEE_ERROR_ACCESS_DENIED;

	*pa = ((mmu_l2->pa & ~mask) | (v & mask));

#if (CFG_TEE_FW_DEBUG == 1)
	{
		uint32_t p;
		if (cpu_mmu_va2pa(CPU_V2P_SEC_USR_RD, va, &p)) {
			EMSG("mapping error: TA va %p => %X != n.a (%X)",
					va, (uint32_t)*pa, p);
			TEE_ASSERT(0);
		} else if ((((uint32_t)*pa) & ~SMALL_PAGE_MASK) !=
			(p & ~SMALL_PAGE_MASK)) {
			EMSG("mapping error: TA va %p => %X != %X", va,
				((uint32_t)*pa) & ~SMALL_PAGE_MASK,
				p & ~SMALL_PAGE_MASK);
			TEE_ASSERT(0);
		}
	}
#endif
	return TEE_SUCCESS;
}

/* */
TEE_Result tee_mmu_user_pa2va_helper(const struct tee_ta_ctx *ctx, paddr_t pa,
				     void **va)
{
	struct tee_mmu_info *mmu = ctx->mmu;
	struct tee_mmu_l2_info *mmu_l2;
	uint32_t cnt;
	uint32_t p = (uint32_t)pa;
	uint32_t mask;

	/* pa2va are allowed only on TA data and params */
	for (cnt = 0; cnt < TEE_NUM_PARAMS; cnt++) {
		mmu_l2 = &mmu->param[cnt];
		if ((p >= mmu_l2->pa) && (p < (mmu_l2->pa + mmu_l2->size)))
			goto found;
	}

	mmu_l2 = &mmu->heap;
	if ((p >= mmu_l2->pa) && (p < (mmu_l2->pa + mmu_l2->size)))
		goto found;

	mmu_l2 = &mmu->code;
	if ((p >= mmu_l2->pa) && (p < (mmu_l2->pa + mmu_l2->size)))
		goto found;

	return TEE_ERROR_ACCESS_DENIED;

found:
	if (mmu_l2->type & UTA_TYPE_LARGE_PAGE)
		mask = LARGE_PAGE_MASK;
	else if (mmu_l2->type & UTA_TYPE_SECTION)
		mask = SECTION_MASK;
	else
		return TEE_ERROR_ACCESS_DENIED;

	*va = (void *)((mmu_l2->va & ~mask) | (p & mask));
	return TEE_SUCCESS;
}

/* converts teecore va into TA va: va->pa->va */
TEE_Result tee_mmu_kernel_to_user(const struct tee_ta_ctx *ctx,
				  const uint32_t kaddr, uint32_t *uaddr)
{
	paddr_t p;

	if ((ctx == NULL) || (uaddr == NULL))
		return TEE_ERROR_SECURITY;

	if (core_va2pa((void *)kaddr, &p))
		return TEE_ERROR_SECURITY;

	return tee_mmu_user_pa2va(ctx, p, (void **)uaddr);
}

uint32_t tee_mmu_user_get_cache_attr(struct tee_ta_ctx *ctx, void *va)
{
	struct tee_mmu_info *mmu = ctx->mmu;
	struct tee_mmu_l2_info *mmu_l2;
	size_t cnt;

	/* check if param mapping */
	mmu_l2 = NULL;
	for (cnt = 0; cnt < TEE_NUM_PARAMS; cnt++) {
		if (l2_lp_is_mapped(&mmu->param[cnt], va, 1)) {
			mmu_l2 = &mmu->param[cnt];
			break;
		}
	}
	/* check if va is TA heap/stack or code/data */
	if (!mmu_l2) {
		if (l2_lp_is_mapped(&mmu->heap, va, 1))
			mmu_l2 = &mmu->heap;
	}
	if (!mmu_l2) {
		if (l2_lp_is_mapped(&mmu->code, va, 1))
			mmu_l2 = &mmu->code;
	}
	/* check if it is "remap" memory. if so, access is allowed */
	if (!mmu_l2 && mmu->mm_remap) {
		struct tee_remap_info *i = mmu->remap_ref;

		for (cnt = 0; cnt < TA_REMAP_PAGES; cnt++, i++) {
			if ((i->va == NULL) || (va < i->va))
				continue;
			if ((uint8_t *)va >= ((uint8_t *)i->va + i->size))
				continue;
			if (i->cache)
				return TEESMC_ATTR_CACHE_DEFAULT;
			return TEESMC_ATTR_CACHE_NONCACHE;
		}
	}

	assert(mmu_l2 != NULL);	/* FIXME: that's weird (insure VA is mapped) */

	if (mmu_l2->type & UTA_TYPE_CACHED)
		return TEESMC_ATTR_CACHE_DEFAULT;

	return TEESMC_ATTR_CACHE_NONCACHE;
}

TEE_Result tee_mmu_check_access_rights(const struct tee_ta_ctx *ctx,
				       uint32_t flags, tee_uaddr_t ua,
				       size_t len)
{
	struct tee_mmu_info *mmu = ctx->mmu;
	struct tee_mmu_l2_info *mmu_l2;
	paddr_t pa;
	uint32_t cnt;
	void *va = (void *)ua;

	/* empty buffer can be accessed (TODO: check this!) */
	if (len == 0)
		return TEE_SUCCESS;

	/* Address wrap */
	if (ua + len < ua)
		return TEE_ERROR_ACCESS_DENIED;

	/* only TA-to-TA can use param inside secure memory */
	mmu_l2 = NULL;
	for (cnt = 0; cnt < TEE_NUM_PARAMS; cnt++) {
		if (l2_lp_is_mapped(&mmu->param[cnt], va, len)) {
			mmu_l2 = &mmu->param[cnt];
			break;
		}
	}
	if ((mmu_l2 != NULL) && (flags & TEE_MEMORY_ACCESS_ANY_OWNER) !=
					TEE_MEMORY_ACCESS_ANY_OWNER) {
		pa = mmu_l2->pa & ~LARGE_PAGE_MASK;
		pa |= (size_t)va & LARGE_PAGE_MASK;
		if (core_pbuf_is(CORE_MEM_SEC, pa, len) == false) {
			EMSG("user TA param in unsec memory: access failure");
			return TEE_ERROR_ACCESS_DENIED;
		}
		/* TODO: should be only TA_RAM ? */
	}

	/* check if va is TA heap/stack or code/data */
	if (!mmu_l2) {
		if (l2_lp_is_mapped(&mmu->heap, va, len))
			mmu_l2 = &mmu->heap;
	}
	if (!mmu_l2) {
		if (l2_lp_is_mapped(&mmu->code, va, len))
			mmu_l2 = &mmu->code;
	}
	/* check if it is "remap" memory. if so, access is allowed */
	if (!mmu_l2 && mmu->mm_remap) {
		struct tee_remap_info *i = mmu->remap_ref;

		for (cnt = 0; cnt < TA_REMAP_PAGES; cnt++, i++) {
			if ((i->va == NULL) || (i->size == 0))
				continue;
			if ((va >= i->va) &&
				((uint8_t *)va + len) <=
				((uint8_t *)i->va + i->size))
				return TEE_SUCCESS;
		}
	}

	if (mmu_l2 == NULL)
		return TEE_ERROR_ACCESS_DENIED;

	/* check the mapping attributes against effective mapping */
	if ((flags & TEE_MEMORY_ACCESS_WRITE) != 0) {
		if (cpu_mmu_va2pa(CPU_V2P_SEC_USR_WR, va, &pa))
			return TEE_ERROR_ACCESS_DENIED;
	} else if (cpu_mmu_va2pa(CPU_V2P_SEC_USR_RD, va, &pa)) {
			return TEE_ERROR_ACCESS_DENIED;
	}

	return TEE_SUCCESS;
}

/* return true only if buffer fits inside TA private memory */
bool tee_mmu_is_vbuf_inside_ta_private(const struct tee_ta_ctx *ctx,
				       const void *va, size_t size)
{
	struct tee_mmu_info *mmu = ctx->mmu;

	return core_is_buffer_inside(va, size, mmu->ta_private_vstart,
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

/* return true only if buffer intersects TA private memory */
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
	memcpy(va, mmu->l1_tbl, mmu->l1_size);
}

/* returns the virtual address (as seen by the TA) when TA is loaded */
uintptr_t tee_mmu_get_load_addr(const struct tee_ta_ctx *const ctx)
{
	struct tee_mmu_info *mmu = ctx->mmu;
	TEE_ASSERT((ctx->flags & TA_FLAG_EXEC_DDR) != 0);
	return mmu->code.va;
}

uint8_t tee_mmu_get_page_shift(void)
{
	return LARGE_PAGE_SHIFT;
}

