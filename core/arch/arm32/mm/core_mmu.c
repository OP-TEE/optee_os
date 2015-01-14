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
 * This core mmu supports static section mapping (1MByte).
 *       It should should finer mapping (4kByte coarse pages).
 *       It should also allow core to map/unmap (and va/pa) at run-time.
 */
#include <platform_config.h>

#include <stdlib.h>
#include <assert.h>
#include <kernel/tz_proc.h>
#include <kernel/tz_ssvce.h>
#include <kernel/thread.h>
#include <arm32.h>
#include <mm/core_mmu.h>
#include <mm/core_memprot.h>
#include <mm/tee_mmu.h>
#include <mm/tee_mmu_defs.h>
#include <kernel/misc.h>
#include <trace.h>
#include <kernel/tee_misc.h>
#include <kernel/panic.h>
#include <util.h>

/* Default NSec shared memory allocated from NSec world */
unsigned long default_nsec_shm_paddr;
unsigned long default_nsec_shm_size;

/* platform handler for core_pbuf_is()  */
static unsigned long bootcfg_pbuf_is = 1;	/* NOT is BSS */
typedef bool(*platform_pbuf_is_t) (unsigned long attr, unsigned long paddr,
				   size_t size);

/*
 * WARNING: resources accessed during the initialization
 * (sequence core_init_mmu()) are accessed *before* BSS is zero-initialised.
 * Be careful NOT to load data that can be 'reset' to zero after
 * core_init_mmu(), due to BSS init loop.
 */
static struct map_area *static_memory_map = (void *)1;	/* not in BSS */
static struct map_area *map_tee_ram = (void *)1;	/* not in BSS */
static struct map_area *map_ta_ram = (void *)1;	/* not in BSS */
static struct map_area *map_nsec_shm = (void *)1;	/* not in BSS */

/* check if target buffer fits in a core default map area */
static bool pbuf_inside_map_area(unsigned long p, size_t l,
				 struct map_area *map)
{
	return core_is_buffer_inside(p, l, map->pa, map->size);
}

static struct map_area *find_map_by_va(void *va)
{
	struct map_area *map = static_memory_map;
	unsigned long a = (unsigned long)va;

	while (map->type != MEM_AREA_NOTYPE) {
		if ((a >= map->va) && (a < (map->va + map->size)))
			return map;
		map++;
	}
	return NULL;
}

static struct map_area *find_map_by_pa(unsigned long pa)
{
	struct map_area *map = static_memory_map;

	while (map->type != MEM_AREA_NOTYPE) {
		if ((pa >= map->pa) && (pa < (map->pa + map->size)))
			return map;
		map++;
	}
	return NULL;
}

/* armv7 memory mapping attributes: section mapping */
#define SECTION_SECURE               (0 << 19)
#define SECTION_NOTSECURE            (1 << 19)
#define SECTION_SHARED               (1 << 16)
#define SECTION_NOTGLOBAL            (1 << 17)
#define SECTION_RW                   ((0 << 15) | (1 << 10))
#define SECTION_RO                   ((1 << 15) | (1 << 10))
#define SECTION_TEXCB(tex, c, b)     ((tex << 12) | (c << 3) | (b << 2))
#define SECTION_DEVICE               SECTION_TEXCB(0, 0, 1)
#define SECTION_NORMAL               SECTION_TEXCB(1, 0, 0)
#define SECTION_NORMAL_CACHED        SECTION_TEXCB(1, 1, 1)
#define SECTION_NO_EXEC              (1 << 4)
#define SECTION_SECTION              (2 << 0)

#define SECTION_PT_NOTSECURE		(1 << 3)
#define SECTION_PT_PT			(1 << 0)

#define SMALL_PAGE_SMALL_PAGE		(1 << 1)
#define SMALL_PAGE_SHARED		(1 << 10)
#define SMALL_PAGE_TEXCB(tex, c, b)	((tex << 6) | (c << 3) | (b << 2))
#define SMALL_PAGE_DEVICE		SMALL_PAGE_TEXCB(0, 0, 1)
#define SMALL_PAGE_NORMAL		SMALL_PAGE_TEXCB(1, 0, 0)
#define SMALL_PAGE_NORMAL_CACHED	SMALL_PAGE_TEXCB(1, 1, 1)
#define SMALL_PAGE_RW			((0 << 9) | (1 << 4))
#define SMALL_PAGE_RO			((1 << 9) | (1 << 4))
#define SMALL_PAGE_NO_EXEC		(1 << 0)


/*
 * memarea_not_mapped - check memory not already (partially) mapped
 * A finer mapping must be supported. Currently section mapping only!
 */
static bool memarea_not_mapped(struct map_area *map, void *ttbr0)
{
	uint32_t m, n;

	m = (map->pa >> 20) * 4;	/* assumes pa=va */
	n = map->size >> 20;
	while (n--) {
		if (*((uint32_t *)((uint32_t)ttbr0 + m)) != 0) {
			EMSG("m %d [0x%x] map->pa 0x%x map->size 0x%x",
			     m, *((uint32_t *)((uint32_t)ttbr0 + m)),
			     map->pa, map->size);
			return false;
		}
		m += 4;
	}
	return true;
}

static paddr_t map_page_memarea(struct map_area *map)
{
	uint32_t *l2 = core_mmu_alloc_l2(map);
	size_t pg_idx;
	uint32_t attr;

	TEE_ASSERT(l2);

	attr = SMALL_PAGE_SMALL_PAGE | SMALL_PAGE_SHARED;

	if (map->device)
		attr |= SMALL_PAGE_DEVICE;
	else if (map->cached)
		attr |= SMALL_PAGE_NORMAL_CACHED;
	else
		attr |= SMALL_PAGE_NORMAL;

	if (map->rw)
		attr |= SMALL_PAGE_RW;
	else
		attr |= SMALL_PAGE_RO;

	if (!map->exec)
		attr |= SMALL_PAGE_NO_EXEC;

	/* Zero fill initial entries */
	pg_idx = 0;
	while ((pg_idx * SMALL_PAGE_SIZE) < (map->pa & SECTION_MASK)) {
		l2[pg_idx] = 0;
		pg_idx++;
	}

	/* Fill in the entries */
	while ((pg_idx * SMALL_PAGE_SIZE) < map->size) {
		l2[pg_idx] = ((map->pa & ~SECTION_MASK) +
				pg_idx * SMALL_PAGE_SIZE) | attr;
		pg_idx++;
	}

	/* Zero fill the rest */
	while (pg_idx < ROUNDUP(map->size, SECTION_SIZE) / SMALL_PAGE_SIZE) {
		l2[pg_idx] = 0;
		pg_idx++;
	}

	return (paddr_t)l2;
}

/*
* map_memarea - load mapping in target L1 table
* A finer mapping must be supported. Currently section mapping only!
*/
static void map_memarea(struct map_area *map, uint32_t *ttb)
{
	size_t m, n;
	uint32_t attr;
	paddr_t pa;
	uint32_t region_size;
	uint32_t region_mask;

	TEE_ASSERT(map && ttb);

	switch (map->region_size) {
	case 0:	/* Default to 1MB section mapping */
	case SECTION_SIZE:
		region_size = SECTION_SIZE;
		region_mask = SECTION_MASK;
		break;
	case SMALL_PAGE_SIZE:
		region_size = SMALL_PAGE_SIZE;
		region_mask = SMALL_PAGE_MASK;
		break;
	default:
		panic();
	}

	/* invalid area confing */
	if (map->va || ((map->pa + map->size - 1) < map->pa) ||
	    !map->size || (map->size & region_mask) ||
	    (map->pa & region_mask))
		panic();

	if (region_size == SECTION_SIZE) {
		attr = SECTION_SHARED | SECTION_NOTGLOBAL | SECTION_SECTION;

		if (map->device == true)
			attr |= SECTION_DEVICE;
		else if (map->cached == true)
			attr |= SECTION_NORMAL_CACHED;
		else
			attr |= SECTION_NORMAL;

		if (map->rw == true)
			attr |= SECTION_RW;
		else
			attr |= SECTION_RO;

		if (map->exec == false)
			attr |= SECTION_NO_EXEC;
		if (map->secure == false)
			attr |= SECTION_NOTSECURE;

		pa = map->pa;
	} else {
		attr = SECTION_PT_PT;
		if (!map->secure)
			attr |= SECTION_PT_NOTSECURE;
		pa = map_page_memarea(map);
	}

	map->va = map->pa;	/* 1-to-1 pa=va mapping */

	m = (map->pa >> SECTION_SHIFT);
	n = ROUNDUP(map->size, SECTION_SIZE) >> SECTION_SHIFT;
	while (n--) {
		ttb[m] = pa | attr;
		m++;
		if (region_size == SECTION_SIZE)
			pa += SECTION_SIZE;
		else
			pa += TEE_MMU_L2_SIZE;
	}
}

/* load_bootcfg_mapping - attempt to map the teecore static mapping */
static void load_bootcfg_mapping(void *ttb1)
{
	struct map_area *map, *in;

	/* get memory bootcfg from system */
	in = bootcfg_get_memory();
	if (!in) {
		EMSG("Invalid memory map");
		TEE_ASSERT(0);
	}
	bootcfg_pbuf_is = (unsigned long)bootcfg_get_pbuf_is_handler();
	if (bootcfg_pbuf_is == 0) {
		EMSG("invalid platform handler for pbuf_is");
		TEE_ASSERT(0);
	}

	/* we must find at least a PUB_RAM area and a TEE_RAM area */
	map_tee_ram = NULL;
	map_ta_ram = NULL;
	map_nsec_shm = NULL;

	/* reset L1 table */
	memset(ttb1, 0, TEE_MMU_L1_SIZE);

	/* map what needs to be mapped (non-null size and non INTRAM/EXTRAM) */
	map = in;
	while (map->type != MEM_AREA_NOTYPE) {
		if (!memarea_not_mapped(map, ttb1)) {
			EMSG("overlapping mapping ! trap CPU");
			TEE_ASSERT(0);
		}

		map_memarea(map, ttb1);

		if (map->type == MEM_AREA_TEE_RAM)
			map_tee_ram = map;
		else if (map->type == MEM_AREA_TA_RAM)
			map_ta_ram = map;
		else if (map->type == MEM_AREA_NSEC_SHM)
			map_nsec_shm = map;

		map++;
	}

	if ((map_tee_ram == NULL) || (map_ta_ram == NULL) ||
	    (map_nsec_shm == NULL)) {
		EMSG("mapping area missing");
		TEE_ASSERT(0);
	}

	static_memory_map = in;
}

/*
 * core_init_mmu - init tee core default memory mapping
 *
 * location of target MMU L1 table is provided as argument.
 * this routine sets the static default tee core mapping.
 *
 * If an error happend: core_init_mmu.c is expected to reset.
 */
void core_init_mmu_tables(void)
{
	load_bootcfg_mapping((void *)core_mmu_get_main_ttb_va());
}

void core_init_mmu_regs(void)
{
	uint32_t sctlr;
	paddr_t ttb_pa = core_mmu_get_main_ttb_pa();

	/*
	 * Program Domain access control register with two domains:
	 * domain 0: teecore
	 * domain 1: TA
	 */
	write_dacr(DACR_DOMAIN(0, DACR_DOMAIN_PERM_CLIENT) |
		   DACR_DOMAIN(1, DACR_DOMAIN_PERM_CLIENT));

	/*
	 * Disable TEX Remap
	 * (This allows TEX field in page table entry take affect)
	 */
	sctlr = read_sctlr();
	sctlr &= ~SCTLR_TRE;
	write_sctlr(sctlr);

	/*
	 * Enable lookups using TTBR0 and TTBR1 with the split of addresses
	 * defined by TEE_MMU_TTBCR_N_VALUE.
	 */
	write_ttbcr(TEE_MMU_TTBCR_N_VALUE);

	write_ttbr0(ttb_pa | TEE_MMU_DEFAULT_ATTRS);
	write_ttbr1(ttb_pa | TEE_MMU_DEFAULT_ATTRS);
}

/* routines to retreive shared mem configuration */
bool core_mmu_is_shm_cached(void)
{
	return map_nsec_shm ? map_nsec_shm->cached : false;
}

/*
 * test attributes of target physical buffer
 *
 * Flags: pbuf_is(SECURE, NOT_SECURE, RAM, IOMEM, KEYVAULT).
 *
 */
bool core_pbuf_is(uint32_t attr, tee_paddr_t pbuf, size_t len)
{
	struct map_area *map;

	/* Empty buffers complies with anything */
	if (len == 0)
		return true;

	switch (attr) {
	case CORE_MEM_SEC:
		return ((platform_pbuf_is_t)bootcfg_pbuf_is)(attr, pbuf, len);
	case CORE_MEM_NON_SEC:
		return ((platform_pbuf_is_t)bootcfg_pbuf_is)(attr, pbuf, len);
	case CORE_MEM_TEE_RAM:
		return pbuf_inside_map_area(pbuf, len, map_tee_ram);
	case CORE_MEM_TA_RAM:
		return pbuf_inside_map_area(pbuf, len, map_ta_ram);
	case CORE_MEM_NSEC_SHM:
		return pbuf_inside_map_area(pbuf, len, map_nsec_shm);
	case CORE_MEM_MULTPURPOSE:
		return ((platform_pbuf_is_t)bootcfg_pbuf_is)(attr, pbuf, len);
	case CORE_MEM_EXTRAM:
		return ((platform_pbuf_is_t)bootcfg_pbuf_is)(attr, pbuf, len);
	case CORE_MEM_CACHED:
		map = find_map_by_pa(pbuf);
		if (map == NULL || !pbuf_inside_map_area(pbuf, len, map))
			return false;
		return map->cached;
	default:
		return false;
	}
}

/* test attributes of target virtual buffer (in core mapping) */
bool core_vbuf_is(uint32_t attr, const void *vbuf, size_t len)
{
	uint32_t p;

	/* Empty buffers complies with anything */
	if (len == 0)
		return true;

	if (core_va2pa((void *)vbuf, &p))
		return false;

	return core_pbuf_is(attr, (tee_paddr_t)p, len);
}

/* core_va2pa - teecore exported service */
int core_va2pa_helper(void *va, paddr_t *pa)
{
	struct map_area *map;

	map = find_map_by_va(va);
	if (map == NULL)
		return -1;

	*pa = ((uintptr_t)va & (map->region_size - 1)) |
	    ((map->pa + (uintptr_t)va - map->va) & ~(map->region_size - 1));
	return 0;
}

/* core_pa2va - teecore exported service */
int core_pa2va_helper(paddr_t pa, void **va)
{
	struct map_area *map;

	map = find_map_by_pa((unsigned long)pa);
	if (map == NULL)
		return -1;

	*va = (void *)((pa & (map->region_size - 1)) |
	    (((map->va + pa - map->pa)) & ~(map->region_size - 1)));
	return 0;
}

/*
 * teecore gets some memory area definitions
 */
void core_mmu_get_mem_by_type(unsigned int type, unsigned int *s,
			      unsigned int *e)
{
	struct map_area *map;

	/* first scan the bootcfg memory layout */
	map = static_memory_map;
	while (map->type != MEM_AREA_NOTYPE) {
		if (map->type == type) {
			*s = map->va;
			*e = map->va + map->size;
			return;
		}
		map++;
	}
	*s = 0;
	*e = 0;
}

int core_tlb_maintenance(int op, unsigned int a)
{
	switch (op) {
	case TLBINV_UNIFIEDTLB:
		secure_mmu_unifiedtlbinvall();
		break;
	case TLBINV_CURRENT_ASID:
		secure_mmu_unifiedtlbinv_curasid();
		break;
	case TLBINV_BY_ASID:
		secure_mmu_unifiedtlbinv_byasid(a);
		break;
	case TLBINV_BY_MVA:
		EMSG("TLB_INV_SECURE_MVA is not yet supported!");
		while (1)
			;
		secure_mmu_unifiedtlbinvbymva(a);
		break;
	default:
		return 1;
	}
	return 0;
}

unsigned int cache_maintenance_l1(int op, void *va, size_t len)
{
	switch (op) {
	case DCACHE_CLEAN:
		arm_cl1_d_cleanbysetway();
		break;
	case DCACHE_AREA_CLEAN:
		if (len)
			arm_cl1_d_cleanbyva(va, (char *)va + len - 1);
		break;
	case DCACHE_INVALIDATE:
		arm_cl1_d_invbysetway();
		break;
	case DCACHE_AREA_INVALIDATE:
		if (len)
			arm_cl1_d_invbyva(va, (char *)va + len - 1);
		break;
	case ICACHE_INVALIDATE:
		arm_cl1_i_inv_all();
		break;
	case ICACHE_AREA_INVALIDATE:
		if (len)
			arm_cl1_i_inv(va, (char *)va + len - 1);
		break;
	case WRITE_BUFFER_DRAIN:
		DMSG("unsupported operation 0x%X (WRITE_BUFFER_DRAIN)",
		     (unsigned int)op);
		return -1;
	case DCACHE_CLEAN_INV:
		arm_cl1_d_cleaninvbysetway();
		break;
	case DCACHE_AREA_CLEAN_INV:
		if (len)
			arm_cl1_d_cleaninvbyva(va, (char *)va + len - 1);
		break;
	default:
		return TEE_ERROR_NOT_IMPLEMENTED;
	}
	return TEE_SUCCESS;
}

/*
 * outer cahce maintenance mutex shared with NSec.
 *
 * At boot, teecore do not need a shared mutex with NSec.
 * Once core has entered NSec state, teecore is not allowed to run outer cache
 * maintenace sequence unless it has necogiate with NSec a shared mutex to
 * spin lock on.
 *
 * In some situation (i.e boot, hibernation), teecore natively synchronise the
 * cores and hence do not need to rely on NSec shared mutex. This can happend
 * with NSec having previously negociated a shared mutex or not. Thus if
 * teecore "disables" the outer (l2cc) shared mutex, it must be able to backup
 * the registered one when enabling back the shared mutex.
 *
 * Currently no multi-cpu lock synchronisation: teecore runs execlusivley on
 * 1 core at a given time.
 */
static unsigned int *l2cc_mutex;
static bool l2cc_mutex_required;	/* default false */

void core_l2cc_mutex_set(void *mutex)
{
	l2cc_mutex = (unsigned int *)mutex;
}
void core_l2cc_mutex_activate(bool en)
{
	l2cc_mutex_required = en;
}

void core_l2cc_mutex_lock(void)
{
	if (l2cc_mutex_required)
		cpu_spin_lock(l2cc_mutex);
}

void core_l2cc_mutex_unlock(void)
{
	if (l2cc_mutex_required)
		cpu_spin_unlock(l2cc_mutex);
}

__weak unsigned int cache_maintenance_l2(int op __unused,
			paddr_t pa __unused, size_t len __unused)
{
	/*
	 * L2 Cache is not available on each platform
	 * This function should be redefined in platform specific
	 * part, when L2 cache is available
	 */

	return TEE_ERROR_NOT_IMPLEMENTED;
}

__weak void *core_mmu_alloc_l2(struct map_area *map __unused)
{
	/*
	 * This function should be redefined in platform specific part if
	 * needed.
	 */
	return NULL;
}
