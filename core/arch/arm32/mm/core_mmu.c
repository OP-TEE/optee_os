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
#include <mm/core_mmu.h>
#include <mm/core_memprot.h>
#include <mm/tee_mmu.h>
#include <mm/tee_mmu_defs.h>
#include <kernel/tee_core_trace.h>

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

/*
 * Save TTBR0 per CPU core running ARM-TZ. (Actually only 1 cpu run TEE)
 * Save TTBR0 used for TA ampping (kTA or uTA).
 * Currently not in BSS since BSS is init after MMU setup.
 */
static unsigned int core_ttbr0[CFG_TEE_CORE_NB_CORE] = { ~0, ~0 };
static unsigned int coreta_ttbr0_pa[CFG_TEE_CORE_NB_CORE] = { ~0, ~0 };
static unsigned int coreta_ttbr0_va[CFG_TEE_CORE_NB_CORE] = { ~0, ~0 };

/* bss is not init: def value must be non-zero */
static bool memmap_notinit[CFG_TEE_CORE_NB_CORE] = { true, true };

#define MEMLAYOUT_NOT_INIT 1
#define MEMLAYOUT_INIT 2
static int memlayout_init = MEMLAYOUT_NOT_INIT;

/* check if target buffer fits in a core default map area */
static bool pbuf_inside_map_area(unsigned long p, size_t l,
				 struct map_area *map)
{
	if ((map->size == 0) ||
	    (((uint32_t) p + l) < (uint32_t) p) ||
	    ((uint32_t) p < map->pa) ||
	    (((uint32_t) p + l) > (map->pa + map->size)))
		return false;
	return true;
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

/*
* map_memarea - load mapping in target L1 table
* A finer mapping must be supported. Currently section mapping only!
*/
static int map_memarea(struct map_area *map, void *ttbr0)
{
	uint32_t m, n;
	unsigned long attr;

	/*
	 * invalid area confing
	 * - only section mapping currently supported
	 * - first section cannot be mapped (safety)
	 */
	if ((map == NULL) ||
	    (ttbr0 == NULL) ||
	    (map->va != 0) ||
	    (map->region_size != 0) ||
	    (map->pa == 0) ||
	    ((map->pa + map->size - 1) < map->pa) ||
	    (map->size == 0) ||
	    (map->size & 0x000FFFFF) ||
	    (map->pa & 0x000FFFFF) || (map->va & 0x000FFFFF)) {
		while (1)
			;
		return 1;
	}

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

	map->va = map->pa;	/* 1-to-1 pa=va mapping */
	map->region_size = 1 << 20;	/* 1MB section mapping */

	m = (map->pa >> 20) * 4;
	n = map->size >> 20;
	while (n--) {
		*((uint32_t *)((uint32_t)ttbr0 + m)) = (m << 18) | attr;
		m += 4;
	}

	return 0;
}

/* load_bootcfg_mapping - attempt to map the teecore static mapping */
static void load_bootcfg_mapping(void *ttbr0)
{
	struct map_area *map, *in;
	uint32_t *p, n;

	/* get memory bootcfg from system */
	in = bootcfg_get_memory();
	if (!in) {
		EMSG("Invalid memory map");
		assert(0);
	}
	bootcfg_pbuf_is = (unsigned long)bootcfg_get_pbuf_is_handler();
	if (bootcfg_pbuf_is == 0) {
		EMSG("invalid platform handler for pbuf_is");
		assert(0);
	}

	/* we must find at least a PUB_RAM area and a TEE_RAM area */
	map_tee_ram = NULL;
	map_ta_ram = NULL;
	map_nsec_shm = NULL;

	/* reset L1 table */
	for (p = (uint32_t *)ttbr0, n = 4096; n > 0; n--)
		*(p++) = 0;

	/* map what needs to be mapped (non-null size and non INTRAM/EXTRAM) */
	map = in;
	while (map->type != MEM_AREA_NOTYPE) {
		if (memarea_not_mapped(map, ttbr0) == false) {
			EMSG("overlapping mapping ! trap CPU");
			assert(0);
		}

		if (map_memarea(map, ttbr0)) {
			EMSG("mapping failed ! trap CPU");
			assert(0);
		}

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
		assert(0);
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
unsigned int core_init_mmu(unsigned int ttbr0, unsigned int ta_ttbr0)
{
	uint32_t n;

	if (secure_get_cpu_id() >= CFG_TEE_CORE_NB_CORE) {
		EMSG("invalid core ID %d. teecore supports %d cores.",
		     secure_get_cpu_id(), CFG_TEE_CORE_NB_CORE);
		assert(0);
	}

	if ((ttbr0 & TEE_MMU_TTBRX_ATTR_MASK) ||
	    (ta_ttbr0 & TEE_MMU_TTBRX_ATTR_MASK)) {
		EMSG("invalid MMU L1 addr: core=0x%X TA=0x%X", ttbr0, ta_ttbr0);
		assert(0);
	}

	if (memlayout_init == MEMLAYOUT_INIT)
		goto skip_mmu_fill;

	/* Note that the initialization of the mmu may depend on the cutID */
	load_bootcfg_mapping((void *)ttbr0);
	memlayout_init = MEMLAYOUT_INIT;

skip_mmu_fill:
	/* All CPUs currently use the same mapping, even on SMP */
	n = secure_get_cpu_id();
	ttbr0 |= TEE_MMU_DEFAULT_ATTRS;
	core_ttbr0[n] = ttbr0;
	cpu_write_ttbr0(ttbr0);

	memmap_notinit[n] = false;

	/* prepare TA mmu table handling */
	/* Support 1 TA MMU table location per CPU core must be implemented */
	if (core_pa2va(ta_ttbr0, (uint32_t *)&(coreta_ttbr0_va[n]))) {
		EMSG("failed to get virtual address of ta_ttbr0 0x%X",
		     ta_ttbr0);
		assert(0);
	}
	coreta_ttbr0_pa[n] = ta_ttbr0;

	return 0;
}

/* return the tee core CP15 TTBR0 */
uint32_t core_mmu_get_ttbr0(void)
{
	return core_ttbr0[secure_get_cpu_id()];
}

/* return the tee core mmu L1 table base address */
uint32_t core_mmu_get_ttbr0_base(void)
{
	return core_mmu_get_ttbr0() & TEE_MMU_TTBRX_TTBX_MASK;
}

/* return the tee core mmu L1 attributes */
uint32_t core_mmu_get_ttbr0_attr(void)
{
	return core_mmu_get_ttbr0() & TEE_MMU_TTBRX_ATTR_MASK;
}

/* return physical address of MMU L1 table of for TA mapping */
uint32_t core_mmu_get_ta_ul1_pa(void)
{
	return coreta_ttbr0_pa[secure_get_cpu_id()];
}

/* return virtual address of MMU L1 table of for TA mapping */
uint32_t core_mmu_get_ta_ul1_va(void)
{
	return coreta_ttbr0_va[secure_get_cpu_id()];
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
		return ((platform_pbuf_is_t) bootcfg_pbuf_is) (attr, pbuf, len);
	case CORE_MEM_NON_SEC:
		return ((platform_pbuf_is_t) bootcfg_pbuf_is) (attr, pbuf, len);
	case CORE_MEM_TEE_RAM:
		return pbuf_inside_map_area(pbuf, len, map_tee_ram);
	case CORE_MEM_TA_RAM:
		return pbuf_inside_map_area(pbuf, len, map_ta_ram);
	case CORE_MEM_NSEC_SHM:
		return pbuf_inside_map_area(pbuf, len, map_nsec_shm);
		/* MultiPurpose and External RAM tests are platform specific */
	case CORE_MEM_MULTPURPOSE:
		return ((platform_pbuf_is_t) bootcfg_pbuf_is) (attr, pbuf, len);
	case CORE_MEM_EXTRAM:
		return ((platform_pbuf_is_t) bootcfg_pbuf_is) (attr, pbuf, len);
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
	TEE_Result res;

	/* Empty buffers complies with anything */
	if (len == 0)
		return true;

	if (!tee_mmu_is_kernel_mapping()) {
		res = tee_mmu_kmap_va2pa_helper((void *)vbuf, (void **)&p);
		if (res != TEE_SUCCESS)
			return false;
	} else if (core_va2pa((uint32_t)vbuf, &p)) {
		return false;
	}

	return core_pbuf_is(attr, (tee_paddr_t)p, len);
}

/*
 * Return true is MMU is initialized for current core
 * Note that this is for DEBUG only, to help preventing
 * use of pa2va va2pa before mmu table is setup !
 */
static bool is_coremap_init(void)
{
	return !memmap_notinit[secure_get_cpu_id()];
}

/* core_va2pa - teecore exported service */
int core_va2pa(uint32_t va, uint32_t *pa)
{
	struct map_area *map;

	if (!is_coremap_init())
		return -1;

	map = find_map_by_va((void *)va);
	if (map == NULL)
		return -1;

	*pa = (va & (map->region_size - 1)) |
	    ((map->pa + va - map->va) & ~(map->region_size - 1));
	return 0;
}

/* core_pa2va - teecore exported service */
int core_pa2va(uint32_t pa, uint32_t *va)
{
	struct map_area *map;

	if (!is_coremap_init())
		return -1;

	map = find_map_by_pa((unsigned long)pa);
	if (map == NULL)
		return -1;

	*va = (pa & (map->region_size - 1)) |
	    (((map->va + pa - map->pa)) & ~(map->region_size - 1));
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
	case TLBINV_DATATLB:
		secure_mmu_datatlbinvall();	/* ??? */
		break;
	case TLBINV_UNIFIEDTLB:
		secure_mmu_unifiedtlbinvall();
		break;
	case TLBINV_CURRENT_ASID:
		secure_mmu_unifiedtlbinv_curasid();
		break;
	case TLBINV_BY_ASID:
		SMSG("TLBINV_BY_ASID is not yet supproted. Trap CPU!");
		while (1)
			;
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

static unsigned int cache_maintenance_l1(int op, void *start, size_t len)
{
	switch (op) {
	case DCACHE_CLEAN:
		arm_cl1_d_cleanbysetway();
		break;
	case DCACHE_AREA_CLEAN:
		arm_cl1_d_cleanbysetway();
		break;
	case DCACHE_INVALIDATE:
		arm_cl1_d_invbysetway();
		break;
	case DCACHE_AREA_INVALIDATE:
		arm_cl1_d_invbysetway();
		break;
	case ICACHE_INVALIDATE:
		arm_cl1_i_inv_all();
		break;
	case ICACHE_AREA_INVALIDATE:
		arm_cl1_i_inv_all();
		break;
	case WRITE_BUFFER_DRAIN:
		DMSG("unsupported operation 0x%X (WRITE_BUFFER_DRAIN)",
		     (unsigned int)op);
		return -1;
	case DCACHE_CLEAN_INV:
		arm_cl1_d_cleaninvbysetway();
		break;
	case DCACHE_AREA_CLEAN_INV:
		arm_cl1_d_cleaninvbysetway();
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

__attribute__((weak)) unsigned int cache_maintenance_l2(
	int op __unused, void *start __unused, size_t len __unused)
{
	/*
	 * L2 Cache is not available on each platform
	 * This function should be redefined in platform specific
	 * part, when L2 cache is available
	 */

	return TEE_ERROR_NOT_IMPLEMENTED;
}

unsigned int core_cache_maintenance(int op, void *start, size_t len)
{
	unsigned int ret;

	ret = cache_maintenance_l1(op, start, len);
	if (ret != TEE_ERROR_NOT_IMPLEMENTED)
		return ret;

	ret = cache_maintenance_l2(op, start, len);
	if (ret != TEE_ERROR_NOT_IMPLEMENTED)
		return ret;

	EMSG("unsupported operation 0x%X", (unsigned int)op);
	return TEE_ERROR_GENERIC;
}
