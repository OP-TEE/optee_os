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
#include <trace.h>
#include <kernel/tee_misc.h>
#include <kernel/panic.h>
#include <util.h>
#include "core_mmu_private.h"

#define MAX_MMAP_REGIONS	10

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

static void insert_mmap(struct tee_mmap_region *mm, size_t max_elem,
		struct tee_mmap_region *mme)
{
	size_t n;

	for (n = 0; n < (max_elem - 1); n++) {
		if (!mm[n].size) {
			mm[n] = *mme;
			return;
		}

		if (core_is_buffer_intersect(mme->va, mme->size, mm[n].va,
					     mm[n].size)) {
			vaddr_t end_va;

			/* Check that the overlapping maps are compatible */
			if (mme->attr != mm[n].attr ||
			    (mme->pa - mme->va) != (mm[n].pa - mm[n].va)) {
				EMSG("Incompatible mmap regions");
				panic();
			}

			/* Grow the current map */
			end_va = MAX(mme->va + mme->size,
				     mm[n].va + mm[n].size);
			mm[n].va = MIN(mme->va, mm[n].va);
			mm[n].pa = MIN(mme->pa, mm[n].pa);
			mm[n].size = end_va - mm[n].va;
			return;
		}

		if (mme->va < mm[n].va) {
			memmove(mm + n + 1, mm + n,
				(max_elem - n - 1) * sizeof(*mm));
			mm[n] = *mme;
			/*
			 * Panics if the terminating element was
			 * overwritten.
			 */
			if (mm[max_elem - 1].size)
				break;
			return;
		}
	}
	EMSG("Too many mmap regions");
	panic();
}

static void core_mmu_mmap_init(struct tee_mmap_region *mm, size_t max_elem,
		struct map_area *map)
{
	struct tee_mmap_region mme;
	size_t n;

	memset(mm, 0, max_elem * sizeof(struct tee_mmap_region));

	for (n = 0; map[n].type != MEM_AREA_NOTYPE; n++) {
		mme.pa = map[n].pa;
		mme.va = map[n].pa;
		mme.size = map[n].size;

		mme.attr = TEE_MATTR_VALID_BLOCK | TEE_MATTR_PR |
			   TEE_MATTR_GLOBAL;

		if (map[n].device || !map[n].cached)
			mme.attr |= TEE_MATTR_NONCACHE;
		else
			mme.attr |= TEE_MATTR_CACHE_DEFAULT;

		if (map[n].rw)
			mme.attr |= TEE_MATTR_PW;

		if (map[n].exec)
			mme.attr |= TEE_MATTR_PX;

		if (map[n].secure)
			mme.attr |= TEE_MATTR_SECURE;

		insert_mmap(mm, max_elem, &mme);
	}
}



/*
 * core_init_mmu_map - init tee core default memory mapping
 *
 * this routine sets the static default tee core mapping.
 *
 * If an error happend: core_init_mmu_map is expected to reset.
 */
void core_init_mmu_map(void)
{
	struct tee_mmap_region mm[MAX_MMAP_REGIONS + 1];
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

	/* map what needs to be mapped (non-null size and non INTRAM/EXTRAM) */
	map = in;
	while (map->type != MEM_AREA_NOTYPE) {
		if (map->va)
			panic();

		map->va = map->pa;	/* 1-to-1 pa = va mapping */
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

	core_mmu_mmap_init(mm, ARRAY_SIZE(mm), in);

	core_init_mmu_tables(mm);
}

/* routines to retrieve shared mem configuration */
bool core_mmu_is_shm_cached(void)
{
	return map_nsec_shm ? map_nsec_shm->cached : false;
}

bool core_mmu_mattr_is_ok(uint32_t mattr)
{
	/*
	 * Keep in sync with core_mmu_lpae.c:mattr_to_desc and
	 * core_mmu_v7.c:mattr_to_texcb
	 */

	switch (mattr & (TEE_MATTR_I_WRITE_THR | TEE_MATTR_I_WRITE_BACK |
			 TEE_MATTR_O_WRITE_THR | TEE_MATTR_O_WRITE_BACK)) {
	case TEE_MATTR_NONCACHE:
	case TEE_MATTR_I_WRITE_BACK | TEE_MATTR_O_WRITE_BACK:
		return true;
	default:
		return false;
	}
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
void core_mmu_get_mem_by_type(unsigned int type, vaddr_t *s, vaddr_t *e)
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
