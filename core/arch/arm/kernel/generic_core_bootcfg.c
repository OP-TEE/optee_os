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
#include <platform_config.h>
#include <mm/core_mmu.h>
#include <mm/core_memprot.h>
#include <util.h>
#include <kernel/tee_misc.h>
#include <kernel/panic.h>
#include <trace.h>

/* Define the platform's memory layout. */
struct memaccess_area {
	paddr_t paddr;
	size_t size;
};
#define MEMACCESS_AREA(a, s) { .paddr = a, .size = s }

static struct memaccess_area ddr[] = {
	MEMACCESS_AREA(DRAM0_BASE, DRAM0_SIZE),
#ifdef DRAM1_BASE
	MEMACCESS_AREA(DRAM1_BASE, DRAM1_SIZE),
#endif
};

static struct memaccess_area secure_only[] = {
#ifdef TZSRAM_BASE
	MEMACCESS_AREA(TZSRAM_BASE, TZSRAM_SIZE),
#endif
	MEMACCESS_AREA(TZDRAM_BASE, TZDRAM_SIZE),
};

static struct memaccess_area nsec_shared[] = {
	MEMACCESS_AREA(CFG_SHMEM_START, CFG_SHMEM_SIZE),
};

static bool _pbuf_intersects(struct memaccess_area *a, size_t alen,
			     paddr_t pa, size_t size)
{
	size_t n;

	for (n = 0; n < alen; n++)
		if (core_is_buffer_intersect(pa, size, a[n].paddr, a[n].size))
			return true;
	return false;
}
#define pbuf_intersects(a, pa, size) \
	_pbuf_intersects((a), ARRAY_SIZE(a), (pa), (size))

static bool _pbuf_is_inside(struct memaccess_area *a, size_t alen,
			    paddr_t pa, size_t size)
{
	size_t n;

	for (n = 0; n < alen; n++)
		if (core_is_buffer_inside(pa, size, a[n].paddr, a[n].size))
			return true;
	return false;
}
#define pbuf_is_inside(a, pa, size) \
	_pbuf_is_inside((a), ARRAY_SIZE(a), (pa), (size))

static bool pbuf_is_multipurpose(paddr_t paddr, size_t size)
{
	if (pbuf_intersects(secure_only, paddr, size))
		return false;
	if (pbuf_intersects(nsec_shared, paddr, size))
		return false;

	return pbuf_is_inside(ddr, paddr, size);
}

/* Wrapper for the platform specific pbuf_is() service. */
static bool pbuf_is(enum buf_is_attr attr, paddr_t paddr, size_t size)
{
	switch (attr) {
	case CORE_MEM_SEC:
		return pbuf_is_inside(secure_only, paddr, size);

	case CORE_MEM_NON_SEC:
		return pbuf_is_inside(nsec_shared, paddr, size);

	case CORE_MEM_MULTPURPOSE:
		return pbuf_is_multipurpose(paddr, size);

	case CORE_MEM_EXTRAM:
		return pbuf_is_inside(ddr, paddr, size);

	default:
		EMSG("Unexpected request: attr=%X", attr);
		return false;
	}
}

register_phys_mem(MEM_AREA_TEE_RAM, CFG_TEE_RAM_START, CFG_TEE_RAM_PH_SIZE);
register_phys_mem(MEM_AREA_TA_RAM, CFG_TA_RAM_START, CFG_TA_RAM_SIZE);
register_phys_mem(MEM_AREA_NSEC_SHM, CFG_SHMEM_START, CFG_SHMEM_SIZE);
#ifdef DEVICE0_PA_BASE
register_phys_mem(DEVICE0_TYPE, DEVICE0_PA_BASE, DEVICE0_SIZE);
#endif
#ifdef DEVICE1_PA_BASE
register_phys_mem(DEVICE1_TYPE, DEVICE1_PA_BASE, DEVICE1_SIZE);
#endif
#ifdef DEVICE2_PA_BASE
register_phys_mem(DEVICE2_TYPE, DEVICE2_PA_BASE, DEVICE2_SIZE);
#endif
#ifdef DEVICE3_PA_BASE
register_phys_mem(DEVICE3_TYPE, DEVICE3_PA_BASE, DEVICE3_SIZE);
#endif
#ifdef DEVICE4_PA_BASE
register_phys_mem(DEVICE4_TYPE, DEVICE4_PA_BASE, DEVICE4_SIZE);
#endif
#ifdef DEVICE5_PA_BASE
register_phys_mem(DEVICE5_TYPE, DEVICE5_PA_BASE, DEVICE5_SIZE);
#endif
#ifdef DEVICE6_PA_BASE
register_phys_mem(DEVICE6_TYPE, DEVICE6_PA_BASE, DEVICE6_SIZE);
#endif

extern const struct core_mmu_phys_mem __start_phys_mem_map_section;
extern const struct core_mmu_phys_mem __end_phys_mem_map_section;

/* Initialized before .bss is cleared */
static struct map_area bootcfg_memory_map[20] __data;
static bool mem_map_inited __data;

static void add_phys_mem(const struct core_mmu_phys_mem *mem, size_t *last)
{
	size_t n = 0;
	paddr_t pa;
	size_t size;

	DMSG("%s %d 0x%08" PRIxPA " size 0x%08zx",
	     mem->name, mem->type, mem->addr, mem->size);
	while (true) {
		if (n >= (ARRAY_SIZE(bootcfg_memory_map) - 1)) {
			EMSG("Out of entries (%zu) in bootcfg_memory_map",
			     ARRAY_SIZE(bootcfg_memory_map));
			panic();
		}
		if (n == *last)
			break;
		pa = bootcfg_memory_map[n].pa;
		size = bootcfg_memory_map[n].size;
		if (mem->addr >= pa &&
		    mem->addr <= (pa + (size - 1)) &&
		    mem->type == bootcfg_memory_map[n].type) {
			DMSG("Physical mem map overlaps 0x%" PRIxPA, mem->addr);
			bootcfg_memory_map[n].pa = MIN(pa, mem->addr);
			bootcfg_memory_map[n].size =
				MAX(size, mem->size) +
				(pa - bootcfg_memory_map[n].pa);
			return;
		}
		if (mem->type < bootcfg_memory_map[n].type ||
		    (mem->type == bootcfg_memory_map[n].type && mem->addr < pa))
			break;
		n++;
	}

	memmove(bootcfg_memory_map + n + 1, bootcfg_memory_map + n,
		sizeof(struct map_area) * (*last - n));
	(*last)++;
	bootcfg_memory_map[n].type = mem->type;
	bootcfg_memory_map[n].pa = mem->addr;
	bootcfg_memory_map[n].size = mem->size;
}

static void check_mem_map(void)
{
	struct map_area *map = bootcfg_memory_map;
	size_t num_tee_ram = 0;
	size_t num_ta_ram = 0;
	size_t num_nsec_shm = 0;

	while (map->type != MEM_AREA_NOTYPE) {
		switch (map->type) {
		case MEM_AREA_TEE_RAM:
			num_tee_ram++;
			break;
		case MEM_AREA_TA_RAM:
			num_ta_ram++;
			break;
		case MEM_AREA_NSEC_SHM:
			num_nsec_shm++;
			break;
		case MEM_AREA_IO_SEC:
		case MEM_AREA_IO_NSEC:
			break;
		default:
			EMSG("Uhandled memtype %d", map->type);
			panic();
		}
		map++;
	}

	assert(num_tee_ram == 1 && num_ta_ram == 1 && num_nsec_shm == 1);
}

static void init_mem_map(void)
{
	const struct core_mmu_phys_mem *mem;
	struct map_area *map;
	size_t last = 0;
	vaddr_t va;

	for (mem = &__start_phys_mem_map_section;
	     mem < &__end_phys_mem_map_section; mem++) {
		struct core_mmu_phys_mem m = *mem;

		if (m.type == MEM_AREA_IO_NSEC || m.type == MEM_AREA_IO_SEC) {
			m.addr = ROUNDDOWN(m.addr, CORE_MMU_PGDIR_SIZE);
			m.size = ROUNDUP(m.size + (mem->addr - m.addr),
					 CORE_MMU_PGDIR_SIZE);
		}
		add_phys_mem(&m, &last);
	}
	bootcfg_memory_map[last].type = MEM_AREA_NOTYPE;
	check_mem_map();
	/*
	 * bootcfg_memory_map is sorted in order first by type and last by
	 * address. This puts TEE_RAM first and TA_RAM second
	 *
	 */

	map = bootcfg_memory_map;
	assert(map->type == MEM_AREA_TEE_RAM);
	map->va = map->pa;
#ifdef CFG_WITH_PAGER
	map->region_size = SMALL_PAGE_SIZE,
#endif
	map->secure = true;
	map->cached = true;
	map->rw = true;
	map->exec = true;

	if (core_mmu_place_tee_ram_at_top(map->pa)) {
		va = map->va;
		map++;
		while (map->type != MEM_AREA_NOTYPE) {
			switch (map->type) {
			case MEM_AREA_TA_RAM:
				map->secure = true;
				map->cached = true;
				break;
			case MEM_AREA_NSEC_SHM:
				map->cached = true;
				break;
			case MEM_AREA_IO_NSEC:
				map->device = true;
				break;
			case MEM_AREA_IO_SEC:
				map->device = true;
				map->secure = true;
				break;
			default:
				panic();
			}
			va = ROUNDDOWN(va - map->size, CORE_MMU_PGDIR_SIZE);
			map->rw = true;
			map->va = va;
			map++;
		}
	} else {
		va = ROUNDUP(map->va + map->size, CORE_MMU_PGDIR_SIZE);
		map++;
		while (map->type != MEM_AREA_NOTYPE) {
			if (map[-1].secure != map->secure)
				va = ROUNDUP(va, CORE_MMU_PGDIR_SIZE);
			switch (map->type) {
			case MEM_AREA_TA_RAM:
				map->secure = true;
				map->cached = true;
				break;
			case MEM_AREA_NSEC_SHM:
				map->cached = true;
				break;
			case MEM_AREA_IO_NSEC:
				map->device = true;
				break;
			case MEM_AREA_IO_SEC:
				map->device = true;
				map->secure = true;
				break;
			default:
				panic();
			}
			map->rw = true;
			map->va = va;
			va += map->size;
			map++;
		}
	}

	for (map = bootcfg_memory_map; map->type != MEM_AREA_NOTYPE; map++)
		DMSG("type va %d 0x%08" PRIxVA "..0x%08" PRIxVA
		     " pa 0x%08" PRIxPA "..0x%08" PRIxPA " size %#zx",
		     map->type, (vaddr_t)map->va,
		     (vaddr_t)map->va + map->size - 1, (paddr_t)map->pa,
		     (paddr_t)map->pa + map->size - 1, map->size);
}

static struct map_area *get_mem_map(void)
{
	if (!mem_map_inited)
		init_mem_map();
	return bootcfg_memory_map;
}

/* Return the platform specific pbuf_is(). */
unsigned long bootcfg_get_pbuf_is_handler(void)
{
	return (unsigned long)pbuf_is;
}

/*
 * This routine is called when MMU and core memory management are not
 * initialized.
 */
struct map_area *bootcfg_get_memory(void)
{
	struct map_area *map;
	size_t n;

	for (n = 0; n < ARRAY_SIZE(secure_only); n++) {
		if (pbuf_intersects(nsec_shared, secure_only[n].paddr,
				    secure_only[n].size)) {
			EMSG("Invalid memory access configuration: sec/nsec");
			return NULL;
		}
	}

	/* Overlapping will be tested later */
	map = get_mem_map();
	while (map->type != MEM_AREA_NOTYPE) {
		switch (map->type) {
		case MEM_AREA_TEE_RAM:
			if (!pbuf_is_inside(secure_only, map->pa, map->size)) {
				EMSG("TEE_RAM does not fit in secure_only");
				return NULL;
			}
			break;
		case MEM_AREA_TA_RAM:
			if (!pbuf_is_inside(secure_only, map->pa, map->size)) {
				EMSG("TA_RAM does not fit in secure_only");
				return NULL;
			}
			break;
		case MEM_AREA_NSEC_SHM:
			if (!pbuf_is_inside(nsec_shared, map->pa, map->size)) {
				EMSG("NSEC_SHM does not fit in nsec_shared");
				return NULL;
			}
			break;
		default:
			/* Other mapped areas are not checked. */
			break;
		}
		map++;
	}

	return bootcfg_memory_map;
}
