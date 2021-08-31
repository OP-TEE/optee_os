// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2018, EPAM Systems. All rights reserved. */

#include <compiler.h>
#include <platform_config.h>
#include <kernel/boot.h>
#include <kernel/linker.h>
#include <kernel/mutex.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <kernel/refcount.h>
#include <kernel/spinlock.h>
#include <kernel/virtualization.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <mm/tee_mm.h>
#include <platform_config.h>
#include <sm/optee_smc.h>
#include <string.h>
#include <util.h>

static unsigned int prtn_list_lock __nex_data = SPINLOCK_UNLOCK;

static LIST_HEAD(prtn_list_head, guest_partition) prtn_list __nex_data =
	LIST_HEAD_INITIALIZER(prtn_list_head);

/* Free pages used for guest partitions */
tee_mm_pool_t virt_mapper_pool __nex_bss;

/* Memory used by OP-TEE core */
struct tee_mmap_region *kmemory_map __nex_bss;

struct guest_partition {
	LIST_ENTRY(guest_partition) link;
	struct mmu_partition *mmu_prtn;
	struct tee_mmap_region *memory_map;
	struct mutex mutex;
	void *tables_va;
	tee_mm_entry_t *tee_ram;
	tee_mm_entry_t *ta_ram;
	tee_mm_entry_t *tables;
	bool runtime_initialized;
	uint16_t id;
	struct refcount refc;
};

struct guest_partition *current_partition[CFG_TEE_CORE_NB_CORE] __nex_bss;

static struct guest_partition *get_current_prtn(void)
{
	struct guest_partition *ret;
	uint32_t exceptions = thread_mask_exceptions(THREAD_EXCP_FOREIGN_INTR);

	ret = current_partition[get_core_pos()];

	thread_unmask_exceptions(exceptions);

	return ret;
}

static void set_current_prtn(struct guest_partition *prtn)
{
	uint32_t exceptions = thread_mask_exceptions(THREAD_EXCP_FOREIGN_INTR);

	current_partition[get_core_pos()] = prtn;

	thread_unmask_exceptions(exceptions);
}

static size_t get_ta_ram_size(void)
{
	return ROUNDDOWN(TA_RAM_SIZE / CFG_VIRT_GUEST_COUNT -
			 VCORE_UNPG_RW_SZ -
			 core_mmu_get_total_pages_size(), SMALL_PAGE_SIZE);
}

static struct tee_mmap_region *prepare_memory_map(paddr_t tee_data,
						  paddr_t ta_ram)
{
	int i, entries;
	vaddr_t max_va = 0;
	struct tee_mmap_region *map;
	/*
	 * This function assumes that at time of operation,
	 * kmemory_map (aka static_memory_map from core_mmu.c)
	 * will not be altered. This is true, because all
	 * changes to static_memory_map are done during
	 * OP-TEE initialization, while this function will
	 * called when hypervisor creates a guest.
	 */

	/* Count number of entries in nexus memory map */
	for (map = kmemory_map, entries = 1; map->type != MEM_AREA_END;
	     map++, entries++)
		;

	/* Allocate entries for virtual guest map */
	map = nex_calloc(entries + 1, sizeof(struct tee_mmap_region));
	if (!map)
		return NULL;

	memcpy(map, kmemory_map, sizeof(*map) * entries);

	/* Map TEE .data and .bss sections */
	for (i = 0; i < entries; i++) {
		if (map[i].va == (vaddr_t)(VCORE_UNPG_RW_PA)) {
			map[i].type = MEM_AREA_TEE_RAM_RW;
			map[i].attr = core_mmu_type_to_attr(map[i].type);
			map[i].pa = tee_data;
		}
		if (map[i].va + map[i].size > max_va)
			max_va = map[i].va + map[i].size;
	}

	/* Map TA_RAM */
	assert(map[entries - 1].type == MEM_AREA_END);
	map[entries] = map[entries - 1];
	map[entries - 1].region_size = SMALL_PAGE_SIZE;
	map[entries - 1].va = ROUNDUP(max_va, map[entries - 1].region_size);
	map[entries - 1].va +=
		(ta_ram - map[entries - 1].va) & CORE_MMU_PGDIR_MASK;
	map[entries - 1].pa = ta_ram;
	map[entries - 1].size = get_ta_ram_size();
	map[entries - 1].type = MEM_AREA_TA_RAM;
	map[entries - 1].attr = core_mmu_type_to_attr(map[entries - 1].type);

	DMSG("New map (%08lx):",  (vaddr_t)(VCORE_UNPG_RW_PA));

	for (i = 0; i < entries; i++)
		DMSG("T: %-16s rsz: %08x, pa: %08lx, va: %08lx, sz: %08lx attr: %x",
		     teecore_memtype_name(map[i].type),
		     map[i].region_size, map[i].pa, map[i].va,
		     map[i].size, map[i].attr);
	return map;
}

void virt_init_memory(struct tee_mmap_region *memory_map)
{
	struct tee_mmap_region *map;

	/* Init page pool that covers all secure RAM */
	if (!tee_mm_init(&virt_mapper_pool, TEE_RAM_START,
			 TA_RAM_START + TA_RAM_SIZE,
			 SMALL_PAGE_SHIFT,
			 TEE_MM_POOL_NEX_MALLOC))
		panic("Can't create pool with free pages");
	DMSG("Created virtual mapper pool from %x to %x",
	     TEE_RAM_START, TA_RAM_START + TA_RAM_SIZE);

	/* Carve out areas that are used by OP-TEE core */
	for (map = memory_map; map->type != MEM_AREA_END; map++) {
		switch (map->type) {
		case MEM_AREA_TEE_RAM_RX:
		case MEM_AREA_TEE_RAM_RO:
		case MEM_AREA_NEX_RAM_RO:
		case MEM_AREA_NEX_RAM_RW:
			DMSG("Carving out area of type %d (0x%08lx-0x%08lx)",
			     map->type, map->pa, map->pa + map->size);
			if (!tee_mm_alloc2(&virt_mapper_pool, map->pa,
					   map->size))
				panic("Can't carve out used area");
			break;
		default:
			continue;
		}
	}

	kmemory_map = memory_map;
}


static TEE_Result configure_guest_prtn_mem(struct guest_partition *prtn)
{
	TEE_Result res = TEE_SUCCESS;
	paddr_t original_data_pa = 0;

	prtn->tee_ram = tee_mm_alloc(&virt_mapper_pool, VCORE_UNPG_RW_SZ);
	if (!prtn->tee_ram) {
		EMSG("Can't allocate memory for TEE runtime context");
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto err;
	}
	DMSG("TEE RAM: %08" PRIxPA, tee_mm_get_smem(prtn->tee_ram));

	prtn->ta_ram = tee_mm_alloc(&virt_mapper_pool, get_ta_ram_size());
	if (!prtn->ta_ram) {
		EMSG("Can't allocate memory for TA data");
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto err;
	}
	DMSG("TA RAM: %08" PRIxPA, tee_mm_get_smem(prtn->ta_ram));

	prtn->tables = tee_mm_alloc(&virt_mapper_pool,
				   core_mmu_get_total_pages_size());
	if (!prtn->tables) {
		EMSG("Can't allocate memory for page tables");
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	prtn->tables_va = phys_to_virt(tee_mm_get_smem(prtn->tables),
				      MEM_AREA_SEC_RAM_OVERALL,
				      core_mmu_get_total_pages_size());
	assert(prtn->tables_va);

	prtn->mmu_prtn = core_alloc_mmu_prtn(prtn->tables_va);
	if (!prtn->mmu_prtn) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	prtn->memory_map = prepare_memory_map(tee_mm_get_smem(prtn->tee_ram),
					     tee_mm_get_smem(prtn->ta_ram));
	if (!prtn->memory_map) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	core_init_mmu_prtn(prtn->mmu_prtn, prtn->memory_map);

	original_data_pa = virt_to_phys(__data_start);
	/* Switch to guest's mappings */
	core_mmu_set_prtn(prtn->mmu_prtn);

	/* clear .bss */
	memset((void *)(VCORE_UNPG_RW_PA), 0, VCORE_UNPG_RW_SZ);

	/* copy .data section from R/O original */
	memcpy(__data_start,
	       phys_to_virt(original_data_pa, MEM_AREA_SEC_RAM_OVERALL,
			    __data_end - __data_start),
	       __data_end - __data_start);

	return TEE_SUCCESS;

err:
	if (prtn->tee_ram)
		tee_mm_free(prtn->tee_ram);
	if (prtn->ta_ram)
		tee_mm_free(prtn->ta_ram);
	if (prtn->tables)
		tee_mm_free(prtn->tables);
	nex_free(prtn->mmu_prtn);
	nex_free(prtn->memory_map);

	return res;
}

TEE_Result virt_guest_created(uint16_t guest_id)
{
	struct guest_partition *prtn = NULL;
	TEE_Result res = TEE_SUCCESS;
	uint32_t exceptions = 0;

	prtn = nex_calloc(1, sizeof(*prtn));
	if (!prtn)
		return TEE_ERROR_OUT_OF_MEMORY;

	prtn->id = guest_id;
	mutex_init(&prtn->mutex);
	refcount_set(&prtn->refc, 1);
	res = configure_guest_prtn_mem(prtn);
	if (res) {
		nex_free(prtn);
		return res;
	}

	set_current_prtn(prtn);

	/* Initialize threads */
	thread_init_threads();
	/* Do the preinitcalls */
	call_preinitcalls();

	exceptions = cpu_spin_lock_xsave(&prtn_list_lock);
	LIST_INSERT_HEAD(&prtn_list, prtn, link);
	cpu_spin_unlock_xrestore(&prtn_list_lock, exceptions);

	IMSG("Added guest %d", guest_id);

	set_current_prtn(NULL);
	core_mmu_set_default_prtn();

	return TEE_SUCCESS;
}

TEE_Result virt_guest_destroyed(uint16_t guest_id)
{
	struct guest_partition *prtn;
	uint32_t exceptions;

	IMSG("Removing guest %d", guest_id);

	exceptions = cpu_spin_lock_xsave(&prtn_list_lock);

	LIST_FOREACH(prtn, &prtn_list, link) {
		if (prtn->id == guest_id) {
			LIST_REMOVE(prtn, link);
			break;
		}
	}
	cpu_spin_unlock_xrestore(&prtn_list_lock, exceptions);

	if (prtn) {
		if (!refcount_dec(&prtn->refc)) {
			EMSG("Guest thread(s) is still running. refc = %d",
			     refcount_val(&prtn->refc));
			panic();
		}

		tee_mm_free(prtn->tee_ram);
		tee_mm_free(prtn->ta_ram);
		tee_mm_free(prtn->tables);
		core_free_mmu_prtn(prtn->mmu_prtn);
		nex_free(prtn->memory_map);
		nex_free(prtn);
	} else
		EMSG("Client with id %d is not found", guest_id);

	return TEE_SUCCESS;
}

TEE_Result virt_set_guest(uint16_t guest_id)
{
	struct guest_partition *prtn;
	uint32_t exceptions;

	prtn = get_current_prtn();

	/* This can be true only if we return from IRQ RPC */
	if (prtn && prtn->id == guest_id)
		return TEE_SUCCESS;

	if (prtn)
		panic("Virtual guest partition is already set");

	exceptions = cpu_spin_lock_xsave(&prtn_list_lock);
	LIST_FOREACH(prtn, &prtn_list, link) {
		if (prtn->id == guest_id) {
			set_current_prtn(prtn);
			core_mmu_set_prtn(prtn->mmu_prtn);
			refcount_inc(&prtn->refc);
			cpu_spin_unlock_xrestore(&prtn_list_lock,
						 exceptions);
			return TEE_SUCCESS;
		}
	}
	cpu_spin_unlock_xrestore(&prtn_list_lock, exceptions);

	if (guest_id == HYP_CLNT_ID)
		return TEE_SUCCESS;
	return TEE_ERROR_ITEM_NOT_FOUND;
}

void virt_unset_guest(void)
{
	struct guest_partition *prtn = get_current_prtn();

	if (!prtn)
		return;

	set_current_prtn(NULL);
	core_mmu_set_default_prtn();
	if (refcount_dec(&prtn->refc))
		panic();
}

void virt_on_stdcall(void)
{
	struct guest_partition *prtn = get_current_prtn();

	/* Initialize runtime on first std call */
	if (!prtn->runtime_initialized) {
		mutex_lock(&prtn->mutex);
		if (!prtn->runtime_initialized) {
			init_tee_runtime();
			prtn->runtime_initialized = true;
		}
		mutex_unlock(&prtn->mutex);
	}
}

struct tee_mmap_region *virt_get_memory_map(void)
{
	struct guest_partition *prtn;

	prtn = get_current_prtn();

	if (!prtn)
		return NULL;

	return prtn->memory_map;
}

void virt_get_ta_ram(vaddr_t *start, vaddr_t *end)
{
	struct guest_partition *prtn = get_current_prtn();

	*start = (vaddr_t)phys_to_virt(tee_mm_get_smem(prtn->ta_ram),
				       MEM_AREA_TA_RAM,
				       tee_mm_get_bytes(prtn->ta_ram));
	*end = *start + tee_mm_get_bytes(prtn->ta_ram);
}
