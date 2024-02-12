// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018, EPAM Systems. All rights reserved.
 * Copyright (c) 2023, Linaro Limited
 */

#include <bitstring.h>
#include <compiler.h>
#include <kernel/boot.h>
#include <kernel/linker.h>
#include <kernel/misc.h>
#include <kernel/mutex.h>
#include <kernel/panic.h>
#include <kernel/refcount.h>
#include <kernel/spinlock.h>
#include <kernel/thread_spmc.h>
#include <kernel/virtualization.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <mm/tee_mm.h>
#include <platform_config.h>
#include <sm/optee_smc.h>
#include <string.h>
#include <util.h>

LIST_HEAD(prtn_list_head, guest_partition);

static unsigned int prtn_list_lock __nex_data = SPINLOCK_UNLOCK;

static struct prtn_list_head prtn_list __nex_data =
	LIST_HEAD_INITIALIZER(prtn_list);
static struct prtn_list_head prtn_destroy_list __nex_data =
	LIST_HEAD_INITIALIZER(prtn_destroy_list);

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
#ifdef CFG_CORE_SEL1_SPMC
	uint64_t cookies[SPMC_CORE_SEL1_MAX_SHM_COUNT];
	uint8_t cookie_count;
	bitstr_t bit_decl(shm_bits, SPMC_CORE_SEL1_MAX_SHM_COUNT);
#endif
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

uint16_t virt_get_current_guest_id(void)
{
	struct guest_partition *prtn = get_current_prtn();

	if (!prtn)
		return 0;
	return prtn->id;
}

static void set_current_prtn(struct guest_partition *prtn)
{
	uint32_t exceptions = thread_mask_exceptions(THREAD_EXCP_FOREIGN_INTR);

	current_partition[get_core_pos()] = prtn;

	thread_unmask_exceptions(exceptions);
}

static size_t get_ta_ram_size(void)
{
	size_t ta_size = 0;

	core_mmu_get_ta_range(NULL, &ta_size);
	return ROUNDDOWN(ta_size / CFG_VIRT_GUEST_COUNT - VCORE_UNPG_RW_SZ -
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

void virt_init_memory(struct tee_mmap_region *memory_map, paddr_t secmem0_base,
		      paddr_size_t secmem0_size, paddr_t secmem1_base,
		      paddr_size_t secmem1_size)
{
	struct tee_mmap_region *map = NULL;
	paddr_size_t size = secmem0_size;
	paddr_t base = secmem0_base;

	if (secmem1_size) {
		assert(secmem0_base + secmem0_size <= secmem1_base);
		size = secmem1_base + secmem1_size - base;
	}

	/* Init page pool that covers all secure RAM */
	if (!tee_mm_init(&virt_mapper_pool, base, size,
			 SMALL_PAGE_SHIFT, TEE_MM_POOL_NEX_MALLOC))
		panic("Can't create pool with free pages");
	DMSG("Created virtual mapper pool from %"PRIxPA" to %"PRIxPA,
	     base, base + size);

	if (secmem1_size) {
		/* Carve out an eventual gap between secmem0 and secmem1 */
		base = secmem0_base + secmem0_size;
		size = secmem1_base - base;
		if (size) {
			DMSG("Carving out gap between secmem0 and secmem1 (0x%"PRIxPA":0x%"PRIxPASZ")",
			     base, size);
			if (!tee_mm_alloc2(&virt_mapper_pool, base, size))
				panic("Can't carve out secmem gap");
		}
	}


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

static bool
prtn_have_remaining_resources(struct guest_partition *prtn __maybe_unused)
{
#ifdef CFG_CORE_SEL1_SPMC
	int i = 0;

	if (prtn->cookie_count)
		return true;
	bit_ffs(prtn->shm_bits, SPMC_CORE_SEL1_MAX_SHM_COUNT, &i);
	return i >= 0;
#else
	return false;
#endif
}

TEE_Result virt_guest_destroyed(uint16_t guest_id)
{
	struct guest_partition *prtn = NULL;
	uint32_t exceptions = 0;
	bool do_free = true;

	IMSG("Removing guest %d", guest_id);

	exceptions = cpu_spin_lock_xsave(&prtn_list_lock);

	LIST_FOREACH(prtn, &prtn_list, link) {
		if (prtn->id == guest_id) {
			if (!refcount_dec(&prtn->refc)) {
				EMSG("Guest thread(s) is still running. refc = %d",
				     refcount_val(&prtn->refc));
				panic();
			}
			LIST_REMOVE(prtn, link);
			if (prtn_have_remaining_resources(prtn)) {
				LIST_INSERT_HEAD(&prtn_destroy_list, prtn,
						 link);
				/*
				 * Delay the nex_free() until
				 * virt_reclaim_cookie_from_destroyed_guest()
				 * is done with this partition.
				 */
				do_free = false;
			}
			break;
		}
	}
	cpu_spin_unlock_xrestore(&prtn_list_lock, exceptions);

	if (prtn) {
		tee_mm_free(prtn->tee_ram);
		prtn->tee_ram = NULL;
		tee_mm_free(prtn->ta_ram);
		prtn->ta_ram = NULL;
		tee_mm_free(prtn->tables);
		prtn->tables = NULL;
		core_free_mmu_prtn(prtn->mmu_prtn);
		prtn->mmu_prtn = NULL;
		nex_free(prtn->memory_map);
		prtn->memory_map = NULL;
		if (do_free)
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

#ifdef CFG_CORE_SEL1_SPMC
static int find_cookie(struct guest_partition *prtn, uint64_t cookie)
{
	int i = 0;

	for (i = 0; i < prtn->cookie_count; i++)
		if (prtn->cookies[i] == cookie)
			return i;
	return -1;
}

static struct guest_partition *find_prtn_cookie(uint64_t cookie, int *idx)
{
	struct guest_partition *prtn = NULL;
	int i = 0;

	LIST_FOREACH(prtn, &prtn_list, link) {
		i = find_cookie(prtn, cookie);
		if (i >= 0) {
			if (idx)
				*idx = i;
			return prtn;
		}
	}

	return NULL;
}

TEE_Result virt_add_cookie_to_current_guest(uint64_t cookie)
{
	TEE_Result res = TEE_ERROR_ACCESS_DENIED;
	struct guest_partition *prtn = NULL;
	uint32_t exceptions = 0;

	exceptions = cpu_spin_lock_xsave(&prtn_list_lock);
	if (find_prtn_cookie(cookie, NULL))
		goto out;

	prtn = current_partition[get_core_pos()];
	if (prtn->cookie_count < ARRAY_SIZE(prtn->cookies)) {
		prtn->cookies[prtn->cookie_count] = cookie;
		prtn->cookie_count++;
		res = TEE_SUCCESS;
	}
out:
	cpu_spin_unlock_xrestore(&prtn_list_lock, exceptions);

	return res;
}

void virt_remove_cookie(uint64_t cookie)
{
	struct guest_partition *prtn = NULL;
	uint32_t exceptions = 0;
	int i = 0;

	exceptions = cpu_spin_lock_xsave(&prtn_list_lock);
	prtn = find_prtn_cookie(cookie, &i);
	if (prtn) {
		memmove(prtn->cookies + i, prtn->cookies + i + 1,
			sizeof(uint64_t) * (prtn->cookie_count - i - 1));
		prtn->cookie_count--;
	}
	cpu_spin_unlock_xrestore(&prtn_list_lock, exceptions);
}

uint16_t virt_find_guest_by_cookie(uint64_t cookie)
{
	struct guest_partition *prtn = NULL;
	uint32_t exceptions = 0;
	uint16_t ret = 0;

	exceptions = cpu_spin_lock_xsave(&prtn_list_lock);
	prtn = find_prtn_cookie(cookie, NULL);
	if (prtn)
		ret = prtn->id;

	cpu_spin_unlock_xrestore(&prtn_list_lock, exceptions);

	return ret;
}

bitstr_t *virt_get_shm_bits(void)
{
	return get_current_prtn()->shm_bits;
}

static TEE_Result reclaim_cookie(struct guest_partition *prtn, uint64_t cookie)
{
	if (cookie & FFA_MEMORY_HANDLE_HYPERVISOR_BIT) {
		size_t n = 0;

		for (n = 0; n < prtn->cookie_count; n++) {
			if (prtn->cookies[n] == cookie) {
				memmove(prtn->cookies + n,
					prtn->cookies + n + 1,
					sizeof(uint64_t) *
						(prtn->cookie_count - n - 1));
				prtn->cookie_count--;
				return TEE_SUCCESS;
			}
		}
	} else {
		uint64_t mask = FFA_MEMORY_HANDLE_NON_SECURE_BIT |
				SHIFT_U64(FFA_MEMORY_HANDLE_PRTN_MASK,
					  FFA_MEMORY_HANDLE_PRTN_SHIFT);
		int64_t i = cookie & ~mask;

		if (i >= 0 && i < SPMC_CORE_SEL1_MAX_SHM_COUNT &&
		    bit_test(prtn->shm_bits, i)) {
			bit_clear(prtn->shm_bits, i);
			return TEE_SUCCESS;
		}
	}

	return TEE_ERROR_ITEM_NOT_FOUND;
}

TEE_Result virt_reclaim_cookie_from_destroyed_guest(uint16_t guest_id,
						    uint64_t cookie)

{
	struct guest_partition *prtn = NULL;
	TEE_Result res = TEE_ERROR_ITEM_NOT_FOUND;
	uint32_t exceptions = 0;

	exceptions = cpu_spin_lock_xsave(&prtn_list_lock);
	LIST_FOREACH(prtn, &prtn_destroy_list, link) {
		if (prtn->id == guest_id) {
			res = reclaim_cookie(prtn, cookie);
			if (prtn_have_remaining_resources(prtn))
				prtn = NULL;
			else
				LIST_REMOVE(prtn, link);
			break;
		}
	}
	cpu_spin_unlock_xrestore(&prtn_list_lock, exceptions);

	nex_free(prtn);

	return res;
}
#endif /*CFG_CORE_SEL1_SPMC*/
