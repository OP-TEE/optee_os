// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018, EPAM Systems. All rights reserved.
 * Copyright (c) 2023-2024, Linaro Limited
 */

#include <bitstring.h>
#include <compiler.h>
#include <kernel/boot.h>
#include <kernel/linker.h>
#include <kernel/misc.h>
#include <kernel/mutex.h>
#include <kernel/notif.h>
#include <kernel/panic.h>
#include <kernel/refcount.h>
#include <kernel/spinlock.h>
#include <kernel/thread_spmc.h>
#include <kernel/virtualization.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <mm/phys_mem.h>
#include <mm/tee_mm.h>
#include <platform_config.h>
#include <sm/optee_smc.h>
#include <string.h>
#include <string_ext.h>
#include <util.h>

LIST_HEAD(prtn_list_head, guest_partition);

static unsigned int prtn_list_lock __nex_data = SPINLOCK_UNLOCK;

static struct prtn_list_head prtn_list __nex_data =
	LIST_HEAD_INITIALIZER(prtn_list);
static struct prtn_list_head prtn_destroy_list __nex_data =
	LIST_HEAD_INITIALIZER(prtn_destroy_list);

/* Memory used by OP-TEE core */
struct memory_map *kmem_map __nex_bss;

struct guest_spec_data {
	size_t size;
	void (*destroy)(void *data);
};

static bool add_disabled __nex_bss;
static unsigned gsd_count __nex_bss;
static struct guest_spec_data *gsd_array __nex_bss;

struct guest_partition {
	LIST_ENTRY(guest_partition) link;
	struct mmu_partition *mmu_prtn;
	struct memory_map mem_map;
	struct mutex mutex;
	void *tables_va;
	tee_mm_entry_t *tee_ram;
	tee_mm_entry_t *ta_ram;
	tee_mm_entry_t *tables;
	bool runtime_initialized;
	bool got_guest_destroyed;
	bool shutting_down;
	uint16_t id;
	struct refcount refc;
#ifdef CFG_CORE_SEL1_SPMC
	uint64_t cookies[SPMC_CORE_SEL1_MAX_SHM_COUNT];
	uint8_t cookie_count;
	bitstr_t bit_decl(shm_bits, SPMC_CORE_SEL1_MAX_SHM_COUNT);
#endif
	void **data_array;
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
	size_t ta_size = nex_phys_mem_get_ta_size();

	return ROUNDDOWN(ta_size / CFG_VIRT_GUEST_COUNT - VCORE_UNPG_RW_SZ -
			 core_mmu_get_total_pages_size(), SMALL_PAGE_SIZE);
}

static TEE_Result prepare_memory_map(struct memory_map *mem_map,
				     paddr_t tee_data)
{
	struct tee_mmap_region *map = NULL;
	vaddr_t max_va = 0;
	size_t n = 0;
	/*
	 * This function assumes that at time of operation,
	 * kmemory_map (aka static_memory_map from core_mmu.c)
	 * will not be altered. This is true, because all
	 * changes to static_memory_map are done during
	 * OP-TEE initialization, while this function will
	 * called when hypervisor creates a guest.
	 */

	/* Allocate entries for virtual guest map */
	mem_map->map = nex_calloc(kmem_map->count + 1, sizeof(*mem_map->map));
	if (!mem_map->map)
		return TEE_ERROR_OUT_OF_MEMORY;
	mem_map->count = kmem_map->count;
	mem_map->alloc_count = kmem_map->count + 1;

	memcpy(mem_map->map, kmem_map->map,
	       sizeof(*mem_map->map) * mem_map->count);

	/* Map TEE .data and .bss sections */
	for (n = 0; n < mem_map->count; n++) {
		map = mem_map->map + n;
		if (map->va == (vaddr_t)(VCORE_UNPG_RW_PA)) {
			map->type = MEM_AREA_TEE_RAM_RW;
			map->attr = core_mmu_type_to_attr(map->type);
			map->pa = tee_data;
		}
		if (map->va + map->size > max_va)
			max_va = map->va + map->size;
	}

	DMSG("New map (%08lx):",  (vaddr_t)(VCORE_UNPG_RW_PA));

	for (n = 0; n < mem_map->count; n++)
		DMSG("T: %-16s rsz: %08x, pa: %08lx, va: %08lx, sz: %08lx attr: %x",
		     teecore_memtype_name(mem_map->map[n].type),
		     mem_map->map[n].region_size, mem_map->map[n].pa,
		     mem_map->map[n].va, mem_map->map[n].size,
		     mem_map->map[n].attr);
	return TEE_SUCCESS;
}

void virt_init_memory(struct memory_map *mem_map, paddr_t secmem0_base,
		      paddr_size_t secmem0_size, paddr_t secmem1_base,
		      paddr_size_t secmem1_size)
{
	size_t n = 0;

	/* Init page pool that covers all secure RAM */
	nex_phys_mem_init(secmem0_base, secmem0_size, secmem1_base,
			  secmem1_size);

	/* Carve out areas that are used by OP-TEE core */
	for (n = 0; n < mem_map->count; n++) {
		struct tee_mmap_region *map = mem_map->map + n;

		switch (map->type) {
		case MEM_AREA_TEE_RAM_RX:
		case MEM_AREA_TEE_RAM_RO:
		case MEM_AREA_NEX_RAM_RO:
		case MEM_AREA_NEX_RAM_RW:
			DMSG("Carving out area of type %d (0x%08lx-0x%08lx)",
			     map->type, map->pa, map->pa + map->size);
			if (!nex_phys_mem_alloc2(map->pa, map->size))
				panic("Can't carve out used area");
			break;
		default:
			continue;
		}
	}

	kmem_map = mem_map;
}


static TEE_Result configure_guest_prtn_mem(struct guest_partition *prtn)
{
	TEE_Result res = TEE_SUCCESS;
	paddr_t original_data_pa = 0;

	prtn->tee_ram = nex_phys_mem_core_alloc(VCORE_UNPG_RW_SZ);
	if (!prtn->tee_ram) {
		EMSG("Can't allocate memory for TEE runtime context");
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto err;
	}
	DMSG("TEE RAM: %08" PRIxPA, tee_mm_get_smem(prtn->tee_ram));

	prtn->ta_ram = nex_phys_mem_ta_alloc(get_ta_ram_size());
	if (!prtn->ta_ram) {
		EMSG("Can't allocate memory for TA data");
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto err;
	}
	DMSG("TA RAM: %08" PRIxPA, tee_mm_get_smem(prtn->ta_ram));

	prtn->tables = nex_phys_mem_core_alloc(core_mmu_get_total_pages_size());
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

	res = prepare_memory_map(&prtn->mem_map,
				 tee_mm_get_smem(prtn->tee_ram));
	if (res)
		goto err;

	core_init_mmu_prtn(prtn->mmu_prtn, &prtn->mem_map);

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
	nex_free(prtn->mem_map.map);

	return res;
}

static void destroy_gsd(struct guest_partition *prtn, bool free_only)
{
	size_t n = 0;

	for (n = 0; n < gsd_count; n++) {
		if (!free_only && prtn->data_array[n] && gsd_array[n].destroy)
			gsd_array[n].destroy(prtn->data_array[n]);
		nex_free(prtn->data_array[n]);
	}
	nex_free(prtn->data_array);
	prtn->data_array = NULL;
}

static TEE_Result alloc_gsd(struct guest_partition *prtn)
{
	unsigned int n = 0;

	if (!gsd_count)
		return TEE_SUCCESS;

	prtn->data_array = nex_calloc(gsd_count, sizeof(void *));
	if (!prtn->data_array)
		return TEE_ERROR_OUT_OF_MEMORY;

	for (n = 0; n < gsd_count; n++) {
		prtn->data_array[n] = nex_calloc(1, gsd_array[n].size);
		if (!prtn->data_array[n]) {
			destroy_gsd(prtn, true /*free_only*/);
			return TEE_ERROR_OUT_OF_MEMORY;
		}
	}

	return TEE_SUCCESS;
}
TEE_Result virt_guest_created(uint16_t guest_id)
{
	struct guest_partition *prtn = NULL;
	TEE_Result res = TEE_SUCCESS;
	uint32_t exceptions = 0;

	if (guest_id == HYP_CLNT_ID)
		return TEE_ERROR_BAD_PARAMETERS;

	prtn = nex_calloc(1, sizeof(*prtn));
	if (!prtn)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = alloc_gsd(prtn);
	if (res)
		goto err_free_prtn;

	prtn->id = guest_id;
	mutex_init(&prtn->mutex);
	refcount_set(&prtn->refc, 1);
	res = configure_guest_prtn_mem(prtn);
	if (res)
		goto err_free_gsd;

	set_current_prtn(prtn);

	malloc_add_pool(__heap1_start, __heap1_end - __heap1_start);
	phys_mem_init(0, 0, tee_mm_get_smem(prtn->ta_ram),
		      tee_mm_get_bytes(prtn->ta_ram));
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

err_free_gsd:
	destroy_gsd(prtn, true /*free_only*/);
err_free_prtn:
	nex_free(prtn);
	return res;
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

static void get_prtn(struct guest_partition *prtn)
{
	if (!refcount_inc(&prtn->refc))
		panic();
}

uint16_t virt_get_guest_id(struct guest_partition *prtn)
{
	if (!prtn)
		return 0;
	return prtn->id;
}

static struct guest_partition *find_guest_by_id_unlocked(uint16_t guest_id)
{
	struct guest_partition *prtn = NULL;

	LIST_FOREACH(prtn, &prtn_list, link)
		if (!prtn->shutting_down && prtn->id == guest_id)
			return prtn;

	return NULL;
}

struct guest_partition *virt_next_guest(struct guest_partition *prtn)
{
	struct guest_partition *ret = NULL;
	uint32_t exceptions = 0;

	exceptions = cpu_spin_lock_xsave(&prtn_list_lock);
	if (prtn)
		ret = LIST_NEXT(prtn, link);
	else
		ret = LIST_FIRST(&prtn_list);

	while (ret && ret->shutting_down)
		ret = LIST_NEXT(prtn, link);
	if (ret)
		get_prtn(ret);
	cpu_spin_unlock_xrestore(&prtn_list_lock, exceptions);

	virt_put_guest(prtn);

	return ret;
}

struct guest_partition *virt_get_current_guest(void)
{
	struct guest_partition *prtn = get_current_prtn();

	if (prtn)
		get_prtn(prtn);
	return prtn;
}

struct guest_partition *virt_get_guest(uint16_t guest_id)
{
	struct guest_partition *prtn = NULL;
	uint32_t exceptions = 0;

	exceptions = cpu_spin_lock_xsave(&prtn_list_lock);
	prtn = find_guest_by_id_unlocked(guest_id);
	if (prtn)
		get_prtn(prtn);
	cpu_spin_unlock_xrestore(&prtn_list_lock, exceptions);

	return prtn;
}

void virt_put_guest(struct guest_partition *prtn)
{
	if (prtn && refcount_dec(&prtn->refc)) {
		uint32_t exceptions = 0;
		bool do_free = true;

		assert(prtn->shutting_down);

		exceptions = cpu_spin_lock_xsave(&prtn_list_lock);
		LIST_REMOVE(prtn, link);
		if (prtn_have_remaining_resources(prtn)) {
			LIST_INSERT_HEAD(&prtn_destroy_list, prtn, link);
			/*
			 * Delay the nex_free() until
			 * virt_reclaim_cookie_from_destroyed_guest()
			 * is done with this partition.
			 */
			do_free = false;
		}
		cpu_spin_unlock_xrestore(&prtn_list_lock, exceptions);

		destroy_gsd(prtn, false /*!free_only*/);
		tee_mm_free(prtn->tee_ram);
		prtn->tee_ram = NULL;
		tee_mm_free(prtn->ta_ram);
		prtn->ta_ram = NULL;
		tee_mm_free(prtn->tables);
		prtn->tables = NULL;
		core_free_mmu_prtn(prtn->mmu_prtn);
		prtn->mmu_prtn = NULL;
		nex_free(prtn->mem_map.map);
		prtn->mem_map.map = NULL;
		if (do_free)
			nex_free(prtn);
	}
}

TEE_Result virt_guest_destroyed(uint16_t guest_id)
{
	struct guest_partition *prtn = NULL;
	uint32_t exceptions = 0;

	IMSG("Removing guest %"PRId16, guest_id);

	exceptions = cpu_spin_lock_xsave(&prtn_list_lock);

	prtn = find_guest_by_id_unlocked(guest_id);
	if (prtn && !prtn->got_guest_destroyed)
		prtn->got_guest_destroyed = true;
	else
		prtn = NULL;

	cpu_spin_unlock_xrestore(&prtn_list_lock, exceptions);

	if (prtn) {
		notif_deliver_atomic_event(NOTIF_EVENT_SHUTDOWN, prtn->id);

		exceptions = cpu_spin_lock_xsave(&prtn_list_lock);
		prtn->shutting_down = true;
		cpu_spin_unlock_xrestore(&prtn_list_lock, exceptions);

		virt_put_guest(prtn);
	} else {
		EMSG("Client with id %d is not found", guest_id);
	}

	return TEE_SUCCESS;
}

TEE_Result virt_set_guest(uint16_t guest_id)
{
	struct guest_partition *prtn = get_current_prtn();

	/* This can be true only if we return from IRQ RPC */
	if (prtn && prtn->id == guest_id)
		return TEE_SUCCESS;

	if (prtn)
		panic("Virtual guest partition is already set");

	prtn = virt_get_guest(guest_id);
	if (!prtn)
		return TEE_ERROR_ITEM_NOT_FOUND;

	set_current_prtn(prtn);
	core_mmu_set_prtn(prtn->mmu_prtn);

	return TEE_SUCCESS;
}

void virt_unset_guest(void)
{
	struct guest_partition *prtn = get_current_prtn();

	if (!prtn)
		return;

	set_current_prtn(NULL);
	core_mmu_set_default_prtn();
	virt_put_guest(prtn);
}

void virt_on_stdcall(void)
{
	struct guest_partition *prtn = get_current_prtn();

	/* Initialize runtime on first std call */
	if (!prtn->runtime_initialized) {
		mutex_lock(&prtn->mutex);
		if (!prtn->runtime_initialized) {
			init_tee_runtime();
			call_driver_initcalls();
			prtn->runtime_initialized = true;
		}
		mutex_unlock(&prtn->mutex);
	}
}

struct memory_map *virt_get_memory_map(void)
{
	struct guest_partition *prtn;

	prtn = get_current_prtn();

	if (!prtn)
		return NULL;

	return &prtn->mem_map;
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

TEE_Result virt_add_guest_spec_data(unsigned int *data_id, size_t data_size,
				    void (*data_destroy)(void *data))
{
	void *p = NULL;

	/*
	 * This function only executes successfully in a single threaded
	 * environment before exiting to the normal world the first time.
	 * If add_disabled is true, it means we're not in this environment
	 * any longer.
	 */

	if (add_disabled)
		return TEE_ERROR_BAD_PARAMETERS;

	p = nex_realloc(gsd_array, sizeof(*gsd_array) * (gsd_count + 1));
	if (!p)
		return TEE_ERROR_OUT_OF_MEMORY;
	gsd_array = p;

	gsd_array[gsd_count] = (struct guest_spec_data){
		.size = data_size,
		.destroy = data_destroy,
	};
	*data_id = gsd_count + 1;
	gsd_count++;
	return TEE_SUCCESS;
}

void *virt_get_guest_spec_data(struct guest_partition *prtn,
			       unsigned int data_id)
{
	assert(data_id);
	if (!data_id || !prtn || data_id > gsd_count)
		return NULL;
	return prtn->data_array[data_id - 1];
}

static TEE_Result virt_disable_add(void)
{
	add_disabled = true;

	return TEE_SUCCESS;
}
nex_release_init_resource(virt_disable_add);
