// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021, Arm Limited. All rights reserved.
 */
#include <assert.h>
#include <bitstring.h>
#include <ffa.h>
#include <kernel/spinlock.h>
#include <mm/mobj.h>
#include <mm/sp_mem.h>

#define NUM_SHARES	64

static bitstr_t bit_decl(share_bits, NUM_SHARES);
static unsigned int sp_mem_lock = SPINLOCK_UNLOCK;

/* mem_shares stores all active FF-A shares. */
SLIST_HEAD(sp_mem_head, sp_mem);
static struct sp_mem_head mem_shares = SLIST_HEAD_INITIALIZER(sp_mem_head);
/* Weak instance of mobj_sp_ops mandates it is not static */
const struct mobj_ops mobj_sp_ops;

struct mobj_sp {
	struct mobj mobj;
	paddr_t pages[];
};

static struct mobj_sp *to_mobj_sp(struct mobj *mobj)
{
	assert(mobj->ops == &mobj_sp_ops);
	return container_of(mobj, struct mobj_sp, mobj);
}

static size_t mobj_sp_size(size_t num_pages)
{
	size_t s = 0;

	if (MUL_OVERFLOW(sizeof(paddr_t), num_pages, &s))
		return 0;
	if (ADD_OVERFLOW(sizeof(struct mobj_sp), s, &s))
		return 0;
	return s;
}

struct mobj *sp_mem_new_mobj(uint64_t pages)
{
	struct mobj_sp *m = NULL;
	size_t s = 0;

	s = mobj_sp_size(pages);
	if (!s)
		return NULL;

	m = calloc(1, s);
	if (!m)
		return NULL;

	m->mobj.ops = &mobj_sp_ops;
	m->mobj.size = pages * SMALL_PAGE_SIZE;
	m->mobj.phys_granule = SMALL_PAGE_SIZE;

	refcount_set(&m->mobj.refc, 1);
	return &m->mobj;
}

static size_t get_page_count(struct mobj_sp *ms)
{
	return ROUNDUP(ms->mobj.size, SMALL_PAGE_SIZE) / SMALL_PAGE_SIZE;
}

/* Add some physical pages to the mobj object. */
int sp_mem_add_pages(struct mobj *mobj, unsigned int *idx,
		     paddr_t pa, unsigned int num_pages)
{
	struct mobj_sp *ms = to_mobj_sp(mobj);
	unsigned int n = 0;
	size_t tot_page_count = get_page_count(ms);

	if (ADD_OVERFLOW(*idx, num_pages, &n) || n > tot_page_count)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!core_pbuf_is(CORE_MEM_NON_SEC, pa, num_pages * SMALL_PAGE_SIZE))
		return TEE_ERROR_BAD_PARAMETERS;

	for (n = 0; n < num_pages; n++)
		ms->pages[n + *idx] = pa + n * SMALL_PAGE_SIZE;

	*idx += n;
	return TEE_SUCCESS;
}

static TEE_Result sp_mem_get_cattr(struct mobj *mobj __unused, uint32_t *cattr)
{
	*cattr = TEE_MATTR_CACHE_CACHED;

	return TEE_SUCCESS;
}

static bool mobj_sp_matches(struct mobj *mobj __maybe_unused,
			    enum buf_is_attr attr)
{
	assert(mobj->ops == &mobj_sp_ops);

	return attr == CORE_MEM_NON_SEC || attr == CORE_MEM_REG_SHM;
}

static TEE_Result get_pa(struct mobj *mobj, size_t offset,
			 size_t granule, paddr_t *pa)
{
	struct mobj_sp *ms = to_mobj_sp(mobj);
	paddr_t p = 0;

	if (!pa)
		return TEE_ERROR_GENERIC;

	if (offset >= mobj->size)
		return TEE_ERROR_GENERIC;

	switch (granule) {
	case 0:
		p = ms->pages[offset / SMALL_PAGE_SIZE] +
		    (offset & SMALL_PAGE_MASK);
		break;
	case SMALL_PAGE_SIZE:
		p = ms->pages[offset / SMALL_PAGE_SIZE];
		break;
	default:
		return TEE_ERROR_GENERIC;
	}
	*pa = p;

	return TEE_SUCCESS;
}
DECLARE_KEEP_PAGER(get_pa);

static size_t get_phys_offs(struct mobj *mobj __maybe_unused,
			    size_t granule __maybe_unused)
{
	return 0;
}

static void inactivate(struct mobj *mobj)
{
	struct mobj_sp *ms = to_mobj_sp(mobj);
	uint32_t exceptions = 0;

	exceptions = cpu_spin_lock_xsave(&sp_mem_lock);
	/*
	 * If refcount isn't 0 some other thread has found this mobj in
	 * shm_head after the mobj_put() that put us here and before we got
	 * the lock.
	 */
	if (!refcount_val(&mobj->refc))
		free(ms);

	cpu_spin_unlock_xrestore(&sp_mem_lock, exceptions);
}

const struct mobj_ops mobj_sp_ops __weak __rodata_unpaged("mobj_sp_ops") = {
	.get_pa = get_pa,
	.get_phys_offs = get_phys_offs,
	.get_cattr = sp_mem_get_cattr,
	.matches = mobj_sp_matches,
	.free = inactivate,
};

struct sp_mem_receiver *sp_mem_get_receiver(uint32_t s_id, struct sp_mem *smem)
{
	struct sp_mem_receiver *r = NULL;

	SLIST_FOREACH(r, &smem->receivers, link) {
		if (r->perm.endpoint_id == s_id)
			return r;
	}
	return NULL;
}

struct sp_mem *sp_mem_get(uint64_t handle)
{
	struct sp_mem *smem = NULL;
	uint32_t exceptions = cpu_spin_lock_xsave(&sp_mem_lock);

	SLIST_FOREACH(smem, &mem_shares, link) {
		if (smem->global_handle == handle)
			break;
	}

	cpu_spin_unlock_xrestore(&sp_mem_lock, exceptions);
	return smem;
}

void *sp_mem_get_va(const struct user_mode_ctx *uctx, size_t offset,
		    struct mobj *mobj)
{
	struct vm_region *region = NULL;

	TAILQ_FOREACH(region, &uctx->vm_info.regions, link) {
		if (region->mobj == mobj && region->offset == offset)
			return (void *)region->va;
	}
	return NULL;
}

struct sp_mem *sp_mem_new(void)
{
	struct sp_mem *smem = NULL;
	uint32_t exceptions = 0;
	int i = 0;

	smem = calloc(sizeof(*smem), 1);
	if (!smem)
		return NULL;

	exceptions = cpu_spin_lock_xsave(&sp_mem_lock);

	bit_ffc(share_bits, NUM_SHARES, &i);
	if (i == -1) {
		cpu_spin_unlock_xrestore(&sp_mem_lock, exceptions);
		free(smem);
		return NULL;
	}

	bit_set(share_bits, i);
	/*
	 * OP-TEE SHAREs use bit 44 use bit 45 instead.
	 */
	smem->global_handle = i | FFA_MEMORY_HANDLE_SECURE_BIT;
	SLIST_INIT(&smem->regions);
	SLIST_INIT(&smem->receivers);

	cpu_spin_unlock_xrestore(&sp_mem_lock, exceptions);

	return smem;
}

void sp_mem_add(struct sp_mem *smem)
{
	uint32_t exceptions = cpu_spin_lock_xsave(&sp_mem_lock);

	SLIST_INSERT_HEAD(&mem_shares, smem, link);

	cpu_spin_unlock_xrestore(&sp_mem_lock, exceptions);
}

bool sp_mem_is_shared(struct sp_mem_map_region *new_reg)
{
	struct sp_mem *smem = NULL;
	uint32_t exceptions = cpu_spin_lock_xsave(&sp_mem_lock);
	uint64_t new_reg_end = new_reg->page_offset +
			       (new_reg->page_count * SMALL_PAGE_SIZE);

	SLIST_FOREACH(smem, &mem_shares, link) {
		struct sp_mem_map_region *reg = NULL;

		SLIST_FOREACH(reg, &smem->regions, link) {
			if (new_reg->mobj == reg->mobj) {
				uint64_t reg_end = 0;

				reg_end = reg->page_offset +
					  (reg->page_count * SMALL_PAGE_SIZE);

				if (new_reg->page_offset < reg_end &&
				    new_reg_end > reg->page_offset) {
					cpu_spin_unlock_xrestore(&sp_mem_lock,
								 exceptions);
					return true;
				}
			}
		}
	}

	cpu_spin_unlock_xrestore(&sp_mem_lock, exceptions);
	return false;
}

void sp_mem_remove(struct sp_mem *smem)
{
	uint32_t exceptions = 0;
	int i = 0;
	struct sp_mem *tsmem = NULL;

	if (!smem)
		return;

	/* Remove all receivers */
	while (!SLIST_EMPTY(&smem->receivers)) {
		struct sp_mem_receiver *receiver = NULL;

		receiver = SLIST_FIRST(&smem->receivers);
		SLIST_REMOVE_HEAD(&smem->receivers, link);
		free(receiver);
	}
	/* Remove all regions */
	while (!SLIST_EMPTY(&smem->regions)) {
		struct sp_mem_map_region *region = SLIST_FIRST(&smem->regions);

		mobj_put(region->mobj);

		SLIST_REMOVE_HEAD(&smem->regions, link);
		free(region);
	}

	exceptions = cpu_spin_lock_xsave(&sp_mem_lock);

	i = smem->global_handle & ~FFA_MEMORY_HANDLE_SECURE_BIT;
	assert(i < NUM_SHARES);

	bit_clear(share_bits, i);

	SLIST_FOREACH(tsmem, &mem_shares, link) {
		if (tsmem == smem) {
			SLIST_REMOVE(&mem_shares, smem, sp_mem, link);
			break;
		}
	}

	cpu_spin_unlock_xrestore(&sp_mem_lock, exceptions);

	free(smem);
}
