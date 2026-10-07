// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <assert.h>
#include <kernel/spinlock.h>
#include <limits.h>
#include <mm/core_mmu.h>
#include <optee_rpmi.h>
#include <rpmi_tee.h>
#include <stdlib.h>
#include <string.h>

#include "optee_rpmi_private.h"

/*
 * Parcel states and transitions. No entry means no local registry record.
 *
 *   Transition               Description
 * ----------------------------------------------------------------------------
 *   No entry  -> ACCEPTING   Reserve the parcel key and an acceptance slot.
 *   ACCEPTING -> ACTIVE      Acceptance succeeds; return the first reference.
 *   ACCEPTING -> No entry    Acceptance fails; clean up and discard the entry.
 *   ACTIVE    -> INACTIVE    Last reference dropped; unmap and cache pages.
 *   INACTIVE  -> ACTIVE      A new borrower reuses the accepted parcel.
 *   INACTIVE  -> RELEASING   Retire after all inactivation callbacks finish.
 *   RELEASING -> No entry    Attempt firmware release; discard local state.
 */
enum rpmi_shm_state {
	RPMI_SHM_ACCEPTING,
	RPMI_SHM_ACTIVE,
	RPMI_SHM_INACTIVE,
	RPMI_SHM_RELEASING,
};

/* Secure-side representation of an RPMI memory parcel. */
struct rpmi_parcel {
	struct mobj mobj;
	SLIST_ENTRY(rpmi_parcel) link;
	struct rpmi_shm_context *ctx;
	/* Authenticated parcel identity (creator_id:global_id). */
	uint32_t creator_id;
	uint64_t global_id;

	enum rpmi_shm_state state;
	tee_mm_entry_t *mm;
	/* Accepted physical backing, retained while inactive. */
	paddr_t *pages;
	size_t page_count;
	size_t activation_pins;
	unsigned int mapcount;
};

static struct rpmi_parcel *to_parcel(struct mobj *mobj)
{
	return container_of(mobj, struct rpmi_parcel, mobj);
}

static void *parcel_get_va(struct mobj *mobj, size_t offset, size_t len)
{
	struct rpmi_parcel *parcel = to_parcel(mobj);

	if (!parcel->mm || !mobj_check_offset_and_len(mobj, offset, len))
		return NULL;

	return (void *)(tee_mm_get_smem(parcel->mm) + offset);
}

static TEE_Result parcel_get_pa(struct mobj *mobj, size_t offset,
				size_t granule, paddr_t *pa)
{
	struct rpmi_parcel *parcel = to_parcel(mobj);

	if (!pa || offset >= mobj->size ||
	    (granule && granule != SMALL_PAGE_SIZE))
		return TEE_ERROR_BAD_PARAMETERS;

	*pa = parcel->pages[offset / SMALL_PAGE_SIZE];
	if (!granule)
		*pa += offset & SMALL_PAGE_MASK;

	return TEE_SUCCESS;
}

/* An RPMI parcel starts at a page boundary, so its initial offset is zero. */
static size_t parcel_get_phys_offs(struct mobj *mobj __unused,
				   size_t granule __unused)
{
	return 0;
}

static TEE_Result parcel_get_mem_type(struct mobj *mobj __unused,
				      uint32_t *type)
{
	if (!type)
		return TEE_ERROR_BAD_PARAMETERS;

	*type = TEE_MATTR_MEM_TYPE_CACHED;

	return TEE_SUCCESS;
}

static bool parcel_matches(struct mobj *mobj __unused, enum buf_is_attr attr)
{
	return attr == CORE_MEM_NON_SEC || attr == CORE_MEM_REG_SHM;
}

/* Called under ctx->lock, with no outstanding mapping users. */
static void unmap_entry(struct rpmi_parcel *parcel)
{
	if (parcel->mm) {
		core_mmu_unmap_pages(tee_mm_get_smem(parcel->mm),
				     parcel->page_count);
		tee_mm_free(parcel->mm);
		parcel->mm = NULL;
	}
}

/* A pending callback keeps its activation pin even after reactivation. */
static void parcel_inactivate(struct mobj *mobj)
{
	struct rpmi_parcel *parcel = to_parcel(mobj);
	struct rpmi_shm_context *ctx = parcel->ctx;
	uint32_t exceptions = cpu_spin_lock_xsave(&ctx->lock);

	/* A lookup may have reactivated the parcel before we took the lock. */
	if (!refcount_val(&mobj->refc) &&
	    parcel->state == RPMI_SHM_ACTIVE) {
		assert(!parcel->mapcount);
		unmap_entry(parcel);
		parcel->state = RPMI_SHM_INACTIVE;
	}

	if (!parcel->activation_pins)
		panic();
	parcel->activation_pins--;

	cpu_spin_unlock_xrestore(&ctx->lock, exceptions);
}

static uint64_t parcel_get_cookie(struct mobj *mobj)
{
	return to_parcel(mobj)->global_id;
}

static TEE_Result parcel_inc_map(struct mobj *mobj)
{
	struct rpmi_parcel *parcel = to_parcel(mobj);
	struct rpmi_shm_context *ctx = parcel->ctx;
	uint32_t exceptions = 0;
	TEE_Result res = TEE_SUCCESS;

	exceptions = cpu_spin_lock_xsave(&ctx->lock);
	/* Prevent the mapping reference count from wrapping to zero. */
	if (parcel->mapcount == UINT_MAX) {
		res = TEE_ERROR_BUSY;
		goto out;
	}

	if (!parcel->mm) {
		parcel->mm = tee_mm_alloc(&core_virt_shm_pool, mobj->size);
		if (!parcel->mm) {
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto out;
		}

		res = core_mmu_map_pages(tee_mm_get_smem(parcel->mm),
					 parcel->pages, parcel->page_count,
					 MEM_AREA_NSEC_SHM);
		if (res) {
			tee_mm_free(parcel->mm);
			parcel->mm = NULL;

			goto out;
		}
	}

	parcel->mapcount++;
out:
	cpu_spin_unlock_xrestore(&ctx->lock, exceptions);

	return res;
}

static TEE_Result parcel_dec_map(struct mobj *mobj)
{
	struct rpmi_parcel *parcel = to_parcel(mobj);
	struct rpmi_shm_context *ctx = parcel->ctx;
	uint32_t exceptions = cpu_spin_lock_xsave(&ctx->lock);

	assert(parcel->mapcount);
	if (!--parcel->mapcount)
		unmap_entry(parcel);
	cpu_spin_unlock_xrestore(&ctx->lock, exceptions);

	return TEE_SUCCESS;
}

static const struct mobj_ops parcel_ops = {
	.get_va = parcel_get_va,
	.get_pa = parcel_get_pa,
	.get_phys_offs = parcel_get_phys_offs,
	.get_mem_type = parcel_get_mem_type,
	.matches = parcel_matches,
	.free = parcel_inactivate,
	.get_cookie = parcel_get_cookie,
	.inc_map = parcel_inc_map,
	.dec_map = parcel_dec_map,
};

TEE_Result rpmi_shm_context_init(struct rpmi_shm_context *ctx, uint32_t self_id,
				 uint32_t multisegment_max, size_t max_pages)
{
	if (!max_pages || max_pages > UINT32_MAX ||
	    max_pages > SIZE_MAX / SMALL_PAGE_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	ctx->self_id = self_id;
	ctx->multisegment_max = multisegment_max;
	ctx->max_pages = max_pages;
	ctx->lock = SPINLOCK_UNLOCK;
	ctx->pending = 0;
	SLIST_INIT(&ctx->entries);

	return TEE_SUCCESS;
}

/* Called under ctx->lock; a key includes its authenticated creator. */
static struct rpmi_parcel *find_entry(struct rpmi_shm_context *ctx,
				      uint32_t creator_id, uint64_t global_id)
{
	struct rpmi_parcel *parcel = NULL;

	SLIST_FOREACH(parcel, &ctx->entries, link)
		if (parcel->creator_id == creator_id &&
		    parcel->global_id == global_id)
			return parcel;

	return NULL;
}

/* Under ctx->lock, drop the slot just before leaving ACCEPTING or removal. */
static void release_slot(struct rpmi_shm_context *ctx,
			 struct rpmi_parcel *parcel)
{
	if (parcel->state == RPMI_SHM_ACCEPTING) {
		assert(ctx->pending);
		ctx->pending--;
	}
}

/* Retire an owned parcel, optionally releasing firmware interest. */
static void release_entry(struct rpmi_shm_context *ctx,
			  struct mbox_chan *channel,
			  struct rpmi_parcel *parcel, bool needs_release)
{
	TEE_Result res = TEE_SUCCESS;
	uint32_t exceptions = 0;
	uint32_t parcel_id = optee_rpmi_parcel_id(parcel->global_id);

	assert(!parcel->mm && !parcel->mapcount && !parcel->activation_pins);

	if (needs_release) {
		/* Firmware receiver interest was acquired or may have been. */
		res = rpmi_tee_memory_release(channel, ctx->self_id, parcel_id);
		if (res)
			EMSG("Parcel %#"PRIx32" release failed: %#"PRIx32,
			     parcel_id, res);
	}

	exceptions = cpu_spin_lock_xsave(&ctx->lock);
	release_slot(ctx, parcel);
	SLIST_REMOVE(&ctx->entries, parcel, rpmi_parcel, link);
	cpu_spin_unlock_xrestore(&ctx->lock, exceptions);
	free(parcel->pages);
	free(parcel);
}

/* Called under ctx->lock; pin each new activation until its callback ends. */
static struct mobj *get_entry(struct rpmi_parcel *parcel)
{
	if (parcel->state != RPMI_SHM_ACTIVE &&
	    parcel->state != RPMI_SHM_INACTIVE)
		return NULL;

	if (!refcount_inc(&parcel->mobj.refc)) {
		refcount_set(&parcel->mobj.refc, 1);
		/* Pin this activation until its last-put callback finishes. */
		parcel->activation_pins++;
	}

	parcel->state = RPMI_SHM_ACTIVE;

	return &parcel->mobj;
}

/* Allocate an unpublished parcel and its temporary acceptance page array. */
static struct rpmi_parcel *rpmi_parcel_alloc(struct rpmi_shm_context *ctx,
					     uint32_t creator_id,
					     uint64_t global_id,
					     paddr_t **pages)
{
	struct rpmi_parcel *parcel = NULL;

	parcel = calloc(1, sizeof(*parcel));
	if (!parcel)
		return NULL;

	*pages = calloc(ctx->max_pages, sizeof(**pages));
	if (!*pages) {
		free(parcel);
		return NULL;
	}

	parcel->creator_id = creator_id;
	parcel->global_id = global_id;
	parcel->ctx = ctx;
	parcel->state = RPMI_SHM_ACCEPTING;

	return parcel;
}

/* Complete acceptance of a published parcel and consume its page buffer. */
static TEE_Result rpmi_parcel_accept(struct mbox_chan *channel,
				     struct rpmi_parcel *parcel,
				     paddr_t *pages, struct mobj **mobj)
{
	struct rpmi_shm_context *ctx = parcel->ctx;
	struct rpmi_tee_memory_accept_args args = {
		.acceptor_id = ctx->self_id,
		.creator_id = parcel->creator_id,
		.parcel_id = optee_rpmi_parcel_id(parcel->global_id),
		.nonce = optee_rpmi_nonce(parcel->global_id),
		.access = RPMI_TEE_ACCESS_READ | RPMI_TEE_ACCESS_WRITE,
		.creator_access = RPMI_TEE_ACCESS_READ | RPMI_TEE_ACCESS_WRITE,
		.pages = pages,
		.page_count_max = ctx->max_pages,
	};
	uint32_t exceptions = 0;
	size_t n = 0;
	TEE_Result res = TEE_SUCCESS;

	res = rpmi_tee_memory_accept(channel, &args);
	if (res)
		goto out_failed;

	/* Require page-aligned backing in non-secure memory. */
	for (n = 0; n < args.page_count; n++) {
		if ((pages[n] & SMALL_PAGE_MASK) ||
		    !core_pbuf_is(CORE_MEM_NON_SEC, pages[n],
				  SMALL_PAGE_SIZE)) {
			res = TEE_ERROR_SECURITY;
			goto out_failed;
		}
	}

	/* Setup parcel: */

	parcel->pages = calloc(args.page_count, sizeof(*pages));
	if (!parcel->pages) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out_failed;
	}

	memcpy(parcel->pages, pages, args.page_count * sizeof(*pages));
	parcel->page_count = args.page_count;
	parcel->mobj.ops = &parcel_ops;
	parcel->mobj.size = args.page_count * SMALL_PAGE_SIZE;
	parcel->mobj.phys_granule = SMALL_PAGE_SIZE;

	exceptions = cpu_spin_lock_xsave(&ctx->lock);
	release_slot(ctx, parcel);
	parcel->state = RPMI_SHM_INACTIVE;
	/* Activate the parcel and return its first MOBJ reference. */
	*mobj = get_entry(parcel);
	cpu_spin_unlock_xrestore(&ctx->lock, exceptions);

	goto out;

out_failed:
	release_entry(ctx, channel, parcel, args.needs_release);
out:
	free(pages);

	return res;
}

/*
 * Get a whole-parcel MOBJ for the authenticated creator_id and global_id pair.
 * Reuse an active or inactive cached object; otherwise accept the RW SHARE
 * parcel and validate its backing pages before publishing it.
 *
 * On TEE_SUCCESS, mobj receives an owned reference, released with mobj_put().
 * No kernel mapping reference is acquired; kernel address users must pair
 * mobj_inc_map() with mobj_dec_map() while holding the MOBJ reference.
 * On failure, mobj is NULL.
 */
TEE_Result rpmi_shm_get(struct rpmi_shm_context *ctx,
			struct mbox_chan *channel,
			uint32_t creator_id, uint64_t global_id,
			struct mobj **mobj)
{
	struct rpmi_parcel *parcel = NULL;
	paddr_t *pages = NULL;
	uint32_t exceptions = 0;

	*mobj = NULL;
	/* A zero nonce denotes NULL, not a usable parcel reference. */
	if (!optee_rpmi_nonce(global_id))
		return TEE_ERROR_BAD_PARAMETERS;

	exceptions = cpu_spin_lock_xsave(&ctx->lock);
	parcel = find_entry(ctx, creator_id, global_id);
	if (parcel) {
		*mobj = get_entry(parcel);
		cpu_spin_unlock_xrestore(&ctx->lock, exceptions);

		if (!*mobj)
			return TEE_ERROR_BUSY;
		return TEE_SUCCESS;
	}

	/* Without segmented support, serialize possible acceptances. */
	if (ctx->pending >= MAX(ctx->multisegment_max, 1U)) {
		cpu_spin_unlock_xrestore(&ctx->lock, exceptions);
		return TEE_ERROR_BUSY;
	}

	parcel = rpmi_parcel_alloc(ctx, creator_id, global_id, &pages);
	if (!parcel) {
		cpu_spin_unlock_xrestore(&ctx->lock, exceptions);
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	ctx->pending++;
	/* Publish ACCEPTING to block duplicate allocation and acceptance. */
	SLIST_INSERT_HEAD(&ctx->entries, parcel, link);
	cpu_spin_unlock_xrestore(&ctx->lock, exceptions);

	return rpmi_parcel_accept(channel, parcel, pages, mobj);
}

TEE_Result rpmi_shm_unregister(struct rpmi_shm_context *ctx,
			       struct mbox_chan *channel,
			       uint32_t creator_id, uint64_t global_id)
{
	struct rpmi_parcel *parcel = NULL;
	uint32_t exceptions = 0;

	/* A zero nonce denotes NULL, not a usable parcel reference. */
	if (!optee_rpmi_nonce(global_id))
		return TEE_ERROR_BAD_PARAMETERS;

	exceptions = cpu_spin_lock_xsave(&ctx->lock);
	parcel = find_entry(ctx, creator_id, global_id);
	if (!parcel) {
		/* An unseen key has no lazily acquired receiver interest. */
		cpu_spin_unlock_xrestore(&ctx->lock, exceptions);
		return TEE_SUCCESS;
	}

	if (parcel->state != RPMI_SHM_INACTIVE || parcel->activation_pins) {
		cpu_spin_unlock_xrestore(&ctx->lock, exceptions);
		return TEE_ERROR_BUSY;
	}

	parcel->state = RPMI_SHM_RELEASING;
	cpu_spin_unlock_xrestore(&ctx->lock, exceptions);

	release_entry(ctx, channel, parcel, true);

	return TEE_SUCCESS;
}
