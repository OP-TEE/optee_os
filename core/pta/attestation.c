// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2021, Huawei Technologies Co., Ltd
 */

#include <crypto/crypto.h>
#include <kernel/pseudo_ta.h>
#include <kernel/tee_ta_manager.h>
#include <kernel/ts_manager.h>
#include <kernel/user_mode_ctx.h>
#include <kernel/user_ta.h>
#include <mm/file.h>
#include <mm/mobj.h>
#include <pta_attestation.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <tee/entry_std.h>
#include <tee/uuid.h>
#include <utee_defines.h>

#define PTA_NAME "attestation.pta"

/*
 * Is region valid for hashing?
 * Exclude writable regions as well as those that are not specific to the TA
 * (ldelf, kernel or temporary mappings).
 */
static bool is_region_valid(struct vm_region *r)
{
	uint32_t skip_flags = VM_FLAG_EPHEMERAL | VM_FLAG_PERMANENT |
			      VM_FLAG_LDELF;

	return !(r->flags & skip_flags || r->attr & TEE_MATTR_UW);
}

/*
 * With this comparison function, we're hashing the smaller regions first.
 * Regions of equal size are ordered based on their content (memcmp()).
 * Identical regions can be in any order since they will yield the same hash
 * anyways.
 */
static int cmp_regions(const void *a, const void *b)
{
	const struct vm_region *r1 = *(const struct vm_region **)a;
	const struct vm_region *r2 = *(const struct vm_region **)b;

	if (r1->size < r2->size)
		return -1;

	if (r1->size > r2->size)
		return 1;

	return memcmp((void *)r1->va, (void *)r2->va, r1->size);
}

static TEE_Result hash_update_method_tags(void *ctx, struct vm_region *r)
{
	struct fobj *fobj = r->mobj->ops->get_fobj(r->mobj);
	struct file *f = to_file_may_fail(r->mobj);
	uint64_t offs_and_size[2] = { };
	TEE_Result res = TEE_SUCCESS;
	unsigned int poffs = 0;
	uint8_t *tag = NULL;

	/* Regions we're interested in should all have a struct file */
	assert(f);

	tag = file_get_tag(f);
	assert(tag);

	res = crypto_hash_update(ctx, tag, FILE_TAG_SIZE);
	if (!res)
		return res;

	file_lock(f);
	res = file_find_page_offset(f, fobj, &poffs);
	file_unlock(f);
	if (!res)
		return res;

	offs_and_size[0] = poffs * SMALL_PAGE_SIZE;
	offs_and_size[1] = r->mobj->size;

	return crypto_hash_update(ctx, (uint8_t *)offs_and_size,
				  sizeof(offs_and_size));
}

static TEE_Result hash_update(void *ctx, struct vm_region *r, uint32_t method)
{
	switch (method) {
	case PTA_ATTESTATION_HASH_METHOD_FULL:
		return crypto_hash_update(ctx, (uint8_t *)r->va, r->size);
	case PTA_ATTESTATION_HASH_METHOD_TAGS:
		return hash_update_method_tags(ctx, r);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}

static TEE_Result hash_regions(struct vm_info *vm_info, uint8_t *hash,
			       uint32_t method)
{
	TEE_Result res = TEE_SUCCESS;
	struct vm_region *r = NULL;
	struct vm_region **regions = NULL;
	size_t nregions = 0;
	void *ctx = NULL;
	size_t i = 0;

	res = crypto_hash_alloc_ctx(&ctx, TEE_ALG_SHA256);
	if (res)
		return res;

	res = crypto_hash_init(ctx);
	if (res)
		goto out;

	/*
	 * Make an array of region pointers so we can use qsort() to order it.
	 */

	TAILQ_FOREACH(r, &vm_info->regions, link)
		if (is_region_valid(r))
			nregions++;

	regions = malloc(nregions * sizeof(*regions));
	if (!regions) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	TAILQ_FOREACH(r, &vm_info->regions, link)
		if (is_region_valid(r))
			regions[i++] = r;

	/*
	 * Sort regions so that they are in a consistent order even when TA ASLR
	 * is enabled.
	 */
	qsort(regions, nregions, sizeof(*regions), cmp_regions);

	/* Hash regions in order */
	for (i = 0; i < nregions; i++) {
		r = regions[i];
		DMSG("va %p size %zu", (void *)r->va, r->size);
		res = hash_update(ctx, r, method);
		if (res)
			goto out;
	}

	res = crypto_hash_final(ctx, hash, TEE_SHA256_HASH_SIZE);
out:
	free(regions);
	crypto_hash_free_ctx(ctx);
	return res;
}

static TEE_Result hash_ta(struct user_mode_ctx *uctx, uint32_t types,
			  TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t method = params[0].value.a;
	uint8_t *hash = params[1].memref.buffer;
	size_t hash_sz = params[1].memref.size;
	TEE_Result res = TEE_SUCCESS;
	struct ts_session *s = NULL;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
				     TEE_PARAM_TYPE_MEMREF_OUTPUT,
				     TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	if (!hash || hash_sz != TEE_SHA256_HASH_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	s = ts_pop_current_session();
	res = hash_regions(&uctx->vm_info, hash, method);
	ts_push_current_session(s);

	return res;
}

static TEE_Result open_session(uint32_t param_types __unused,
			       TEE_Param params[TEE_NUM_PARAMS] __unused,
			       void **sess_ctx __unused)
{
	struct ts_session *s = NULL;
	struct user_mode_ctx *uctx = NULL;

	/* Check that we're called from a user TA */
	s = ts_get_calling_session();
	if (!s)
		return TEE_ERROR_ACCESS_DENIED;
	uctx = to_user_mode_ctx(s->ctx);
	if (!uctx)
		return TEE_ERROR_ACCESS_DENIED;

	return hash_ta(uctx, param_types, params);
}

static TEE_Result invoke_command(void *sess_ctx __unused,
				 uint32_t cmd_id __unused,
				 uint32_t param_types __unused,
				 TEE_Param params[TEE_NUM_PARAMS] __unused)
{
	return TEE_SUCCESS;
}

pseudo_ta_register(.uuid = PTA_ATTESTATION_UUID, .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .open_session_entry_point = open_session,
		   .invoke_command_entry_point = invoke_command);
