// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2021, Huawei Technologies Co., Ltd
 */

#include <crypto/crypto.h>
#include <kernel/mutex.h>
#include <kernel/pseudo_ta.h>
#include <kernel/tee_ta_manager.h>
#include <kernel/ts_manager.h>
#include <kernel/user_ta.h>
#include <mm/file.h>
#include <mm/mobj.h>
#include <pta_attestation.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <tee/entry_std.h>
#include <tee/uuid.h>
#include <user_ta_header.h>
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

static TEE_Result hash_update_mode_tags(void *ctx, struct vm_region *r)
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

static TEE_Result hash_update(void *ctx, struct vm_region *r, uint32_t mode)
{
	switch (mode) {
	case PTA_ATTESTATION_HASH_MODE_FULL:
		return crypto_hash_update(ctx, (uint8_t *)r->va, r->size);
	case PTA_ATTESTATION_HASH_MODE_TAGS:
		return hash_update_mode_tags(ctx, r);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}

static TEE_Result hash_regions(struct vm_info *vm_info, uint8_t *hash,
			       uint32_t mode)
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
		res = hash_update(ctx, r, mode);
		if (res)
			goto out;
	}

	res = crypto_hash_final(ctx, hash, TEE_SHA256_HASH_SIZE);
out:
	free(regions);
	crypto_hash_free_ctx(ctx);
	return res;
}

static TEE_Result hash_ta(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	struct tee_ta_session_head *open_sessions = NULL;
	struct tee_ta_session *s = NULL;
	struct ts_session *ts_sess = NULL;
	uint32_t id = params[0].value.a;
	uint32_t mode = params[0].value.b;
	uint8_t *hash = params[1].memref.buffer;
	size_t hash_sz = params[1].memref.size;
	TEE_Result res = TEE_SUCCESS;
	struct user_ta_ctx *ctx = NULL;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
				     TEE_PARAM_TYPE_MEMREF_OUTPUT,
				     TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	if (!hash || hash_sz != TEE_SHA256_HASH_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	if (ts_get_calling_session()) {
		/*
		 * Called from secure world: not what we expect. Only the normal
		 * world CA is supposed to know about the session ID.
		 */
		return TEE_ERROR_ACCESS_DENIED;
	}

	nsec_sessions_list_head(&open_sessions);
	s = tee_ta_get_session(id, true, open_sessions);
	if (!s)
		return TEE_ERROR_ITEM_NOT_FOUND;

	if (!is_user_ta_ctx(s->ts_sess.ctx)) {
		res = TEE_ERROR_ITEM_NOT_FOUND;
		goto out;
	}

	ts_push_current_session(&s->ts_sess);

	ctx = to_user_ta_ctx(s->ts_sess.ctx);
	res = hash_regions(&ctx->uctx.vm_info, hash, mode);

	ts_sess = ts_pop_current_session();
	assert(ts_sess == &s->ts_sess);
out:
	tee_ta_put_session(s);
	return res;
}

static TEE_Result invoke_command(void *pSessionContext __unused,
				 uint32_t command_id, uint32_t param_types,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	switch (command_id) {
	case PTA_ATTESTATION_HASH_TA:
		return hash_ta(param_types, params);
	default:
		break;
	}

	return TEE_ERROR_NOT_IMPLEMENTED;
}

pseudo_ta_register(.uuid = PTA_ATTESTATION_UUID, .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .invoke_command_entry_point = invoke_command);
