// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2024, Institute of Information Security (IISEC)
 */

#include <config.h>
#include <crypto/crypto.h>
#include <kernel/linker.h>
#include <kernel/user_mode_ctx.h>

#include "hash.h"

/*
 * Is region valid for hashing?
 * Exclude writable regions as well as those that are not specific to the TA
 * (ldelf, kernel or temporary mappings).
 */
static bool is_region_valid(struct vm_region *r)
{
	uint32_t dontwant = VM_FLAG_EPHEMERAL | VM_FLAG_PERMANENT |
			    VM_FLAG_LDELF;
	uint32_t want = VM_FLAG_READONLY;

	return ((r->flags & want) == want && !(r->flags & dontwant));
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

static TEE_Result hash_regions(struct vm_info *vm_info,
			       uint8_t hash[TEE_SHA256_HASH_SIZE])
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

	regions = calloc(nregions, sizeof(*regions));
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
		res = crypto_hash_update(ctx, (uint8_t *)r->va, r->size);
		if (res)
			goto out;
	}

	res = crypto_hash_final(ctx, hash, TEE_SHA256_HASH_SIZE);
out:
	free(regions);
	crypto_hash_free_ctx(ctx);
	return res;
}

TEE_Result get_hash_ta_memory(uint8_t out[TEE_SHA256_HASH_SIZE])
{
	struct user_mode_ctx *uctx = NULL;
	TEE_Result res = TEE_SUCCESS;
	struct ts_session *s = NULL;

	/* Check that we're called from a user TA */
	s = ts_get_calling_session();
	if (!s)
		return TEE_ERROR_ACCESS_DENIED;
	uctx = to_user_mode_ctx(s->ctx);
	if (!uctx)
		return TEE_ERROR_ACCESS_DENIED;

	s = ts_pop_current_session();
	res = hash_regions(&uctx->vm_info, out);
	ts_push_current_session(s);
	return res;
}

/*
 * Hash the immutable part of the TEE core: .text and .rodata, in the same
 * order as the attestation PTA (core/pta/attestation.c). The relocated
 * read-only data is left out so that the value does not depend on the
 * load address.
 */
TEE_Result get_hash_tee_memory(uint8_t out[TEE_SHA256_HASH_SIZE])
{
	TEE_Result res = TEE_SUCCESS;
	void *ctx = NULL;

	res = crypto_hash_alloc_ctx(&ctx, TEE_ALG_SHA256);
	if (res)
		return res;

	res = crypto_hash_init(ctx);
	if (res)
		goto out;
	res = crypto_hash_update(ctx, __text_start,
				 __text_data_start - __text_start);
	if (res)
		goto out;
	res = crypto_hash_update(ctx, __text_data_end,
				 __text_end - __text_data_end);
	if (res)
		goto out;
	if (IS_ENABLED(CFG_WITH_PAGER)) {
		res = crypto_hash_update(ctx, __text_init_start,
					 __text_init_end - __text_init_start);
		if (res)
			goto out;
		res = crypto_hash_update(ctx, __text_pageable_start,
					 __text_pageable_end -
						__text_pageable_start);
		if (res)
			goto out;
	}
	res = crypto_hash_update(ctx, __rodata_start,
				 __rodata_end - __rodata_start);
	if (res)
		goto out;
	if (IS_ENABLED(CFG_WITH_PAGER)) {
		res = crypto_hash_update(ctx, __rodata_init_start,
					 __rodata_init_end -
						__rodata_init_start);
		if (res)
			goto out;
		res = crypto_hash_update(ctx, __rodata_pageable_start,
					 __rodata_pageable_end -
						__rodata_pageable_start);
		if (res)
			goto out;
	}
	res = crypto_hash_final(ctx, out, TEE_SHA256_HASH_SIZE);
out:
	crypto_hash_free_ctx(ctx);
	return res;
}
