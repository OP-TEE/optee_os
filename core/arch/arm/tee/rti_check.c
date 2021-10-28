// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021, Linaro Limited
 */

#include <crypto/crypto.h>
#include <initcall.h>
#include <kernel/spinlock.h>
#include <mm/core_mmu.h>
#include <stdlib.h>
#include <string_ext.h>
#include <sys/queue.h>
#include <types_ext.h>
#include <utee_defines.h>

#include "rti_check.h"

struct rti_check_range {
	paddr_t pa;
	size_t sz;
	bool final;
	uint8_t digest[TEE_SHA256_HASH_SIZE];
	SLIST_ENTRY(rti_check_range) link;
};

SLIST_HEAD(rti_check_range_head, rti_check_range);

static struct rti_check_range_head rti_check_head =
	SLIST_HEAD_INITIALIZER(rti_check_head);
static unsigned int rti_check_lock = SPINLOCK_UNLOCK;
static void *rti_check_ctx;
static uint8_t rti_check_tmp_digest[TEE_SHA256_HASH_SIZE];

static TEE_Result compute_hash(paddr_t pa, size_t sz, uint8_t *digest)
{
	TEE_Result res = TEE_SUCCESS;
	size_t pos = 0;
	void *p = NULL;
	size_t len = 0;

	res = crypto_atomic_sha256_init(rti_check_ctx);
	if (res)
		return res;
	while (pos < sz) {
		p = core_mmu_map_rti_check(pa + pos, sz - pos, &len);
		if (!p)
			return TEE_ERROR_ACCESS_CONFLICT;
		pos += len;
		res = crypto_atomic_sha256_update(rti_check_ctx, p, len);
		if (res)
			return res;
	}

	return crypto_atomic_sha256_final(rti_check_ctx, digest,
					  TEE_SHA256_HASH_SIZE);
}

TEE_Result rti_check_add(paddr_t pa, size_t sz, bool final)
{
	TEE_Result res = TEE_SUCCESS;
	struct rti_check_range *range = NULL;
	size_t len = 0;

	if (!rti_check_ctx)
		return TEE_ERROR_OUT_OF_MEMORY;

	range = nex_calloc(1, sizeof(*range));
	if (!range)
		return TEE_ERROR_OUT_OF_MEMORY;
	range->pa = pa;
	range->sz = sz;
	range->final = final;

	cpu_spin_lock(&rti_check_lock);

	res = compute_hash(pa, sz, range->digest);
	core_mmu_map_rti_check(0, 0, &len);
	if (res)
		nex_free(range);
	else
		SLIST_INSERT_HEAD(&rti_check_head, range, link);

	cpu_spin_unlock(&rti_check_lock);
	return res;
}

TEE_Result rti_check_rem(paddr_t pa, size_t sz)
{
	struct rti_check_range *range_prev = NULL;
	struct rti_check_range *range = NULL;

	cpu_spin_lock(&rti_check_lock);
	SLIST_FOREACH(range, &rti_check_head, link) {
		if (pa == range->pa && sz == range->sz) {
			if (!range->final) {
				if (range_prev)
					SLIST_REMOVE_AFTER(range_prev, link);
				else
					SLIST_REMOVE_HEAD(&rti_check_head,
							  link);
			} else {
				range = NULL;
			}
			break;
		}
		range_prev = range;
	}
	cpu_spin_unlock(&rti_check_lock);

	if (!range)
		return TEE_ERROR_ACCESS_CONFLICT;

	nex_free(range);
	return TEE_SUCCESS;
}

TEE_Result rti_check_run(void)
{
	struct rti_check_range *range = NULL;
	TEE_Result res = TEE_SUCCESS;
	size_t dummy_len = 0;

	cpu_spin_lock(&rti_check_lock);
	SLIST_FOREACH(range, &rti_check_head, link) {
		res = compute_hash(range->pa, range->sz, rti_check_tmp_digest);
		if (res || consttime_memcmp(rti_check_tmp_digest, range->digest,
					    sizeof(range->digest))) {
			EMSG("PA:len %#"PRIxPA":%#zx failed RTI check",
			     range->pa, range->sz);
			res = TEE_ERROR_SECURITY;
		}
	}
	core_mmu_map_rti_check(0, 0, &dummy_len);
	cpu_spin_unlock(&rti_check_lock);

	return res;
}

static TEE_Result rti_check_init(void)
{
	rti_check_ctx = nex_malloc(crypto_atomic_sha256_get_ctx_size());
	return TEE_SUCCESS;
}
service_init(rti_check_init);
