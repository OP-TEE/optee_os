// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019, Linaro Limited
 */

#include <crypto/crypto.h>
#include <crypto/internal_aes-gcm.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <mm/fobj.h>
#include <mm/tee_mm.h>
#include <stdlib.h>
#include <string.h>
#include <tee_api_types.h>
#include <types_ext.h>
#include <util.h>

#ifdef CFG_WITH_PAGER

#define RWP_AE_KEY_BITS		256

struct rwp_aes_gcm_iv {
	uint32_t iv[3];
};

#define RWP_AES_GCM_TAG_LEN	16

struct rwp_state {
	uint64_t iv;
	uint8_t tag[RWP_AES_GCM_TAG_LEN];
};

struct fobj_rwp {
	uint8_t *store;
	struct rwp_state *state;
	struct fobj fobj;
};

static struct fobj_ops ops_rw_paged;

static struct internal_aes_gcm_key rwp_ae_key;

void fobj_generate_authenc_key(void)
{
	uint8_t key[RWP_AE_KEY_BITS / 8] = { 0 };

	if (crypto_rng_read(key, sizeof(key)) != TEE_SUCCESS)
		panic("failed to generate random");
	if (internal_aes_gcm_expand_enc_key(key, sizeof(key), &rwp_ae_key))
		panic("failed to expand key");
}

static void fobj_init(struct fobj *fobj, const struct fobj_ops *ops,
		      unsigned int num_pages)
{
	fobj->ops = ops;
	fobj->num_pages = num_pages;
	refcount_set(&fobj->refc, 1);
}

static void fobj_uninit(struct fobj *fobj)
{
	assert(!refcount_val(&fobj->refc));
}

struct fobj *fobj_rw_paged_alloc(unsigned int num_pages)
{
	tee_mm_entry_t *mm = NULL;
	struct fobj_rwp *rwp = NULL;
	size_t size = 0;

	assert(num_pages);

	rwp = calloc(1, sizeof(*rwp));
	if (!rwp)
		return NULL;

	rwp->state = calloc(num_pages, sizeof(*rwp->state));
	if (!rwp->state)
		goto err;

	if (MUL_OVERFLOW(num_pages, SMALL_PAGE_SIZE, &size))
		goto err;
	mm = tee_mm_alloc(&tee_mm_sec_ddr, size);
	if (!mm)
		goto err;
	rwp->store = phys_to_virt(tee_mm_get_smem(mm), MEM_AREA_TA_RAM);
	assert(rwp->store); /* to assist debugging if it would ever happen */
	if (!rwp->store)
		goto err;

	fobj_init(&rwp->fobj, &ops_rw_paged, num_pages);

	return &rwp->fobj;

err:
	tee_mm_free(mm);
	free(rwp->state);
	free(rwp);

	return NULL;
}

static struct fobj_rwp *to_rwp(struct fobj *fobj)
{
	assert(fobj->ops == &ops_rw_paged);

	return container_of(fobj, struct fobj_rwp, fobj);
}

static void rwp_free(struct fobj *fobj)
{
	struct fobj_rwp *rwp = to_rwp(fobj);

	fobj_uninit(fobj);
	tee_mm_free(tee_mm_find(&tee_mm_sec_ddr, virt_to_phys(rwp->store)));
	free(rwp->state);
	free(rwp);
}

static TEE_Result rwp_load_page(struct fobj *fobj, unsigned int page_idx,
				void *va)
{
	struct fobj_rwp *rwp = to_rwp(fobj);
	struct rwp_state *state = rwp->state + page_idx;
	uint8_t *src = rwp->store + page_idx * SMALL_PAGE_SIZE;
	struct rwp_aes_gcm_iv iv = {
		.iv = { (vaddr_t)state, state->iv >> 32, state->iv }
	};

	assert(refcount_val(&fobj->refc));
	assert(page_idx < fobj->num_pages);

	if (!state->iv) {
		/*
		 * iv still zero which means that this is previously unused
		 * page.
		 */
		memset(va, 0, SMALL_PAGE_SIZE);
		return TEE_SUCCESS;
	}

	return internal_aes_gcm_dec(&rwp_ae_key, &iv, sizeof(iv),
				    NULL, 0, src, SMALL_PAGE_SIZE, va,
				    state->tag, sizeof(state->tag));
}
KEEP_PAGER(rwp_load_page);

static TEE_Result rwp_save_page(struct fobj *fobj, unsigned int page_idx,
				const void *va)
{
	struct fobj_rwp *rwp = to_rwp(fobj);
	struct rwp_state *state = rwp->state + page_idx;
	size_t tag_len = sizeof(state->tag);
	uint8_t *dst = rwp->store + page_idx * SMALL_PAGE_SIZE;
	struct rwp_aes_gcm_iv iv;

	memset(&iv, 0, sizeof(iv));
	assert(refcount_val(&fobj->refc));
	assert(page_idx < fobj->num_pages);
	assert(state->iv + 1 > state->iv);

	state->iv++;
	/*
	 * IV is constructed as recommended in section "8.2.1 Deterministic
	 * Construction" of "Recommendation for Block Cipher Modes of
	 * Operation: Galois/Counter Mode (GCM) and GMAC",
	 * http://csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf
	 */

	iv.iv[0] = (vaddr_t)state;
	iv.iv[1] = state->iv >> 32;
	iv.iv[2] = state->iv;

	return internal_aes_gcm_enc(&rwp_ae_key, &iv, sizeof(iv),
				    NULL, 0, va, SMALL_PAGE_SIZE, dst,
				    state->tag, &tag_len);
}
KEEP_PAGER(rwp_save_page);

static struct fobj_ops ops_rw_paged __rodata_unpaged = {
	.free = rwp_free,
	.load_page = rwp_load_page,
	.save_page = rwp_save_page,
};

struct fobj_rop {
	uint8_t *hashes;
	uint8_t *store;
	struct fobj fobj;
};

static struct fobj_ops ops_ro_paged;

struct fobj *fobj_ro_paged_alloc(unsigned int num_pages, void *hashes,
				 void *store)
{
	struct fobj_rop *rop = NULL;

	assert(num_pages && hashes && store);

	rop = calloc(1, sizeof(*rop));
	if (!rop)
		return NULL;

	rop->hashes = hashes;
	rop->store = store;
	fobj_init(&rop->fobj, &ops_ro_paged, num_pages);

	return &rop->fobj;
}

static struct fobj_rop *to_rop(struct fobj *fobj)
{
	assert(fobj->ops == &ops_ro_paged);

	return container_of(fobj, struct fobj_rop, fobj);
}

static void rop_free(struct fobj *fobj)
{
	struct fobj_rop *rop = to_rop(fobj);

	fobj_uninit(fobj);
	tee_mm_free(tee_mm_find(&tee_mm_sec_ddr, virt_to_phys(rop->store)));
	free(rop->hashes);
	free(rop);
}

static TEE_Result rop_load_page(struct fobj *fobj, unsigned int page_idx,
				void *va)
{
	struct fobj_rop *rop = to_rop(fobj);
	const uint8_t *hash = rop->hashes + page_idx * TEE_SHA256_HASH_SIZE;
	const uint8_t *src = rop->store + page_idx * SMALL_PAGE_SIZE;

	assert(refcount_val(&fobj->refc));
	assert(page_idx < fobj->num_pages);
	memcpy(va, src, SMALL_PAGE_SIZE);

	return hash_sha256_check(hash, va, SMALL_PAGE_SIZE);
}
KEEP_PAGER(rop_load_page);

static TEE_Result rop_save_page(struct fobj *fobj __unused,
				unsigned int page_idx __unused,
				const void *va __unused)
{
	return TEE_ERROR_GENERIC;
}
KEEP_PAGER(rop_save_page);

static struct fobj_ops ops_ro_paged __rodata_unpaged = {
	.free = rop_free,
	.load_page = rop_load_page,
	.save_page = rop_save_page,
};

static struct fobj_ops ops_locked_paged;

struct fobj *fobj_locked_paged_alloc(unsigned int num_pages)
{
	struct fobj *f = NULL;

	assert(num_pages);

	f = calloc(1, sizeof(*f));
	if (!f)
		return NULL;

	fobj_init(f, &ops_locked_paged, num_pages);

	return f;
}

static void lop_free(struct fobj *fobj)
{
	assert(fobj->ops == &ops_locked_paged);
	fobj_uninit(fobj);
	free(fobj);
}

static TEE_Result lop_load_page(struct fobj *fobj __maybe_unused,
				unsigned int page_idx __maybe_unused,
				void *va)
{
	assert(fobj->ops == &ops_locked_paged);
	assert(refcount_val(&fobj->refc));
	assert(page_idx < fobj->num_pages);

	memset(va, 0, SMALL_PAGE_SIZE);

	return TEE_SUCCESS;
}
KEEP_PAGER(lop_load_page);

static TEE_Result lop_save_page(struct fobj *fobj __unused,
				unsigned int page_idx __unused,
				const void *va __unused)
{
	return TEE_ERROR_GENERIC;
}
KEEP_PAGER(lop_save_page);

static struct fobj_ops ops_locked_paged __rodata_unpaged = {
	.free = lop_free,
	.load_page = lop_load_page,
	.save_page = lop_save_page,
};
#endif /*CFG_WITH_PAGER*/
