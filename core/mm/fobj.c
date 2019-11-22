// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019, Linaro Limited
 */

#include <crypto/crypto.h>
#include <crypto/internal_aes-gcm.h>
#include <kernel/generic_boot.h>
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

static const struct fobj_ops ops_rw_paged;

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
	TAILQ_INIT(&fobj->areas);
}

static void fobj_uninit(struct fobj *fobj)
{
	assert(!refcount_val(&fobj->refc));
	assert(TAILQ_EMPTY(&fobj->areas));
	tee_pager_invalidate_fobj(fobj);
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

	if (!refcount_val(&fobj->refc)) {
		/*
		 * This fobj is being teared down, it just hasn't had the time
		 * to call tee_pager_invalidate_fobj() yet.
		 */
		assert(TAILQ_EMPTY(&fobj->areas));
		return TEE_SUCCESS;
	}

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

static const struct fobj_ops ops_rw_paged __rodata_unpaged = {
	.free = rwp_free,
	.load_page = rwp_load_page,
	.save_page = rwp_save_page,
};

struct fobj_rop {
	uint8_t *hashes;
	uint8_t *store;
	struct fobj fobj;
};

static const struct fobj_ops ops_ro_paged;

static void rop_init(struct fobj_rop *rop, const struct fobj_ops *ops,
		     unsigned int num_pages, void *hashes, void *store)
{
	rop->hashes = hashes;
	rop->store = store;
	fobj_init(&rop->fobj, ops, num_pages);
}

struct fobj *fobj_ro_paged_alloc(unsigned int num_pages, void *hashes,
				 void *store)
{
	struct fobj_rop *rop = NULL;

	assert(num_pages && hashes && store);

	rop = calloc(1, sizeof(*rop));
	if (!rop)
		return NULL;

	rop_init(rop, &ops_ro_paged, num_pages, hashes, store);

	return &rop->fobj;
}

static struct fobj_rop *to_rop(struct fobj *fobj)
{
	assert(fobj->ops == &ops_ro_paged);

	return container_of(fobj, struct fobj_rop, fobj);
}

static void rop_uninit(struct fobj_rop *rop)
{
	fobj_uninit(&rop->fobj);
	tee_mm_free(tee_mm_find(&tee_mm_sec_ddr, virt_to_phys(rop->store)));
	free(rop->hashes);
}

static void rop_free(struct fobj *fobj)
{
	struct fobj_rop *rop = to_rop(fobj);

	rop_uninit(rop);
	free(rop);
}

static TEE_Result rop_load_page_helper(struct fobj_rop *rop,
				       unsigned int page_idx, void *va)
{
	const uint8_t *hash = rop->hashes + page_idx * TEE_SHA256_HASH_SIZE;
	const uint8_t *src = rop->store + page_idx * SMALL_PAGE_SIZE;

	assert(refcount_val(&rop->fobj.refc));
	assert(page_idx < rop->fobj.num_pages);
	memcpy(va, src, SMALL_PAGE_SIZE);

	return hash_sha256_check(hash, va, SMALL_PAGE_SIZE);
}

static TEE_Result rop_load_page(struct fobj *fobj, unsigned int page_idx,
				void *va)
{
	return rop_load_page_helper(to_rop(fobj), page_idx, va);
}
KEEP_PAGER(rop_load_page);

static TEE_Result rop_save_page(struct fobj *fobj __unused,
				unsigned int page_idx __unused,
				const void *va __unused)
{
	return TEE_ERROR_GENERIC;
}
KEEP_PAGER(rop_save_page);

static const struct fobj_ops ops_ro_paged __rodata_unpaged = {
	.free = rop_free,
	.load_page = rop_load_page,
	.save_page = rop_save_page,
};

#ifdef CFG_CORE_ASLR
/*
 * When using relocated pages the relocation information must be applied
 * before the pages can be used. With read-only paging the content is only
 * integrity protected so relocation cannot be applied on pages in the less
 * secure "store" or the load_address selected by ASLR could be given away.
 * This means that each time a page has been loaded and verified it has to
 * have its relocation information applied before it can be used.
 *
 * Only the relative relocations are supported, this allows a rather compact
 * represenation of the needed relocation information in this struct.
 * r_offset is replaced with the offset into the page that need to be updated,
 * this number can never be larger than SMALL_PAGE_SIZE so a uint16_t can be
 * used to represent it.
 *
 * All relocations are converted and stored in @relocs. @page_reloc_idx is
 * an array of length @rop.fobj.num_pages with an entry for each page. If
 * @page_reloc_idx[page_idx] isn't UINT16_MAX it's an index into @relocs.
 */
struct fobj_ro_reloc_paged {
	uint16_t *page_reloc_idx;
	uint16_t *relocs;
	unsigned int num_relocs;
	struct fobj_rop rop;
};

static const struct fobj_ops ops_ro_reloc_paged;

static unsigned int get_num_rels(unsigned int num_pages,
				 unsigned int reloc_offs,
				 const uint32_t *reloc, unsigned int num_relocs)
{
	const unsigned int align_mask __maybe_unused = sizeof(long) - 1;
	unsigned int nrels = 0;
	unsigned int n = 0;
	vaddr_t offs = 0;

	/*
	 * Count the number of relocations which are needed for these
	 * pages.  Also check that the data is well formed, only expected
	 * relocations and sorted in order of address which it applies to.
	 */
	for (; n < num_relocs; n++) {
		assert(ALIGNMENT_IS_OK(reloc[n], unsigned long));
		assert(offs < reloc[n]);	/* check that it's sorted */
		offs = reloc[n];
		if (offs >= reloc_offs &&
		    offs <= reloc_offs + num_pages * SMALL_PAGE_SIZE)
			nrels++;
	}

	return nrels;
}

static void init_rels(struct fobj_ro_reloc_paged *rrp, unsigned int reloc_offs,
		      const uint32_t *reloc, unsigned int num_relocs)
{
	unsigned int npg = rrp->rop.fobj.num_pages;
	unsigned int pg_idx = 0;
	unsigned int reln = 0;
	unsigned int n = 0;
	uint32_t r = 0;

	for (n = 0; n < npg; n++)
		rrp->page_reloc_idx[n] = UINT16_MAX;

	for (n = 0; n < num_relocs ; n++) {
		if (reloc[n] < reloc_offs)
			continue;

		/* r is the offset from beginning of this fobj */
		r = reloc[n] - reloc_offs;

		pg_idx = r / SMALL_PAGE_SIZE;
		if (pg_idx >= npg)
			break;

		if (rrp->page_reloc_idx[pg_idx] == UINT16_MAX)
			rrp->page_reloc_idx[pg_idx] = reln;
		rrp->relocs[reln] = r - pg_idx * SMALL_PAGE_SIZE;
		reln++;
	}

	assert(reln == rrp->num_relocs);
}

struct fobj *fobj_ro_reloc_paged_alloc(unsigned int num_pages, void *hashes,
				       unsigned int reloc_offs,
				       const void *reloc,
				       unsigned int reloc_len, void *store)
{
	struct fobj_ro_reloc_paged *rrp = NULL;
	const unsigned int num_relocs = reloc_len / sizeof(uint32_t);
	unsigned int nrels = 0;

	assert(ALIGNMENT_IS_OK(reloc, uint32_t));
	assert(ALIGNMENT_IS_OK(reloc_len, uint32_t));
	assert(num_pages && hashes && store);
	if (!reloc_len) {
		assert(!reloc);
		return fobj_ro_paged_alloc(num_pages, hashes, store);
	}
	assert(reloc);

	nrels = get_num_rels(num_pages, reloc_offs, reloc, num_relocs);
	if (!nrels)
		return fobj_ro_paged_alloc(num_pages, hashes, store);

	rrp = calloc(1, sizeof(*rrp) + num_pages * sizeof(uint16_t) +
			nrels * sizeof(uint16_t));
	if (!rrp)
		return NULL;
	rop_init(&rrp->rop, &ops_ro_reloc_paged, num_pages, hashes, store);
	rrp->page_reloc_idx = (uint16_t *)(rrp + 1);
	rrp->relocs = rrp->page_reloc_idx + num_pages;
	rrp->num_relocs = nrels;
	init_rels(rrp, reloc_offs, reloc, num_relocs);

	return &rrp->rop.fobj;
}

static struct fobj_ro_reloc_paged *to_rrp(struct fobj *fobj)
{
	assert(fobj->ops == &ops_ro_reloc_paged);

	return container_of(fobj, struct fobj_ro_reloc_paged, rop.fobj);
}

static void rrp_free(struct fobj *fobj)
{
	struct fobj_ro_reloc_paged *rrp = to_rrp(fobj);

	rop_uninit(&rrp->rop);
	free(rrp);
}

static TEE_Result rrp_load_page(struct fobj *fobj, unsigned int page_idx,
				void *va)
{
	struct fobj_ro_reloc_paged *rrp = to_rrp(fobj);
	unsigned int end_rel = rrp->num_relocs;
	TEE_Result res = TEE_SUCCESS;
	unsigned long *where = NULL;
	unsigned int n = 0;

	res = rop_load_page_helper(&rrp->rop, page_idx, va);
	if (res)
		return res;

	/* Find the reloc index of the next page to tell when we're done */
	for (n = page_idx + 1; n < fobj->num_pages; n++) {
		if (rrp->page_reloc_idx[n] != UINT16_MAX) {
			end_rel = rrp->page_reloc_idx[n];
			break;
		}
	}

	for (n = rrp->page_reloc_idx[page_idx]; n < end_rel; n++) {
		where = (void *)((vaddr_t)va + rrp->relocs[n]);
		*where += boot_mmu_config.load_offset;
	}

	return TEE_SUCCESS;
}
KEEP_PAGER(rrp_load_page);

static const struct fobj_ops ops_ro_reloc_paged __rodata_unpaged = {
	.free = rrp_free,
	.load_page = rrp_load_page,
	.save_page = rop_save_page, /* Direct reuse */
};
#endif /*CFG_CORE_ASLR*/

static const struct fobj_ops ops_locked_paged;

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

static const struct fobj_ops ops_locked_paged __rodata_unpaged = {
	.free = lop_free,
	.load_page = lop_load_page,
	.save_page = lop_save_page,
};
#endif /*CFG_WITH_PAGER*/

#ifndef CFG_PAGED_USER_TA

struct fobj_sec_mem {
	tee_mm_entry_t *mm;
	struct fobj fobj;
};

static struct fobj_ops ops_sec_mem;

struct fobj *fobj_sec_mem_alloc(unsigned int num_pages)
{
	struct fobj_sec_mem *f = calloc(1, sizeof(*f));
	size_t size = 0;
	void *va = NULL;

	if (!f)
		return NULL;

	if (MUL_OVERFLOW(num_pages, SMALL_PAGE_SIZE, &size))
		goto err;

	f->mm = tee_mm_alloc(&tee_mm_sec_ddr, size);
	if (!f->mm)
		goto err;

	va = phys_to_virt(tee_mm_get_smem(f->mm), MEM_AREA_TA_RAM);
	if (!va)
		goto err;

	memset(va, 0, size);
	f->fobj.ops = &ops_sec_mem;
	f->fobj.num_pages = num_pages;
	refcount_set(&f->fobj.refc, 1);

	return &f->fobj;
err:
	tee_mm_free(f->mm);
	free(f);

	return NULL;
}

static struct fobj_sec_mem *to_sec_mem(struct fobj *fobj)
{
	assert(fobj->ops == &ops_sec_mem);

	return container_of(fobj, struct fobj_sec_mem, fobj);
}

static void sec_mem_free(struct fobj *fobj)
{
	struct fobj_sec_mem *f = to_sec_mem(fobj);

	assert(!refcount_val(&fobj->refc));
	tee_mm_free(f->mm);
	free(f);
}

static paddr_t sec_mem_get_pa(struct fobj *fobj, unsigned int page_idx)
{
	struct fobj_sec_mem *f = to_sec_mem(fobj);

	assert(refcount_val(&fobj->refc));
	assert(page_idx < fobj->num_pages);

	return tee_mm_get_smem(f->mm) + page_idx * SMALL_PAGE_SIZE;
}

static struct fobj_ops ops_sec_mem __rodata_unpaged = {
	.free = sec_mem_free,
	.get_pa = sec_mem_get_pa,
};

#endif /*PAGED_USER_TA*/
