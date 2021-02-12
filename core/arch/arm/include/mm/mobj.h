/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016-2017, Linaro Limited
 */

#ifndef __MM_MOBJ_H
#define __MM_MOBJ_H

#include <compiler.h>
#include <mm/core_memprot.h>
#include <mm/file.h>
#include <mm/fobj.h>
#include <string_ext.h>
#include <sys/queue.h>
#include <tee_api_types.h>
#include <types_ext.h>

struct mobj {
	const struct mobj_ops *ops;
	size_t size;
	size_t phys_granule;
	struct refcount refc;
};

struct mobj_ops {
	void *(*get_va)(struct mobj *mobj, size_t offs);
	TEE_Result (*get_pa)(struct mobj *mobj, size_t offs, size_t granule,
			     paddr_t *pa);
	size_t (*get_phys_offs)(struct mobj *mobj, size_t granule);
	TEE_Result (*get_cattr)(struct mobj *mobj, uint32_t *cattr);
	bool (*matches)(struct mobj *mobj, enum buf_is_attr attr);
	void (*free)(struct mobj *mobj);
	uint64_t (*get_cookie)(struct mobj *mobj);
	struct fobj *(*get_fobj)(struct mobj *mobj);
	TEE_Result (*inc_map)(struct mobj *mobj);
	TEE_Result (*dec_map)(struct mobj *mobj);
};

extern struct mobj mobj_virt;
extern struct mobj *mobj_sec_ddr;
extern struct mobj *mobj_tee_ram;

static inline void *mobj_get_va(struct mobj *mobj, size_t offset)
{
	if (mobj && mobj->ops && mobj->ops->get_va)
		return mobj->ops->get_va(mobj, offset);
	return NULL;
}

static inline TEE_Result mobj_get_pa(struct mobj *mobj, size_t offs,
				     size_t granule, paddr_t *pa)
{
	if (mobj && mobj->ops && mobj->ops->get_pa)
		return mobj->ops->get_pa(mobj, offs, granule, pa);
	return TEE_ERROR_GENERIC;
}

static inline size_t mobj_get_phys_offs(struct mobj *mobj, size_t granule)
{
	if (mobj && mobj->ops && mobj->ops->get_phys_offs)
		return mobj->ops->get_phys_offs(mobj, granule);
	return 0;
}

static inline TEE_Result mobj_get_cattr(struct mobj *mobj, uint32_t *cattr)
{
	if (mobj && mobj->ops && mobj->ops->get_cattr)
		return mobj->ops->get_cattr(mobj, cattr);
	return TEE_ERROR_GENERIC;
}

static inline bool mobj_matches(struct mobj *mobj, enum buf_is_attr attr)
{
	if (mobj && mobj->ops && mobj->ops->matches)
		return mobj->ops->matches(mobj, attr);
	return false;
}

/**
 * mobj_inc_map() - increase map count
 * @mobj:	pointer to a MOBJ
 *
 * Maps the MOBJ if it isn't mapped already and increases the map count
 * Each call to mobj_inc_map() is supposed to be matches by a call to
 * mobj_dec_map().
 *
 * Returns TEE_SUCCESS on success or an error code on failure
 */
static inline TEE_Result mobj_inc_map(struct mobj *mobj)
{
	if (mobj && mobj->ops) {
		if (mobj->ops->inc_map)
			return mobj->ops->inc_map(mobj);
		return TEE_SUCCESS;
	}
	return TEE_ERROR_GENERIC;
}

/**
 * mobj_dec_map() - decrease map count
 * @mobj:	pointer to a MOBJ
 *
 * Decreases the map count and also unmaps the MOBJ if the map count
 * reaches 0.  Each call to mobj_inc_map() is supposed to be matched by a
 * call to mobj_dec_map().
 *
 * Returns TEE_SUCCESS on success or an error code on failure
 */
static inline TEE_Result mobj_dec_map(struct mobj *mobj)
{
	if (mobj && mobj->ops) {
		if (mobj->ops->dec_map)
			return mobj->ops->dec_map(mobj);
		return TEE_SUCCESS;
	}
	return TEE_ERROR_GENERIC;
}

/**
 * mobj_get() - get a MOBJ
 * @mobj:	Pointer to a MOBJ or NULL
 *
 * Increases reference counter of the @mobj
 *
 * Returns @mobj with reference counter increased or NULL if @mobj was NULL
 */
static inline struct mobj *mobj_get(struct mobj *mobj)
{
	if (mobj && !refcount_inc(&mobj->refc))
		panic();

	return mobj;
}

/**
 * mobj_put() - put a MOBJ
 * @mobj:	Pointer to a MOBJ or NULL
 *
 * Decreases reference counter of the @mobj and frees it if the counter
 * reaches 0.
 */
static inline void mobj_put(struct mobj *mobj)
{
	if (mobj && refcount_dec(&mobj->refc))
		mobj->ops->free(mobj);
}

/**
 * mobj_put_wipe() - wipe and put a MOBJ
 * @mobj:	Pointer to a MOBJ or NULL
 *
 * Clears the memory represented by the mobj and then puts it.
 */
static inline void mobj_put_wipe(struct mobj *mobj)
{
	void *buf = mobj_get_va(mobj, 0);

	if (buf)
		memzero_explicit(buf, mobj->size);
	mobj_put(mobj);
}

static inline uint64_t mobj_get_cookie(struct mobj *mobj)
{
	if (mobj && mobj->ops && mobj->ops->get_cookie)
		return mobj->ops->get_cookie(mobj);

	return 0;
}

static inline struct fobj *mobj_get_fobj(struct mobj *mobj)
{
	if (mobj && mobj->ops && mobj->ops->get_fobj)
		return mobj->ops->get_fobj(mobj);

	return NULL;
}

static inline bool mobj_is_nonsec(struct mobj *mobj)
{
	return mobj_matches(mobj, CORE_MEM_NON_SEC);
}

static inline bool mobj_is_secure(struct mobj *mobj)
{
	return mobj_matches(mobj, CORE_MEM_SEC);
}

static inline bool mobj_is_sdp_mem(struct mobj *mobj)
{
	return mobj_matches(mobj, CORE_MEM_SDP_MEM);
}

static inline size_t mobj_get_phys_granule(struct mobj *mobj)
{
	if (mobj->phys_granule)
		return mobj->phys_granule;
	return mobj->size;
}

struct mobj *mobj_mm_alloc(struct mobj *mobj_parent, size_t size,
			   tee_mm_pool_t *pool);

struct mobj *mobj_phys_alloc(paddr_t pa, size_t size, uint32_t cattr,
			     enum buf_is_attr battr);

#if defined(CFG_CORE_FFA)
struct mobj *mobj_ffa_get_by_cookie(uint64_t cookie,
				    unsigned int internal_offs);

TEE_Result mobj_ffa_unregister_by_cookie(uint64_t cookie);

/* Functions for SPMC */
#ifdef CFG_CORE_SEL1_SPMC
struct mobj_ffa *mobj_ffa_sel1_spmc_new(unsigned int num_pages);
void mobj_ffa_sel1_spmc_delete(struct mobj_ffa *mobj);
TEE_Result mobj_ffa_sel1_spmc_reclaim(uint64_t cookie);
#endif
uint64_t mobj_ffa_get_cookie(struct mobj_ffa *mobj);
TEE_Result mobj_ffa_add_pages_at(struct mobj_ffa *mobj, unsigned int *idx,
				 paddr_t pa, unsigned int num_pages);
uint64_t mobj_ffa_push_to_inactive(struct mobj_ffa *mobj);

#elif defined(CFG_CORE_DYN_SHM)
/* reg_shm represents TEE shared memory */
struct mobj *mobj_reg_shm_alloc(paddr_t *pages, size_t num_pages,
				paddr_t page_offset, uint64_t cookie);

/**
 * mobj_reg_shm_get_by_cookie() - get a MOBJ based on cookie
 * @cookie:	Cookie used by normal world when suppling the shared memory
 *
 * Searches for a registered shared memory MOBJ and if one with a matching
 * @cookie is found its reference counter is increased before returning
 * the MOBJ.
 *
 * Returns a valid pointer on success or NULL on failure.
 */
struct mobj *mobj_reg_shm_get_by_cookie(uint64_t cookie);

TEE_Result mobj_reg_shm_release_by_cookie(uint64_t cookie);

/**
 * mobj_reg_shm_unguard() - unguards a reg_shm
 * @mobj:	pointer to a registered shared memory mobj
 *
 * A registered shared memory mobj is normally guarded against being
 * released with mobj_reg_shm_try_release_by_cookie(). After this function
 * has returned the mobj can be released by a call to
 * mobj_reg_shm_try_release_by_cookie() if the reference counter allows it.
 */
void mobj_reg_shm_unguard(struct mobj *mobj);

/*
 * mapped_shm represents registered shared buffer
 * which is mapped into OPTEE va space
 */
struct mobj *mobj_mapped_shm_alloc(paddr_t *pages, size_t num_pages,
				   paddr_t page_offset, uint64_t cookie);
#endif /*CFG_CORE_DYN_SHM*/

#if !defined(CFG_CORE_DYN_SHM)
static inline struct mobj *mobj_mapped_shm_alloc(paddr_t *pages __unused,
						 size_t num_pages __unused,
						 paddr_t page_offset __unused,
						 uint64_t cookie __unused)
{
	return NULL;
}
#endif

struct mobj *mobj_shm_alloc(paddr_t pa, size_t size, uint64_t cookie);

#ifdef CFG_PAGED_USER_TA
bool mobj_is_paged(struct mobj *mobj);
#else
static inline bool mobj_is_paged(struct mobj *mobj __unused)
{
	return false;
}
#endif

struct mobj *mobj_seccpy_shm_alloc(size_t size);

struct mobj *mobj_with_fobj_alloc(struct fobj *fobj, struct file *file);

#endif /*__MM_MOBJ_H*/
