/*
 * Copyright (c) 2016-2017, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __MM_MOBJ_H
#define __MM_MOBJ_H

#include <compiler.h>
#include <mm/core_memprot.h>
#include <optee_msg.h>
#include <sys/queue.h>
#include <tee_api_types.h>
#include <types_ext.h>


struct mobj {
	const struct mobj_ops *ops;
	size_t size;
	size_t phys_granule;
};

struct mobj_ops {
	void *(*get_va)(struct mobj *mobj, size_t offs);
	TEE_Result (*get_pa)(struct mobj *mobj, size_t offs, size_t granule,
			     paddr_t *pa);
	TEE_Result (*get_cattr)(struct mobj *mobj, uint32_t *cattr);
	bool (*matches)(struct mobj *mobj, enum buf_is_attr attr);
	void (*free)(struct mobj *mobj);
	void (*update_mapping)(struct mobj *mobj, struct user_ta_ctx *utc,
			       vaddr_t va);
};

extern struct mobj mobj_virt;
extern struct mobj *mobj_sec_ddr;

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

static inline void mobj_free(struct mobj *mobj)
{
	if (mobj && mobj->ops && mobj->ops->free)
		mobj->ops->free(mobj);
}

static inline void mobj_update_mapping(struct mobj *mobj,
				       struct user_ta_ctx *utc, vaddr_t va)
{
	if (mobj && mobj->ops && mobj->ops->update_mapping)
		mobj->ops->update_mapping(mobj, utc, va);
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

/* reg_shm represents TEE shared memory */
struct mobj *mobj_reg_shm_alloc(paddr_t *pages, size_t num_pages,
				paddr_t page_offset, uint64_t cookie);

struct mobj *mobj_reg_shm_find_by_cookie(uint64_t cookie);

/*
 * mapped_shm represents registered shared buffer
 * which is mapped into OPTEE va space
 */
struct mobj *mobj_mapped_shm_alloc(paddr_t *pages, size_t num_pages,
				   paddr_t page_offset, uint64_t cookie);

struct mobj *mobj_shm_alloc(paddr_t pa, size_t size);

struct mobj *mobj_paged_alloc(size_t size);

#ifdef CFG_PAGED_USER_TA
bool mobj_is_paged(struct mobj *mobj);
#else
static inline bool mobj_is_paged(struct mobj *mobj __unused)
{
	return false;
}
#endif

struct mobj *mobj_seccpy_shm_alloc(size_t size);

#endif /*__MM_MOBJ_H*/
