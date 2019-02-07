/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2019, Linaro Limited
 */

#ifndef __MM_FOBJ_H
#define __MM_FOBJ_H

#include <kernel/refcount.h>
#include <kernel/panic.h>
#include <tee_api_types.h>
#include <types_ext.h>

/*
 * struct fobj - file object storage abstraction
 * @ops:	Operations pointer
 * @num_pages:	Number of pages covered
 * @refc:	Reference counter
 */
struct fobj {
	const struct fobj_ops *ops;
	unsigned int num_pages;
	struct refcount refc;
};

/*
 * struct fobj_ops - operations struct for struct fobj
 * @free:	Frees the @fobj
 * @load_page:	Loads page with index @page_idx at address @va
 * @save_page:	Saves page with index @page_idx from address @va
 */
struct fobj_ops {
	void (*free)(struct fobj *fobj);
#ifdef CFG_WITH_PAGER
	TEE_Result (*load_page)(struct fobj *fobj, unsigned int page_idx,
				void *va);
	TEE_Result (*save_page)(struct fobj *fobj, unsigned int page_idx,
				const void *va);
#endif
};

#ifdef CFG_WITH_PAGER
/*
 * fobj_locked_paged_alloc() - Allocate storage which is locked in memory
 * @num_pages:	Number of pages covered
 *
 * This object only supports loading pages zero initialized. Saving a page
 * will result in an error.
 *
 * Returns a valid pointer on success or NULL on failure.
 */
struct fobj *fobj_locked_paged_alloc(unsigned int num_pages);

/*
 * fobj_rw_paged_alloc() - Allocate read/write storage
 * @num_pages:	Number of pages covered
 *
 * This object supports both load and saving of pages. Pages are zero
 * initialized the first time they are loaded.
 *
 * Returns a valid pointer on success or NULL on failure.
 */
struct fobj *fobj_rw_paged_alloc(unsigned int num_pages);

/*
 * fobj_ro_paged_alloc() - Allocate initialized read-only storage
 * @num_pages:	Number of pages covered
 * @hashes:	Hashes to verify the pages
 * @store:	Clear text data for all pages
 *
 * This object only support loading pages with an already provided content
 * in @store. When a page is loaded it will be verified against an hash in
 * @hash. Saving a page will result in an error.
 *
 * Returns a valid pointer on success or NULL on failure.
 */
struct fobj *fobj_ro_paged_alloc(unsigned int num_pages, void *hashes,
				 void *store);

/*
 * fobj_load_page() - Load a page into memory
 * @fobj:	Fobj pointer
 * @page_index:	Index of page in @fobj
 * @va:		Address where content should be stored and verified
 *
 * Returns TEE_SUCCESS on success or TEE_ERROR_* on failure.
 */
static inline TEE_Result fobj_load_page(struct fobj *fobj,
					unsigned int page_idx, void *va)
{
	if (fobj)
		return fobj->ops->load_page(fobj, page_idx, va);

	return TEE_ERROR_GENERIC;
}

/*
 * fobj_save_page() - Save a page into storage
 * @fobj:	Fobj pointer
 * @page_index:	Index of page in @fobj
 * @va:		Address of the page to store.
 *
 * Returns TEE_SUCCESS on success or TEE_ERROR_* on failure.
 */
static inline TEE_Result fobj_save_page(struct fobj *fobj,
					unsigned int page_idx, const void *va)
{
	if (fobj)
		return fobj->ops->save_page(fobj, page_idx, va);

	return TEE_ERROR_GENERIC;
}
#endif

/*
 * fobj_get() - Increase fobj reference count
 * @fobj:	Fobj pointer
 *
 * Returns @fobj, if @fobj isn't NULL its reference counter is first
 * increased.
 */
static inline struct fobj *fobj_get(struct fobj *fobj)
{
	if (fobj && !refcount_inc(&fobj->refc))
		panic();

	return fobj;
}

/*
 * fobj_put() - Decrease reference counter of fobj
 * @fobj:	Fobj pointer
 *
 * If reference counter reaches 0, matching the numbers of fobj_alloc_*() +
 * fobj_get(), the fobj is freed.
 */
static inline void fobj_put(struct fobj *fobj)
{
	if (fobj && refcount_dec(&fobj->refc))
		fobj->ops->free(fobj);
}

#ifdef CFG_WITH_PAGER
/*
 * fobj_generate_authenc_key() - Generate authentication key
 *
 * Generates the authentication key used in all fobjs allocated with
 * fobj_rw_paged_alloc().
 */
void fobj_generate_authenc_key(void);
#else
static inline void fobj_generate_authenc_key(void)
{
}
#endif

#endif /*__MM_FOBJ_H*/
