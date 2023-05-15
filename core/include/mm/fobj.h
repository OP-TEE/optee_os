/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2019-2021, Linaro Limited
 */

#ifndef __MM_FOBJ_H
#define __MM_FOBJ_H

#include <kernel/panic.h>
#include <kernel/refcount.h>
#include <mm/tee_pager.h>
#include <sys/queue.h>
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
#ifdef CFG_WITH_PAGER
	struct vm_paged_region_head regions;
#endif
};

/*
 * struct fobj_ops - operations struct for struct fobj
 * @free:	  Frees the @fobj
 * @load_page:	  Loads page with index @page_idx at address @va
 * @save_page:	  Saves page with index @page_idx from address @va
 * @get_iv_vaddr: Returns virtual address of tag and IV for the page at
 *		  @page_idx if tag and IV are paged for this fobj
 * @get_pa:	  Returns physical address of page at @page_idx if not paged
 */
struct fobj_ops {
	void (*free)(struct fobj *fobj);
#ifdef CFG_WITH_PAGER
	TEE_Result (*load_page)(struct fobj *fobj, unsigned int page_idx,
				void *va);
	TEE_Result (*save_page)(struct fobj *fobj, unsigned int page_idx,
				const void *va);
	vaddr_t (*get_iv_vaddr)(struct fobj *fobj, unsigned int page_idx);
#endif
	paddr_t (*get_pa)(struct fobj *fobj, unsigned int page_idx);
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
 * fobj_ro_reloc_paged_alloc() - Allocate initialized read-only storage with
 *				 relocation
 * @num_pages:	Number of pages covered
 * @hashes:	Hashes to verify the pages
 * @reloc_offs:	Offset from the base address in the relocations in @reloc
 * @reloc:	Relocation data
 * @reloc_len:	Length of relocation data
 * @store:	Clear text data for all pages
 *
 * This object is like fobj_ro_paged_alloc() above, but in addition the
 * relocation information is applied to a populated page. This makes sure
 * the offset to which all pages are relocated doesn't leak out to storage.
 *
 * Returns a valid pointer on success or NULL on failure.
 */
struct fobj *fobj_ro_reloc_paged_alloc(unsigned int num_pages, void *hashes,
				       unsigned int reloc_offs,
				       const void *reloc,
				       unsigned int reloc_len, void *store);

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

static inline vaddr_t fobj_get_iv_vaddr(struct fobj *fobj,
					unsigned int page_idx)
{
	if (fobj && fobj->ops->get_iv_vaddr)
		return fobj->ops->get_iv_vaddr(fobj, page_idx);

	return 0;
}
#endif

/*
 * fobj_ta_mem_alloc() - Allocates TA memory
 * @num_pages:	Number of pages
 *
 * If paging of user TAs read/write paged fobj is allocated otherwise a
 * fobj which uses unpaged secure memory directly.
 *
 * Returns a valid pointer on success or NULL on failure.
 */
#ifdef CFG_PAGED_USER_TA
#define fobj_ta_mem_alloc(num_pages)	fobj_rw_paged_alloc(num_pages)
#else
/*
 * fobj_sec_mem_alloc() - Allocates storage directly in secure memory
 * @num_pages:	Number of pages
 *
 * Returns a valid pointer on success or NULL on failure.
 */
struct fobj *fobj_sec_mem_alloc(unsigned int num_pages);

#define fobj_ta_mem_alloc(num_pages)	fobj_sec_mem_alloc(num_pages)
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

#endif /*__MM_FOBJ_H*/
