/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2019, Linaro Limited
 */

#ifndef __MM_FILE_H
#define __MM_FILE_H

#include <tee_api_types.h>
#include <types_ext.h>
#include <utee_defines.h>

/* This is supposed to be large enough to hold any hash or tag used */
#define FILE_TAG_SIZE	TEE_SHA256_HASH_SIZE

/*
 * struct file_slice - one slice of a file
 * @fobj:	 Fobj holding the data of this slice
 * @page_offset: Offset in pages into the file where the @fobj is
 *		 located.
 */
struct file_slice {
	struct fobj *fobj;
	unsigned int page_offset;
};

struct file;

/*
 * file_lock() - Lock the file
 * @f:		File pointer
 *
 * Waits until the file can be locked and with the file put in locked state.
 */
void file_lock(struct file *f);

/*
 * file_lock() - Try to lock the file without blocking
 * @f:		File pointer
 *
 * Returns false if file cannot be locked without blocking.
 * Returns true if the file has been put in locked state.
 */
bool file_trylock(struct file *f);

/*
 * file_unlock() - Unlock the file
 * @f:		File pointer
 *
 * File must be in locked state. Releases the previous lock and returns.
 */
void file_unlock(struct file *f);

/*
 * file_add_slice() - Add a slice to a file
 * @f:		 File pointer
 * @fobj:	 Fobj holding the data of this slice
 * @page_offset: Offset in pages into the file (@f) where the @fobj is
 *		 located.
 *
 * File must be in locked state.
 *
 * Returns TEE_SUCCESS on success or a TEE_ERROR_* code on failure.
 */
TEE_Result file_add_slice(struct file *f, struct fobj *fobj,
			  unsigned int page_offset);

/*
 * file_get() - Increase file reference counter
 * @f:		File pointer
 *
 * Returns @f, if @f isn't NULL its reference counter is first increased.
 */
struct file *file_get(struct file *f);

/*
 * file_get_by_tag() - Finds a file based on tag and increase reference counter
 * @tag:	Tag of the file
 * @taglen:	Length of @tag
 *
 * If a file doesn't exist it's created with the supplied tag.
 *
 * Returns a file with an increased reference counter, or NULL on failure.
 */
struct file *file_get_by_tag(const uint8_t *tag, unsigned int taglen);

/*
 * file_put() - Decrease reference counter of file
 * @f:		File pointer
 *
 * If reference counter reaches 0, matching the numbers of file_new() +
 * file_get() + file_get_by_tag(), the file is removed with reference
 * counters for all contained fobjs decreased.
 */
void file_put(struct file *f);

/*
 * file_find_slice() - Find a slice covering the @page_offset
 * @f:		 File pointer
 * @page_offset: Offset that must be covered
 *
 * File must be in locked state.
 *
 * If a matching file slice is found it is returned, else NULL is returned.
 */
struct file_slice *file_find_slice(struct file *f, unsigned int page_offset);

#endif /*__MM_FILE_H*/

