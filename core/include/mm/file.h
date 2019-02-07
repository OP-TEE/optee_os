/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2019, Linaro Limited
 */

#ifndef __MM_FILE_H
#define __MM_FILE_H

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
 * file_new() - allocate a new struct file
 * @tag:	Tag of the file
 * @taglen:	Length of @tag
 * @slices:	An array of file slices
 * @num_slices:	Number of elements in the @slices array
 *
 * Returns a newly allocated file with the reference counters of the fobjs
 * in all the slices increased on success. Returns NULL on failure.
 */
struct file *file_new(uint8_t *tag, unsigned int taglen,
		      struct file_slice *slices, unsigned int num_slices);

/*
 * file_get() - Increase file reference counter
 * @f:		File pointer
 *
 * Returns @f, if @if isn't NULL its reference counter is first increased.
 */
struct file *file_get(struct file *f);

/*
 * file_get_by_tag() - Finds a file based on tag and increase reference counter
 * @tag:	Tag of the file
 * @taglen:	Length of @tag
 *
 * Returns a file with an increased reference counter if found, or NULL if
 * not found.
 */
struct file *file_get_by_tag(uint8_t *tag, unsigned int taglen);

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
 * If a matching file slice is found it's returned, else NULL is returned.
 */
struct file_slice *file_find_slice(struct file *f, unsigned int page_offset);

#endif /*__MM_FILE_H*/

