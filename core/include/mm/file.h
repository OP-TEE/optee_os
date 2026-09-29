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
 * file_add_slice() - Add a not yet verified slice to a file
 * @f:		 File pointer
 * @fobj:	 Fobj holding the data of this slice
 * @page_offset: Offset in pages into the file (@f) where the @fobj is
 *		 located.
 *
 * Added unverified: invisible to file_find_slice() until the loader
 * calls file_end_load(..., true). Still checked for conflicts against
 * all slices, verified or not.
 *
 * File must be in locked state and caller must be the file's loader
 * (file_begin_load() returned true).
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
 * file_find_slice() - Find a verified slice covering the @page_offset
 * @f:		 File pointer
 * @page_offset: Offset that must be covered
 *
 * File must be in locked state. Only returns verified slices.
 *
 * Returns the matching slice, or NULL if none is found.
 */
struct file_slice *file_find_slice(struct file *f, unsigned int page_offset);

/*
 * file_begin_load() - Try to register the caller as the loader of @f
 * @f:		File pointer
 *
 * Serialize load access to a shared file. File must be in locked state.
 *
 * Returns true if the current thread was granted exclusive load rights.
 * When loading using file_add_slice(), the loading is finalized with
 * file_end_load().
 *
 * Returns false if another thread is already loading @f: the caller
 * should call file_wait_load(), then retry file_find_slice().
 */
bool file_begin_load(struct file *f);

/*
 * file_wait_load() - Wait for another thread's ongoing load of @f
 * @f:		File pointer
 *
 * Blocks until the current loader calls file_end_load(). Only valid
 * to call after file_begin_load() returned false for @f.
 *
 * File must be in locked state. Releases and reacquires the file's
 * internal lock while waiting.
 */
void file_wait_load(struct file *f);

/*
 * file_end_load() - End the caller's load of @f
 * @f:		File pointer
 * @verified:	True if the loaded binary's digest/signature check
 *		succeeded
 *
 * Called once by the registered loader (file_begin_load() returned
 * true) when done. Every unverified slice is promoted (@verified
 * true) or removed and released (@verified false). Wakes threads
 * blocked in file_wait_load().
 *
 * File must be in locked state.
 */
void file_end_load(struct file *f, bool verified);

#endif /*__MM_FILE_H*/

