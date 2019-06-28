// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019, Linaro Limited
 */

#include <kernel/panic.h>
#include <kernel/refcount.h>
#include <mm/file.h>
#include <mm/fobj.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <types_ext.h>
#include <util.h>

struct file_slice_elem {
	struct file_slice slice;
	SLIST_ENTRY(file_slice_elem) link;
};

/*
 * struct file - file resources
 * @tag:	Tag or hash uniquely identifying a file
 * @taglen:	Byte length of @tag
 * @refc:	Reference counter
 * @link:	Linked list element
 * @num_slices:	Number of elements in the @slices array below
 * @slices:	Array of file slices holding the fobjs of this file
 *
 * A file is constructed of slices which may be shared in different
 * mappings/contexts. There may be holes in the file for ranges of the file
 * that can't be shared.
 */
struct file {
	uint8_t tag[FILE_TAG_SIZE];
	unsigned int taglen;
	struct refcount refc;
	TAILQ_ENTRY(file) link;
	struct mutex mu;
	SLIST_HEAD(, file_slice_elem) slice_head;
};

static struct mutex file_mu = MUTEX_INITIALIZER;
static TAILQ_HEAD(, file) file_head = TAILQ_HEAD_INITIALIZER(file_head);

static int file_tag_cmp(const struct file *f, const uint8_t *tag,
			unsigned int taglen)
{
	if (f->taglen != taglen)
		return -1;
	return memcmp(tag, f->tag, taglen);
}

static struct file *file_find_tag_unlocked(const uint8_t *tag,
					   unsigned int taglen)
{
	struct file *f = NULL;

	TAILQ_FOREACH(f, &file_head, link)
		if (!file_tag_cmp(f, tag, taglen))
			return f;

	return NULL;
}

static void file_free(struct file *f)
{
	mutex_destroy(&f->mu);

	while (!SLIST_EMPTY(&f->slice_head)) {
		struct file_slice_elem *fse = SLIST_FIRST(&f->slice_head);

		SLIST_REMOVE_HEAD(&f->slice_head, link);
		fobj_put(fse->slice.fobj);
		free(fse);
	}

	free(f);
}

TEE_Result file_add_slice(struct file *f, struct fobj *fobj,
			  unsigned int page_offset)
{
	struct file_slice_elem *fse = NULL;
	unsigned int s = 0;

	/* Check for conflicts */
	if (file_find_slice(f, page_offset))
		return TEE_ERROR_BAD_PARAMETERS;

	fse = calloc(1, sizeof(*fse));
	if (!fse)
		return TEE_ERROR_OUT_OF_MEMORY;

	fse->slice.fobj = fobj_get(fobj);
	if (!fse->slice.fobj ||
	    ADD_OVERFLOW(page_offset, fse->slice.fobj->num_pages, &s)) {
		fobj_put(fse->slice.fobj);
		free(fse);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	fse->slice.page_offset = page_offset;
	SLIST_INSERT_HEAD(&f->slice_head, fse, link);

	return TEE_SUCCESS;
}

struct file *file_get(struct file *f)
{
	if (f && !refcount_inc(&f->refc))
		panic();

	return f;
}

struct file *file_get_by_tag(const uint8_t *tag, unsigned int taglen)
{
	struct file *f = NULL;

	if (taglen > sizeof(f->tag))
		return NULL;

	mutex_lock(&file_mu);

	/*
	 * If file is found and reference counter can be increased, we're done.
	 * If file can't be found, it doesn't exist so it has to be added.
	 * If it's found but reference counter is 0, the situation is
	 * a bit complicated:
	 * - file_put() is about to free the file as soon as it can obtain the
	 *   mutex.
	 * - Unless there's a mismatch between file_get() and file_put() only
	 *   one thread calling file_put() is about to free the file.
	 *
	 * There's a window of opportunity where file_put() is called
	 * (without a mutex being held, which is quite OK) while we're
	 * holding the mutex here and are searching for the file and it's
	 * found, but just after file_put() has decreased the reference
	 * counter.
	 *
	 * To keep it simple we're adding a new file at the head (so new
	 * searches finds this file instead of the old being freed) instead
	 * of complicating file_put() by trying to rescue the file and
	 * possibly hiding a case of mismatching file_put() and file_get().
	 */
	f = file_find_tag_unlocked(tag, taglen);
	if (f && refcount_inc(&f->refc))
		goto out;

	f = calloc(1, sizeof(*f));
	if (!f)
		goto out;
	memcpy(f->tag, tag, taglen);
	f->taglen = taglen;
	refcount_set(&f->refc, 1);
	mutex_init(&f->mu);
	SLIST_INIT(&f->slice_head);
	TAILQ_INSERT_HEAD(&file_head, f, link);

out:
	mutex_unlock(&file_mu);

	return f;
}

void file_put(struct file *f)
{
	if (f && refcount_dec(&f->refc)) {
		mutex_lock(&file_mu);
		TAILQ_REMOVE(&file_head, f, link);
		mutex_unlock(&file_mu);

		file_free(f);
	}

}

struct file_slice *file_find_slice(struct file *f, unsigned int page_offset)
{
	struct file_slice_elem *fse = NULL;

	assert(f->mu.state);

	SLIST_FOREACH(fse, &f->slice_head, link) {
		struct file_slice *fs = &fse->slice;

		if (page_offset >= fs->page_offset &&
		    page_offset < fs->page_offset + fs->fobj->num_pages)
			return fs;
	}

	return NULL;
}

void file_lock(struct file *f)
{
	mutex_lock(&f->mu);
}

bool file_trylock(struct file *f)
{
	return mutex_trylock(&f->mu);
}

void file_unlock(struct file *f)
{
	mutex_unlock(&f->mu);
}
