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

/*
 * struct file - file resources
 * @tag:	Tag or hash uniquely identifying a the file
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
	unsigned int num_slices;
	struct file_slice slices[];
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
	size_t n = 0;

	for (n = 0; n < f->num_slices; n++)
		fobj_put(f->slices[n].fobj);

	free(f);
}

struct file *file_new(uint8_t *tag, unsigned int taglen,
		      struct file_slice *slices, unsigned int num_slices)
{
	unsigned int s = 0;
	unsigned int n = 0;
	struct file *f = NULL;
	bool did_insert = false;

	if (taglen > sizeof(f->tag))
		return NULL;
	if (MUL_OVERFLOW(num_slices, sizeof(*slices), &s))
		return NULL;
	if (ADD_OVERFLOW(s, sizeof(*f), &s))
		return NULL;
	f = calloc(1, s);
	if (!f)
		return NULL;

	memcpy(f->tag, tag, taglen);
	f->taglen = taglen;
	refcount_set(&f->refc, 1);
	for (n = 0; n < num_slices; n++) {
		f->slices[n].fobj = fobj_get(slices[n].fobj);
		if (!f->slices[n].fobj ||
		    ADD_OVERFLOW(slices[n].page_offset,
				 slices[n].fobj->num_pages, &s))
			goto err;
	}
	f->num_slices = num_slices;

	mutex_lock(&file_mu);
	if (!file_find_tag_unlocked(tag, taglen)) {
		TAILQ_INSERT_TAIL(&file_head, f, link);
		did_insert = true;
	}
	mutex_unlock(&file_mu);

	if (did_insert)
		return f;
err:
	file_free(f);

	return NULL;
}

struct file *file_get(struct file *f)
{
	if (f && !refcount_inc(&f->refc))
		panic();

	return f;
}

struct file *file_get_by_tag(uint8_t *tag, unsigned int taglen)
{
	struct file *f = NULL;

	mutex_lock(&file_mu);
	f = file_get(file_find_tag_unlocked(tag, taglen));
	mutex_unlock(&file_mu);

	return f;
}

void file_put(struct file *f)
{
	bool did_remove = false;

	if (!f)
		return;

	mutex_lock(&file_mu);
	if (refcount_dec(&f->refc)) {
		TAILQ_REMOVE(&file_head, f, link);
		did_remove = true;
	}
	mutex_unlock(&file_mu);

	if (did_remove)
		file_free(f);
}

struct file_slice *file_find_slice(struct file *f, unsigned int page_offset)
{
	size_t n = 0;

	if (!f)
		return NULL;

	for (n = 0; n < f->num_slices; n++) {
		struct file_slice *fs = f->slices + n;

		if (page_offset >= fs[n].page_offset &&
		    page_offset < fs[n].page_offset + fs[n].fobj->num_pages)
			return fs;
	}

	return NULL;
}
