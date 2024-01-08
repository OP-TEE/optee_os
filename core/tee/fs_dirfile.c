// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017, Linaro Limited
 */

#include <assert.h>
#include <bitstring.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tee/fs_dirfile.h>
#include <types_ext.h>

struct tee_fs_dirfile_dirh {
	const struct tee_fs_dirfile_operations *fops;
	struct tee_file_handle *fh;
	int nbits;
	bitstr_t *files;
	size_t ndents;
};

struct dirfile_entry {
	TEE_UUID uuid;
	uint8_t oid[TEE_OBJECT_ID_MAX_LEN];
	uint32_t oidlen;
	uint8_t hash[TEE_FS_HTREE_HASH_SIZE];
	uint32_t file_number;
};

#define OID_EMPTY_NAME 1

/*
 * An object can have an ID of size zero. This object is represented by
 * oidlen == 0 and oid[0] == OID_EMPTY_NAME. When both are zero, the entry is
 * not a valid object.
 */
static bool is_free(struct dirfile_entry *dent)
{
	assert(dent->oidlen || !dent->oid[0] || dent->oid[0] == OID_EMPTY_NAME);

	return !dent->oidlen && !dent->oid[0];
}

/*
 * File layout
 *
 * dirfile_entry.0
 * ...
 * dirfile_entry.n
 *
 * where n the index is disconnected from file_number in struct dirfile_entry
 */

static TEE_Result maybe_grow_files(struct tee_fs_dirfile_dirh *dirh, int idx)
{
	void *p;

	if (idx < dirh->nbits)
		return TEE_SUCCESS;

	p = realloc(dirh->files, bitstr_size(idx + 1));
	if (!p)
		return TEE_ERROR_OUT_OF_MEMORY;
	dirh->files = p;

	bit_nclear(dirh->files, dirh->nbits, idx);
	dirh->nbits = idx + 1;

	return TEE_SUCCESS;
}

static TEE_Result set_file(struct tee_fs_dirfile_dirh *dirh, int idx)
{
	TEE_Result res = maybe_grow_files(dirh, idx);

	if (!res)
		bit_set(dirh->files, idx);

	return res;
}

static void clear_file(struct tee_fs_dirfile_dirh *dirh, int idx)
{
	if (idx < dirh->nbits)
		bit_clear(dirh->files, idx);
}

static bool test_file(struct tee_fs_dirfile_dirh *dirh, int idx)
{
	if (idx < dirh->nbits)
		return bit_test(dirh->files, idx);

	return false;
}

static TEE_Result read_dent(struct tee_fs_dirfile_dirh *dirh, int idx,
			    struct dirfile_entry *dent)
{
	TEE_Result res;
	size_t l;

	l = sizeof(*dent);
	res = dirh->fops->read(dirh->fh, sizeof(struct dirfile_entry) * idx,
			       dent, &l);
	if (!res && l != sizeof(*dent))
		res = TEE_ERROR_ITEM_NOT_FOUND;

	return res;
}

static TEE_Result write_dent(struct tee_fs_dirfile_dirh *dirh, size_t n,
			     struct dirfile_entry *dent)
{
	TEE_Result res;

	res = dirh->fops->write(dirh->fh, sizeof(*dent) * n, dent,
				sizeof(*dent));
	if (!res && n >= dirh->ndents)
		dirh->ndents = n + 1;

	return res;
}

TEE_Result tee_fs_dirfile_open(bool create, uint8_t *hash, uint32_t min_counter,
			       const struct tee_fs_dirfile_operations *fops,
			       struct tee_fs_dirfile_dirh **dirh_ret)
{
	TEE_Result res;
	struct tee_fs_dirfile_dirh *dirh = calloc(1, sizeof(*dirh));
	size_t n;

	if (!dirh)
		return TEE_ERROR_OUT_OF_MEMORY;

	dirh->fops = fops;
	res = fops->open(create, hash, min_counter, NULL, NULL, &dirh->fh);
	if (res)
		goto out;

	for (n = 0;; n++) {
		struct dirfile_entry dent = { };

		res = read_dent(dirh, n, &dent);
		if (res) {
			if (res == TEE_ERROR_ITEM_NOT_FOUND)
				res = TEE_SUCCESS;
			goto out;
		}

		if (is_free(&dent))
			continue;

		if (test_file(dirh, dent.file_number)) {
			DMSG("clearing duplicate file number %" PRIu32,
			     dent.file_number);
			memset(&dent, 0, sizeof(dent));
			res = write_dent(dirh, n, &dent);
			if (res)
				goto out;
			continue;
		}

		res = set_file(dirh, dent.file_number);
		if (res != TEE_SUCCESS)
			goto out;
	}
out:
	if (!res) {
		dirh->ndents = n;
		*dirh_ret = dirh;
	} else {
		tee_fs_dirfile_close(dirh);
	}
	return res;
}

void tee_fs_dirfile_close(struct tee_fs_dirfile_dirh *dirh)
{
	if (dirh) {
		dirh->fops->close(dirh->fh);
		free(dirh->files);
		free(dirh);
	}
}

TEE_Result tee_fs_dirfile_commit_writes(struct tee_fs_dirfile_dirh *dirh,
					uint8_t *hash, uint32_t *counter)
{
	return dirh->fops->commit_writes(dirh->fh, hash, counter);
}

TEE_Result tee_fs_dirfile_get_tmp(struct tee_fs_dirfile_dirh *dirh,
				  struct tee_fs_dirfile_fileh *dfh)
{
	TEE_Result res;
	int i = 0;

	if (dirh->nbits) {
		bit_ffc(dirh->files, dirh->nbits, &i);
		if (i == -1)
			i = dirh->nbits;
	}

	res = set_file(dirh, i);
	if (!res)
		dfh->file_number = i;

	return res;
}

TEE_Result tee_fs_dirfile_find(struct tee_fs_dirfile_dirh *dirh,
			       const TEE_UUID *uuid, const void *oid,
			       size_t oidlen, struct tee_fs_dirfile_fileh *dfh)
{
	TEE_Result res = TEE_SUCCESS;
	struct dirfile_entry dent = { };
	int n = 0;

	for (n = 0;; n++) {
		res = read_dent(dirh, n, &dent);
		if (res)
			return res;

		if (is_free(&dent))
			continue;
		if (dent.oidlen != oidlen)
			continue;

		assert(test_file(dirh, dent.file_number));

		if (!memcmp(&dent.uuid, uuid, sizeof(dent.uuid)) &&
		    !memcmp(&dent.oid, oid, oidlen))
			break;
	}

	if (dfh) {
		dfh->idx = n;
		dfh->file_number = dent.file_number;
		memcpy(dfh->hash, dent.hash, sizeof(dent.hash));
	}

	return TEE_SUCCESS;
}

static TEE_Result find_empty_idx(struct tee_fs_dirfile_dirh *dh, int *idx)
{
	struct dirfile_entry dent = { };
	TEE_Result res = TEE_SUCCESS;
	int n = 0;

	for (n = 0;; n++) {
		res = read_dent(dh, n, &dent);
		if (res == TEE_ERROR_ITEM_NOT_FOUND)
			break;
		if (res)
			return res;
		if (is_free(&dent))
			break;
	}

	*idx = n;
	return TEE_SUCCESS;
}

TEE_Result tee_fs_dirfile_fileh_to_fname(const struct tee_fs_dirfile_fileh *dfh,
					 char *fname, size_t *fnlen)
{
	int r;
	size_t l = *fnlen;

	if (dfh)
		r = snprintf(fname, l, "%" PRIx32, dfh->file_number);
	else
		r = snprintf(fname, l, "dirf.db");

	if (r < 0)
		return TEE_ERROR_GENERIC;

	*fnlen = r + 1;
	if ((size_t)r >= l)
		return TEE_ERROR_SHORT_BUFFER;

	return TEE_SUCCESS;
}

TEE_Result tee_fs_dirfile_rename(struct tee_fs_dirfile_dirh *dirh,
				 const TEE_UUID *uuid,
				 struct tee_fs_dirfile_fileh *dfh,
				 const void *oid, size_t oidlen)
{
	TEE_Result res;
	struct dirfile_entry dent = { };

	if (oidlen > sizeof(dent.oid))
		return TEE_ERROR_BAD_PARAMETERS;
	memset(&dent, 0, sizeof(dent));
	dent.uuid = *uuid;
	if (oidlen)
		memcpy(dent.oid, oid, oidlen);
	else
		dent.oid[0] = OID_EMPTY_NAME;

	dent.oidlen = oidlen;
	memcpy(dent.hash, dfh->hash, sizeof(dent.hash));
	dent.file_number = dfh->file_number;

	if (dfh->idx < 0) {
		struct tee_fs_dirfile_fileh dfh2;

		res = tee_fs_dirfile_find(dirh, uuid, oid, oidlen, &dfh2);
		if (res) {
			if (res == TEE_ERROR_ITEM_NOT_FOUND)
				res = find_empty_idx(dirh, &dfh2.idx);
			if (res)
				return res;
		}
		dfh->idx = dfh2.idx;
	}

	return write_dent(dirh, dfh->idx, &dent);
}

TEE_Result tee_fs_dirfile_remove(struct tee_fs_dirfile_dirh *dirh,
				 const struct tee_fs_dirfile_fileh *dfh)
{
	TEE_Result res;
	struct dirfile_entry dent = { };
	uint32_t file_number;

	res = read_dent(dirh, dfh->idx, &dent);
	if (res)
		return res;

	if (is_free(&dent))
		return TEE_SUCCESS;

	file_number = dent.file_number;
	assert(dfh->file_number == file_number);
	assert(test_file(dirh, file_number));

	memset(&dent, 0, sizeof(dent));
	res = write_dent(dirh, dfh->idx, &dent);
	if (!res)
		clear_file(dirh, file_number);

	return res;
}

TEE_Result tee_fs_dirfile_update_hash(struct tee_fs_dirfile_dirh *dirh,
				      const struct tee_fs_dirfile_fileh *dfh)
{
	TEE_Result res;
	struct dirfile_entry dent = { };

	res = read_dent(dirh, dfh->idx, &dent);
	if (res)
		return res;
	assert(dent.file_number == dfh->file_number);
	assert(test_file(dirh, dent.file_number));

	memcpy(&dent.hash, dfh->hash, sizeof(dent.hash));

	return write_dent(dirh, dfh->idx, &dent);
}

TEE_Result tee_fs_dirfile_get_next(struct tee_fs_dirfile_dirh *dirh,
				   const TEE_UUID *uuid, int *idx, void *oid,
				   size_t *oidlen)
{
	TEE_Result res;
	int i = *idx + 1;
	struct dirfile_entry dent = { };

	if (i < 0)
		i = 0;

	for (;; i++) {
		res = read_dent(dirh, i, &dent);
		if (res)
			return res;
		if (!memcmp(&dent.uuid, uuid, sizeof(dent.uuid)) &&
		    !is_free(&dent))
			break;
	}

	if (*oidlen < dent.oidlen)
		return TEE_ERROR_SHORT_BUFFER;

	memcpy(oid, dent.oid, dent.oidlen);
	*oidlen = dent.oidlen;
	*idx = i;

	return TEE_SUCCESS;
}
