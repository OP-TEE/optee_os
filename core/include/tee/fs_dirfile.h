/*
 * Copyright (c) 2017, Linaro Limited
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

#ifndef __TEE_FS_DIRFILE_H
#define __TEE_FS_DIRFILE_H

#include <tee/tee_fs.h>
#include <tee/fs_htree.h>

struct tee_fs_dirfile_dirh;

/**
 * struct tee_fs_dirfile_fileh - file handle
 * @file_number:	sequence number of a file
 * @hash:		hash of file, to be supplied to tee_fs_htree_open()
 * @idx:		index of the file handle in the dirfile
 */
struct tee_fs_dirfile_fileh {
	uint32_t file_number;
	uint8_t hash[TEE_FS_HTREE_HASH_SIZE];
	int idx;
};

/**
 * struct tee_fs_dirfile_operations - file interface supplied by user of this
 * interface
 * @open:		opens a file
 * @close:		closes a file, changes are discarded unless
 *			@commit_writes is called before
 * @read:		reads from an open file
 * @write:		writes to an open file
 * @commit_writes:	commits changes since the file was opened
 */
struct tee_fs_dirfile_operations {
	TEE_Result (*open)(bool create, uint8_t *hash, const TEE_UUID *uuid,
			   struct tee_fs_dirfile_fileh *dfh,
			   struct tee_file_handle **fh);
	void (*close)(struct tee_file_handle *fh);
	TEE_Result (*read)(struct tee_file_handle *fh, size_t pos,
			   void *buf, size_t *len);
	TEE_Result (*write)(struct tee_file_handle *fh, size_t pos,
			    const void *buf, size_t len);
	TEE_Result (*commit_writes)(struct tee_file_handle *fh, uint8_t *hash);
};

/**
 * tee_fs_dirfile_open() - opens a dirfile handle
 * @create:	true if a new dirfile is to be created, else the dirfile
 *		is read opened and verified
 * @hash:	hash of underlying file
 * @fops:	file interface
 * @dirh:	returned dirfile handle
 */
TEE_Result tee_fs_dirfile_open(bool create, uint8_t *hash,
			       const struct tee_fs_dirfile_operations *fops,
			       struct tee_fs_dirfile_dirh **dirh);
/**
 * tee_fs_dirfile_close() - closes a dirfile handle
 * @dirh:	dirfile handle
 *
 * All changes since last call to tee_fs_dirfile_commit_writes() are
 * discarded.
 */
void tee_fs_dirfile_close(struct tee_fs_dirfile_dirh *dirh);

/**
 * tee_fs_dirfile_commit_writes() - commit updates of dirfile
 * @dirh:	dirfile handle
 * @hash:	hash of underlying file is copied here if not NULL
 */
TEE_Result tee_fs_dirfile_commit_writes(struct tee_fs_dirfile_dirh *dirh,
					uint8_t *hash);

/**
 * tee_fs_dirfile_get_tmp() - get a temporary file handle
 * @dirh:	dirfile handle
 * @dfh:	returned temporary file handle
 *
 * Note, nothing is queued up as changes to the dirfile with this function.
 */
TEE_Result tee_fs_dirfile_get_tmp(struct tee_fs_dirfile_dirh *dirh,
				  struct tee_fs_dirfile_fileh *dfh);

/**
 * tee_fs_dirfile_find() - find a file handle
 * @dirh:	dirfile handle
 * @uuid:	uuid of requesting TA
 * @oid:	object id
 * @oidlen:	length of object id
 * @dfh:	returned file handle
 */
TEE_Result tee_fs_dirfile_find(struct tee_fs_dirfile_dirh *dirh,
			       const TEE_UUID *uuid, const void *oid,
			       size_t oidlen, struct tee_fs_dirfile_fileh *dfh);

/**
 * tee_fs_dirfile_fileh_to_fname() - get string representation of file handle
 * @dfh:	file handle
 * @fname:	buffer
 * @fnlen:	length of buffer, updated to used length
 */
TEE_Result tee_fs_dirfile_fileh_to_fname(const struct tee_fs_dirfile_fileh *dfh,
					 char *fname, size_t *fnlen);

/**
 * tee_fs_dirfile_rename() - changes/supplies file handle object id
 * @dirh:	dirfile handle
 * @uuid:	uuid of requesting TA
 * @dfh:	file handle
 * @oid:	object id
 * @oidlen:	length of object id
 *
 * If the supplied object id already is used by another file is that file
 * removed from the dirfile.
 */
TEE_Result tee_fs_dirfile_rename(struct tee_fs_dirfile_dirh *dirh,
				 const TEE_UUID *uuid,
				 struct tee_fs_dirfile_fileh *dfh,
				 const void *oid, size_t oidlen);

/**
 * tee_fs_dirfile_remove() - remove file
 * @dirh:	dirfile handle
 * @dfh:	file handle
 */
TEE_Result tee_fs_dirfile_remove(struct tee_fs_dirfile_dirh *dirh,
				 const struct tee_fs_dirfile_fileh *dfh);

/**
 * tee_fs_dirfile_update_hash() - update hash of file handle
 * @dirh:	filefile handle
 * @dfh:	file handle
 */
TEE_Result tee_fs_dirfile_update_hash(struct tee_fs_dirfile_dirh *dirh,
				      const struct tee_fs_dirfile_fileh *dfh);

/**
 * tee_fs_dirfile_get_next() - get object id of next file
 * @dirh:	dirfile handle
 * @uuid:	uuid of requesting TA
 * @idx:	pointer to index
 * @oid:	object id
 * @oidlen:	length of object id
 *
 * If @idx contains -1 the first object id is returned, *@idx is updated
 * with the index of the file.
 */
TEE_Result tee_fs_dirfile_get_next(struct tee_fs_dirfile_dirh *dirh,
				   const TEE_UUID *uuid, int *idx, void *oid,
				   size_t *oidlen);

#endif /*__TEE_FS_DIRFILE_H*/
