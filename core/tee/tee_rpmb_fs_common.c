/*
 * Copyright (c) 2015, Linaro Limited
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

#include <stdlib.h>
#include <string.h>
#include <tee/tee_fs.h>
#include <tee/tee_fs_defs.h>
#include <tee/tee_rpmb_fs.h>
#include <kernel/handle.h>
#include <kernel/tee_common_unpg.h>
#include <trace.h>
#include <assert.h>

#include "tee_fs_private.h"

static struct handle_db fs_handle_db = HANDLE_DB_INITIALIZER;

static void do_fail_recovery(struct tee_fs_fd *fdp)
{
	/* Try to delete the file for new created file */
	if (fdp->is_new_file) {
		tee_fs_common_unlink(fdp->filename);
		EMSG("New created file was deleted, file=%s",
				fdp->filename);
		return;
	}

	/* Note: Roll back is automatic for RPMB */
}

struct tee_fs_fd *tee_fs_fd_lookup(int fd)
{
	return handle_lookup(&fs_handle_db, fd);
}

int tee_fs_common_open(TEE_Result *errno, const char *file, int flags, ...)
{
	int res = -1;
	size_t len;
	bool is_new_file = false;
	int fd = -1;
	struct tee_fs_fd *fdp = NULL;

	assert(errno);
	*errno = TEE_SUCCESS;

	len = strlen(file) + 1;
	if (len > TEE_FS_NAME_MAX) {
		*errno = TEE_ERROR_BAD_PARAMETERS;
		goto exit;
	}

	/*
	 * try to open file without O_CREATE flag, if failed try again with
	 * O_CREATE flag (to distinguish whether it's a new file or not)
	 */
	res = tee_rpmb_fs_open(file, flags & (~TEE_FS_O_CREATE));
	if (res < 0) {
		if (!(flags & TEE_FS_O_CREATE)) {
			*errno = TEE_ERROR_ITEM_NOT_FOUND;
			goto exit;
		}

		res = tee_rpmb_fs_open(file, flags);
		if (res < 0)
			goto exit;

		is_new_file = true;
	} else {
		/* File already exists */
		if ((flags & TEE_FS_O_CREATE) && (flags & TEE_FS_O_EXCL)) {
			*errno = TEE_ERROR_ACCESS_CONFLICT;
			goto exit;
		}
	}

	fd = res;
	fdp = malloc(sizeof(struct tee_fs_fd));
	if (!fdp)
		goto exit;

	/* init internal status */
	fdp->nw_fd = fd;
	fdp->flags = flags;
	fdp->is_new_file = is_new_file;
	fdp->filename = strdup(file);
	if (!fdp->filename) {
		res = -1;
		goto exit;
	}

	/* return fd */
	res = handle_get(&fs_handle_db, fdp);
	fdp->fd = res;

exit:
	if (res == -1) {
		free(fdp);
		if (fd != -1)
			tee_rpmb_fs_close(fd);
	}

	return res;
}

int tee_fs_common_close(struct tee_fs_fd *fdp)
{
	int res = -1;

	if (!fdp)
		return -1;

	handle_put(&fs_handle_db, fdp->fd);

	res = tee_rpmb_fs_close(fdp->nw_fd);
	if (res < 0) {
		EMSG("Failed to close file, start fail recovery");
		do_fail_recovery(fdp);
	}

	free(fdp->filename);
	free(fdp);

	return res;
}


static TEE_Result to_errno(int rc)
{
	if (rc == -1)
		return TEE_ERROR_GENERIC;
	else if (rc < 0)
		return (TEE_Result)rc;
	else
		return TEE_SUCCESS;
}

static int filter_rc(int rc)
{
	if (rc < 0)
		return -1;
	else
		return rc;
}


tee_fs_off_t tee_fs_common_lseek(TEE_Result *errno, struct tee_fs_fd *fdp,
				tee_fs_off_t offset, int whence)
{
	int rc;
	int res = -1;

	assert(errno != NULL);
	*errno = TEE_SUCCESS;

	if (!fdp) {
		*errno = TEE_ERROR_BAD_PARAMETERS;
		res = -1;
		goto exit;
	}

	rc = tee_rpmb_fs_lseek(fdp->nw_fd, offset, whence);
	if (rc == -1) {
		*errno = TEE_ERROR_GENERIC;
		res = -1;
	} else if (rc < 0) {
		*errno = (TEE_Result)rc;
		res = -1;
	} else {
		res = rc;
	}

exit:
	return res;
}

int tee_fs_common_ftruncate(TEE_Result *errno, struct tee_fs_fd *fdp,
			    tee_fs_off_t length)
{
	int rc;
	int res = -1;

	assert(errno != NULL);
	*errno = TEE_SUCCESS;

	if (!fdp) {
		*errno = TEE_ERROR_BAD_PARAMETERS;
		res = -1;
		goto exit;
	}

	rc = tee_rpmb_fs_ftruncate(fdp->nw_fd, length);
	*errno = to_errno(rc);
	res = filter_rc(rc);
exit:
	return res;
}

int tee_fs_common_read(TEE_Result *errno, struct tee_fs_fd *fdp,
		       void *buf, size_t len)
{
	int rc;
	int res = -1;

	assert(errno != NULL);
	*errno = TEE_SUCCESS;

	if (!fdp) {
		*errno = TEE_ERROR_BAD_PARAMETERS;
		res = -1;
		goto exit;
	}

	rc = tee_rpmb_fs_read(fdp->nw_fd, (uint8_t *)buf, len);
	*errno = to_errno(rc);
	res = filter_rc(rc);

exit:
	return res;
}

int tee_fs_common_write(TEE_Result *errno, struct tee_fs_fd *fdp,
			const void *buf, size_t len)
{
	int rc;
	int res = -1;

	assert(errno != NULL);
	*errno = TEE_SUCCESS;

	if (!fdp) {
		*errno = TEE_ERROR_BAD_PARAMETERS;
		goto exit;
	}

	if (!len) {
		res = 0;
		goto exit;
	}

	if (!buf) {
		*errno = TEE_ERROR_BAD_PARAMETERS;
		goto exit;
	}

	rc = tee_rpmb_fs_write(fdp->nw_fd, (uint8_t *)buf, len);
	*errno = to_errno(rc);
	res = filter_rc(rc);

exit:
	return res;
}

int tee_fs_common_rename(const char *old, const char *new)
{
	return tee_rpmb_fs_rename(old, new);
}

int tee_fs_common_unlink(const char *file)
{
	return tee_rpmb_fs_rm(file);
}

int tee_fs_common_mkdir(const char *path, tee_fs_mode_t mode)
{
	return tee_rpmb_fs_mkdir(path, mode);
}

tee_fs_dir *tee_fs_common_opendir(const char *name)
{
	return tee_rpmb_fs_opendir(name);
}

int tee_fs_common_closedir(tee_fs_dir *d)
{
	return tee_rpmb_fs_closedir(d);
}

struct tee_fs_dirent *tee_fs_common_readdir(tee_fs_dir *d)
{
	return tee_rpmb_fs_readdir(d);
}

int tee_fs_common_rmdir(const char *name)
{
	return tee_rpmb_fs_rmdir(name);
}

int tee_fs_common_access(const char *name, int mode)
{
	return tee_rpmb_fs_access(name, mode);
}

