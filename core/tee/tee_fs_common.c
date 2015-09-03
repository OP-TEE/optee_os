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
#include <kernel/tee_common_unpg.h>
#include <kernel/handle.h>
#include <trace.h>

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

	/* TODO: Roll back to previous version for existed file */
}

struct tee_fs_fd *tee_fs_fd_lookup(int fd)
{
	return handle_lookup(&fs_handle_db, fd);
}

void tee_fs_fail_recovery(struct tee_fs_fd *fdp)
{
	int res;

	res = tee_fs_common_close(fdp);
	if (!res)
		do_fail_recovery(fdp);
}

int tee_fs_get_file_length(struct tee_fs_fd *fdp, size_t *length)
{
	size_t file_len;
	int res;

	*length = 0;

	res = tee_fs_common_lseek(fdp, 0, TEE_FS_SEEK_END);
	if (res < 0)
		return res;
	file_len = res;

	res = tee_fs_common_lseek(fdp, 0, TEE_FS_SEEK_SET);
	if (res < 0)
		return res;

	*length = file_len;
	return 0;
}

int tee_fs_common_open(const char *file, int flags, ...)
{
	int res = -1;
	size_t len;
	bool is_new_file = false;
	struct tee_fs_fd *fdp = NULL;
	struct tee_fs_rpc head = { 0 };

	len = strlen(file) + 1;
	if (len > TEE_FS_NAME_MAX)
		goto exit;

	/* fill in parameters */
	head.op = TEE_FS_OPEN;
	head.flags = flags & ~TEE_FS_O_CREATE;
	head.fd = 0;

	/*
	 * try to open file without O_CREATE flag, if failed try again with
	 * O_CREATE flag (to distinguish whether it's a new file or not)
	 */
	res = tee_fs_send_cmd(&head, (void *)file, len, TEE_FS_MODE_IN);
	if (!res)
		res = head.res;
	if (res < 0) {
		if (!(flags & TEE_FS_O_CREATE))
			goto exit;

		head.flags |= TEE_FS_O_CREATE;
		res = tee_fs_send_cmd(&head, (void *)file, len, TEE_FS_MODE_IN);
		if (!res)
			res = head.res;
		if (res < 0)
			goto exit;
		is_new_file = true;
	}

	res = head.res;

	if (res == -1)
		goto exit;

	fdp = (struct tee_fs_fd *)malloc(sizeof(struct tee_fs_fd));
	if (!fdp)
		goto exit;

	/* init internal status */
	fdp->nw_fd = head.fd;
	fdp->flags = flags;
	fdp->is_new_file = is_new_file;
	fdp->private = NULL;
	fdp->filename = malloc(len);
	if (!fdp->filename) {
		res = -1;
		goto exit;
	}
	memcpy(fdp->filename, file, len);

	/* return fd */
	res = handle_get(&fs_handle_db, fdp);
	fdp->fd = res;

exit:
	if (res == -1)
		free(fdp);

	return res;
}

int tee_fs_common_close(struct tee_fs_fd *fdp)
{
	int res = -1;
	struct tee_fs_rpc head = { 0 };

	if (!fdp)
		return -1;

	handle_put(&fs_handle_db, fdp->fd);

	/* fill in parameters */
	head.op = TEE_FS_CLOSE;
	head.fd = fdp->nw_fd;

	res = tee_fs_send_cmd(&head, NULL, 0, TEE_FS_MODE_NONE);
	if (!res)
		res = head.res;

	if (res < 0) {
		EMSG("Failed to close file, start fail recovery");
		do_fail_recovery(fdp);
	}

	if (fdp->private)
		free(fdp->private);
	free(fdp->filename);
	free(fdp);

	return res;
}

tee_fs_off_t tee_fs_common_lseek(struct tee_fs_fd *fdp,
				tee_fs_off_t offset, int whence)
{
	tee_fs_off_t res = -1;
	struct tee_fs_rpc head = { 0 };

	if (!fdp)
		return -1;

	/* fill in parameters */
	head.op = TEE_FS_SEEK;
	head.fd = fdp->nw_fd;
	head.arg = offset;
	head.flags = whence;

	res = tee_fs_send_cmd(&head, NULL, 0, TEE_FS_MODE_NONE);
	if (!res)
		res = head.res;

	return res;
}

int tee_fs_common_ftruncate(struct tee_fs_fd *fdp, tee_fs_off_t length)
{
	int res = -1;
	struct tee_fs_rpc head = { 0 };

	if (!fdp)
		return -1;

	head.op = TEE_FS_TRUNC;
	head.fd = fdp->nw_fd;
	head.arg = length;

	res = tee_fs_send_cmd(&head, NULL, 0, TEE_FS_MODE_NONE);
	if (!res)
		res = head.res;

	return res;
}

int tee_fs_common_read(struct tee_fs_fd *fdp, void *buf, size_t len)
{
	int res = -1;
	struct tee_fs_rpc head = { 0 };

	if (!fdp)
		return -1;

	if (!len) {
		res = 0;
		goto exit;
	}

	if (!buf)
		goto exit;

	/* fill in parameters */
	head.op = TEE_FS_READ;
	head.fd = fdp->nw_fd;
	head.len = (uint32_t) len;

	res = tee_fs_send_cmd(&head, (void *)buf, len, TEE_FS_MODE_OUT);
	if (!res)
		res = head.res;
exit:
	return res;
}

int tee_fs_common_write(struct tee_fs_fd *fdp,
			const void *buf, size_t len)
{
	int res = -1;
	struct tee_fs_rpc head = { 0 };

	if (!fdp)
		return -1;

	if (!len) {
		res = 0;
		goto exit;
	}

	if (!buf)
		goto exit;

	/* fill in parameters */
	head.op = TEE_FS_WRITE;
	head.fd = fdp->nw_fd;
	head.len = len;

	res = tee_fs_send_cmd(&head, (void *)buf, len, TEE_FS_MODE_IN);
	if (!res)
		res = head.res;
exit:
	return res;
}

int tee_fs_common_rename(const char *old, const char *new)
{
	int res = -1;
	char *tmp = NULL;
	struct tee_fs_rpc head = { 0 };
	size_t len_old = strlen(old) + 1;
	size_t len_new = strlen(new) + 1;
	size_t len = len_old + len_new;

	if (len > TEE_FS_NAME_MAX)
		goto exit;

	tmp = malloc(len);
	if (!tmp)
		goto exit;
	memcpy(tmp, old, len_old);
	memcpy(tmp + len_old, new, len_new);

	head.op = TEE_FS_RENAME;

	res = tee_fs_send_cmd(&head, tmp, len, TEE_FS_MODE_IN);
	if (!res)
		res = head.res;

exit:
	free(tmp);
	return res;
}

int tee_fs_common_unlink(const char *file)
{
	int res = -1;
	struct tee_fs_rpc head = { 0 };
	size_t len = strlen(file) + 1;

	if (len > TEE_FS_NAME_MAX)
		goto exit;

	head.op = TEE_FS_UNLINK;

	res = tee_fs_send_cmd(&head, (void *)file, len, TEE_FS_MODE_IN);
	if (!res)
		res = head.res;

exit:
	return res;
}

int tee_fs_common_mkdir(const char *path, tee_fs_mode_t mode)
{
	int res = -1;
	struct tee_fs_rpc head = { 0 };
	uint32_t len;

	len = strlen(path) + 1;
	if (len > TEE_FS_NAME_MAX)
		goto exit;

	head.op = TEE_FS_MKDIR;
	head.flags = mode;

	res = tee_fs_send_cmd(&head, (void *)path, len, TEE_FS_MODE_IN);
	if (!res)
		res = head.res;

exit:
	return res;
}

tee_fs_dir *tee_fs_common_opendir(const char *name)
{
	struct tee_fs_rpc head = { 0 };
	uint32_t len;
	struct tee_fs_dir *dir = NULL;

	len = strlen(name) + 1;
	if (len > TEE_FS_NAME_MAX)
		goto exit;

	head.op = TEE_FS_OPENDIR;

	if (tee_fs_send_cmd(&head, (void *)name, len, TEE_FS_MODE_IN))
		goto exit;

	if (head.res < 0)
		goto exit;

	dir = malloc(sizeof(struct tee_fs_dir));
	if (!dir) {
		int nw_dir = head.res;

		memset(&head, 0, sizeof(head));
		head.op = TEE_FS_CLOSEDIR;
		head.arg = nw_dir;
		tee_fs_send_cmd(&head, NULL, 0, TEE_FS_MODE_NONE);
		goto exit;
	}

	dir->nw_dir = head.res;
	dir->d.d_name = NULL;

exit:
	return dir;
}

int tee_fs_common_closedir(tee_fs_dir *d)
{
	int res = -1;
	struct tee_fs_rpc head = { 0 };

	if (!d) {
		res = 0;
		goto exit;
	}

	head.op = TEE_FS_CLOSEDIR;
	head.arg = (int)d->nw_dir;

	res = tee_fs_send_cmd(&head, NULL, 0, TEE_FS_MODE_NONE);
	if (!res)
		res = head.res;

exit:
	if (d)
		free(d->d.d_name);
	free(d);

	return res;
}

struct tee_fs_dirent *tee_fs_common_readdir(tee_fs_dir *d)
{
	struct tee_fs_dirent *res = NULL;
	struct tee_fs_rpc head = { 0 };
	char fname[TEE_FS_NAME_MAX + 1];

	if (!d)
		goto exit;

	head.op = TEE_FS_READDIR;
	head.arg = (int)d->nw_dir;

	if (tee_fs_send_cmd(&head, fname, sizeof(fname), TEE_FS_MODE_OUT))
		goto exit;

	if (head.res < 0)
		goto exit;

	if (!head.len || head.len > sizeof(fname))
		goto exit;

	fname[head.len - 1] = '\0'; /* make sure it's zero terminated */
	free(d->d.d_name);
	d->d.d_name = strdup(fname);
	if (!d->d.d_name)
		goto exit;

	res = &d->d;
exit:
	return res;
}

int tee_fs_common_rmdir(const char *name)
{
	int res = -1;
	struct tee_fs_rpc head = { 0 };
	uint32_t len;

	len = strlen(name) + 1;
	if (len > TEE_FS_NAME_MAX)
		goto exit;

	head.op = TEE_FS_RMDIR;

	res = tee_fs_send_cmd(&head, (void *)name, len, TEE_FS_MODE_IN);
	if (!res)
		res = head.res;

exit:
	return res;
}

int tee_fs_common_access(const char *name, int mode)
{
	int res = -1;
	struct tee_fs_rpc head = { 0 };
	uint32_t len;

	len = strlen(name) + 1;
	if (len > TEE_FS_NAME_MAX)
		goto exit;

	head.op = TEE_FS_ACCESS;
	head.flags = mode;

	res = tee_fs_send_cmd(&head, (void *)name, len, TEE_FS_MODE_IN);
	if (!res)
		res = head.res;

exit:
	return res;
}
