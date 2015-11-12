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

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string_ext.h>
#include <tee/tee_fs_defs.h>
#include <tee/tee_cryp_provider.h>
#include <kernel/tee_common_unpg.h>
#include <kernel/handle.h>
#include <kernel/mutex.h>
#include <trace.h>

#include "ree_fs_intf.h"

static int ree_fs_open(const char *file, int flags, ...)
{
	int res = -1;
	struct tee_fs_rpc head = { 0 };
	size_t len;

	len = strlen(file) + 1;
	if (len > REE_FS_NAME_MAX)
		goto exit;

	/* fill in parameters */
	head.op = TEE_FS_OPEN;
	head.flags = flags;
	head.fd = 0;

	res = tee_fs_send_cmd(&head, (void *)file, len, TEE_FS_MODE_IN);
	if (!res)
		res = head.res;

exit:
	return res;
}

static int ree_fs_read(int fd, void *buf, size_t len)
{
	int res = -1;
	struct tee_fs_rpc head = { 0 };

	if (!len) {
		res = 0;
		goto exit;
	}

	if (!buf)
		goto exit;

	/* fill in parameters */
	head.op = TEE_FS_READ;
	head.fd = fd;
	head.len = (uint32_t) len;

	res = tee_fs_send_cmd(&head, (void *)buf, len, TEE_FS_MODE_OUT);
	if (!res)
		res = head.res;
exit:
	return res;
}

static int ree_fs_write(int fd, const void *buf, size_t len)
{
	int res = -1;
	struct tee_fs_rpc head = { 0 };

	if (!len) {
		res = 0;
		goto exit;
	}

	if (!buf)
		goto exit;

	/* fill in parameters */
	head.op = TEE_FS_WRITE;
	head.fd = fd;
	head.len = (uint32_t) len;

	res = tee_fs_send_cmd(&head, (void *)buf, len, TEE_FS_MODE_IN);
	if (!res)
		res = head.res;
exit:
	return res;
}

static int ree_fs_ftruncate(int fd, tee_fs_off_t length)
{
	int res = -1;
	struct tee_fs_rpc head = { 0 };

	head.op = TEE_FS_TRUNC;
	head.fd = fd;
	head.arg = length;

	res = tee_fs_send_cmd(&head, NULL, 0, TEE_FS_MODE_NONE);
	if (!res)
		res = head.res;

	return res;
}

static int ree_fs_close(int fd)
{
	int res = -1;
	struct tee_fs_rpc head = { 0 };

	/* fill in parameters */
	head.op = TEE_FS_CLOSE;
	head.fd = fd;

	res = tee_fs_send_cmd(&head, NULL, 0, TEE_FS_MODE_NONE);
	if (!res)
		res = head.res;

	return res;
}

static int ree_fs_rename(const char *old, const char *new)
{
	int res = -1;
	char *tmp = NULL;
	struct tee_fs_rpc head = { 0 };
	uint32_t len_old = strlen(old) + 1;
	uint32_t len_new = strlen(new) + 1;
	uint32_t len = len_old + len_new;

	if (len_old > REE_FS_NAME_MAX || len_new > REE_FS_NAME_MAX)
		goto exit;

	tmp = malloc(len);
	if (!tmp)
		goto exit;

	memcpy(tmp, old, len_old);
	memcpy(tmp + len_old, new, len_new);

	head.op = TEE_FS_RENAME;

	res = tee_fs_send_cmd(&head, tmp, len, TEE_FS_MODE_IN);
	if (res)
		goto exit;

	res = head.res;

exit:
	free(tmp);
	return res;
}

static tee_fs_off_t ree_fs_lseek(int fd, tee_fs_off_t offset, int whence)
{
	tee_fs_off_t res = -1;
	struct tee_fs_rpc head = { 0 };

	/* fill in parameters */
	head.op = TEE_FS_SEEK;
	head.fd = fd;
	head.arg = offset;
	head.flags = whence;

	res = tee_fs_send_cmd(&head, NULL, 0, TEE_FS_MODE_NONE);
	if (!res)
		res = head.res;

	return res;
}

static int ree_fs_link(const char *old, const char *new)
{
	int res = -1;
	char *tmp = NULL;
	struct tee_fs_rpc head = { 0 };
	size_t len_old = strlen(old) + 1;
	size_t len_new = strlen(new) + 1;
	size_t len = len_old + len_new;

	if (len_old > REE_FS_NAME_MAX || len_new > REE_FS_NAME_MAX)
		goto exit;

	tmp = malloc(len);
	if (!tmp)
		goto exit;
	memcpy(tmp, old, len_old);
	memcpy(tmp + len_old, new, len_new);

	head.op = TEE_FS_LINK;

	res = tee_fs_send_cmd(&head, tmp, len, TEE_FS_MODE_IN);
	if (!res)
		res = head.res;

exit:
	free(tmp);
	return res;
}

static int ree_fs_unlink(const char *file)
{
	int res = -1;
	struct tee_fs_rpc head = { 0 };
	size_t len = strlen(file) + 1;

	if (len > REE_FS_NAME_MAX)
		goto exit;

	head.op = TEE_FS_UNLINK;

	res = tee_fs_send_cmd(&head, (void *)file, len, TEE_FS_MODE_IN);
	if (!res)
		res = head.res;
exit:
	return res;
}

static int ree_fs_mkdir(const char *path, tee_fs_mode_t mode)
{
	int res = -1;
	struct tee_fs_rpc head = { 0 };
	uint32_t len;

	if (!path)
		return -1;

	len = strlen(path) + 1;
	if (len > REE_FS_NAME_MAX)
		goto exit;

	head.op = TEE_FS_MKDIR;
	head.flags = mode;

	res = tee_fs_send_cmd(&head, (void *)path, len, TEE_FS_MODE_IN);
	if (!res)
		res = head.res;

exit:
	return res;
}

static tee_fs_dir *ree_fs_opendir(const char *name)
{
	struct tee_fs_rpc head = { 0 };
	uint32_t len;
	struct tee_fs_dir *dir = NULL;

	if (!name)
		goto exit;

	len = strlen(name) + 1;
	if (len > REE_FS_NAME_MAX)
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

static int ree_fs_closedir(tee_fs_dir *d)
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

static struct tee_fs_dirent *ree_fs_readdir(tee_fs_dir *d)
{
	struct tee_fs_dirent *res = NULL;
	struct tee_fs_rpc head = { 0 };
	char fname[REE_FS_NAME_MAX + 1];

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

static int ree_fs_rmdir(const char *name)
{
	int res = -1;
	struct tee_fs_rpc head = { 0 };
	uint32_t len;

	len = strlen(name) + 1;
	if (len > REE_FS_NAME_MAX)
		goto exit;

	head.op = TEE_FS_RMDIR;

	res = tee_fs_send_cmd(&head, (void *)name, len, TEE_FS_MODE_IN);
	if (!res)
		res = head.res;

exit:
	return res;
}

static int ree_fs_access(const char *name, int mode)
{
	int res = -1;
	struct tee_fs_rpc head = { 0 };
	uint32_t len;

	if (!name)
		goto exit;

	len = strlen(name) + 1;
	if (len > REE_FS_NAME_MAX)
		goto exit;

	head.op = TEE_FS_ACCESS;
	head.flags = mode;

	res = tee_fs_send_cmd(&head, (void *)name, len, TEE_FS_MODE_IN);
	if (!res)
		res = head.res;

exit:
	return res;
}

static int ree_fs_get_file_length(int fd, uint32_t *length)
{
	uint32_t file_len;
	int res;

	TEE_ASSERT(length);

	*length = 0;

	res = ree_fs_lseek(fd, 0, TEE_FS_SEEK_END);
	if (res < 0)
		return res;

	file_len = res;

	res = ree_fs_lseek(fd, 0, TEE_FS_SEEK_SET);
	if (res < 0)
		return res;

	*length = file_len;
	return 0;
}

/* read_ree_file: Allocate buffer and read file.
 *
 * Note: please remember to free buffer when buffer is not needed.
 */
TEE_Result read_ree_file(const char *ree_path,
		uint8_t **out, uint32_t *out_size)
{
	TEE_Result tee_res = TEE_SUCCESS;
	int res;
	int fd;
	uint32_t file_size;
	uint8_t *buf = NULL;

	fd = ree_file_ops.open(ree_path, TEE_FS_O_RDWR);
	if (fd < 0) {
		EMSG("Failed to open REE file, file=%s", ree_path);
		tee_res = TEE_ERROR_CORRUPT_OBJECT;
		goto exit;
	}

	res = ree_file_ops.get_file_length(fd, &file_size);
	if (res < 0) {
		EMSG("Failed to get file size, file=%s", ree_path);
		tee_res = TEE_ERROR_CORRUPT_OBJECT;
		goto exit;
	}

	buf = malloc(file_size);
	if (!buf) {
		EMSG("Failed to allocate buffer");
		tee_res = TEE_ERROR_OUT_OF_MEMORY;
		goto exit;
	}

	res = ree_file_ops.read(fd, buf, file_size);
	if (res != (int)file_size) {
		EMSG("return bytes(%d) != file_size(%u)",
				res, file_size);
		tee_res = TEE_ERROR_CORRUPT_OBJECT;
	}

	ree_file_ops.close(fd);

exit:
	if (tee_res != TEE_SUCCESS) {
		free(buf);
		buf = NULL;
	}

	*out = buf;
	*out_size = file_size;

	return tee_res;
}

TEE_Result write_ree_file(char *ree_path,
		uint8_t *in, uint32_t in_size)
{
	TEE_Result tee_res = TEE_SUCCESS;
	int bytes;
	int fd = -1;

	fd = ree_file_ops.open(ree_path, TEE_FS_O_CREATE |
			TEE_FS_O_TRUNC | TEE_FS_O_WRONLY);
	if (fd < 0) {
		tee_res = TEE_ERROR_CORRUPT_OBJECT;
		goto exit;
	}

	bytes = ree_file_ops.write(fd, in, in_size);
	if (bytes != (int)in_size) {
		EMSG("return bytes(%d) != in size(%u)",
				bytes, in_size);
		tee_res = TEE_ERROR_CORRUPT_OBJECT;
	}

	ree_file_ops.close(fd);

exit:
	return tee_res;
}

struct ree_file_operations ree_file_ops = {
	.open = ree_fs_open,
	.read = ree_fs_read,
	.write = ree_fs_write,
	.ftruncate = ree_fs_ftruncate,
	.close = ree_fs_close,
	.rename = ree_fs_rename,
	.lseek = ree_fs_lseek,
	.link = ree_fs_link,
	.unlink = ree_fs_unlink,
	.mkdir = ree_fs_mkdir,
	.opendir = ree_fs_opendir,
	.closedir = ree_fs_closedir,
	.readdir = ree_fs_readdir,
	.rmdir = ree_fs_rmdir,
	.access =  ree_fs_access,
	.get_file_length = ree_fs_get_file_length
};
