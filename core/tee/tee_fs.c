/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
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
#include <kernel/tee_rpc.h>
#include <kernel/tee_rpc_types.h>
#include <mm/core_mmu.h>
#include "tee_api_defines.h"
#include <kernel/tee_common_unpg.h>
#include <trace.h>
#include <kernel/handle.h>

#include "tee_fs_private.h"

struct tee_fs_fd {
	int nw_fd;		/* normal world fd */
	uint32_t flags;
	uint32_t fp;		/* file pointer offset */
	uint32_t len;
};

static struct handle_db fs_handle_db = HANDLE_DB_INITIALIZER;

static int tee_fs_open(const char *file, int flags, ...)
{
	int res = -1;
	size_t len;
	struct tee_fs_fd *fd = NULL;
	struct tee_fs_rpc head = { 0 };

	len = strlen(file) + 1;
	if (len > TEE_FS_NAME_MAX)
		goto exit;

	/* fill in parameters */
	head.op = TEE_FS_OPEN;
	head.flags = flags;
	head.fd = 0;

	res = tee_fs_send_cmd(&head, (void *)file, len, TEE_FS_MODE_IN);
	if (res)
		goto exit;

	res = head.res;

	if (res == -1)
		goto exit;

	fd = (struct tee_fs_fd *)malloc(sizeof(struct tee_fs_fd));
	if (fd == NULL)
		goto exit;

	/* init internal status */
	fd->nw_fd = head.fd;
	fd->flags = flags;

	/* return fd */
	res = handle_get(&fs_handle_db, fd);

exit:
	if (res == -1)
		free(fd);

	return res;
}

static int tee_fs_close(int fd)
{
	int res = -1;
	struct tee_fs_fd *fdp = handle_put(&fs_handle_db, fd);
	struct tee_fs_rpc head = { 0 };

	if (fdp == NULL)
		return -1;

	/* fill in parameters */
	head.op = TEE_FS_CLOSE;
	head.fd = fdp->nw_fd;

	res = tee_fs_send_cmd(&head, NULL, 0, TEE_FS_MODE_NONE);
	if (res)
		goto exit;

	res = head.res;

exit:
	free(fdp);

	return res;
}

static int tee_fs_read(int fd, void *buf, size_t len)
{
	struct tee_fs_fd *fdp = handle_lookup(&fs_handle_db, fd);

	if (!fdp)
		return -1;

	return tee_fs_common_read(fdp->nw_fd, buf, len);
}

static int tee_fs_write(int fd, const void *buf, size_t len)
{
	struct tee_fs_fd *fdp = handle_lookup(&fs_handle_db, fd);

	if (!fdp)
		return -1;

	return tee_fs_common_write(fdp->nw_fd, buf, len);
}

static tee_fs_off_t tee_fs_lseek(int fd, tee_fs_off_t offset, int whence)
{
	struct tee_fs_fd *fdp = handle_lookup(&fs_handle_db, fd);

	if (!fdp)
		return -1;

	return tee_fs_common_lseek(fdp->nw_fd, offset, whence);
}

static int tee_fs_ftruncate(int fd, tee_fs_off_t length)
{
	struct tee_fs_fd *fdp = handle_lookup(&fs_handle_db, fd);

	if (!fdp)
		return -1;

	return tee_fs_common_ftruncate(fdp->nw_fd, length);
}

struct tee_file_operations tee_file_ops = {
	.open = tee_fs_open,
	.close = tee_fs_close,
	.read = tee_fs_read,
	.write = tee_fs_write,
	.lseek = tee_fs_lseek,
	.ftruncate = tee_fs_ftruncate,
	.rename = tee_fs_common_rename,
	.unlink = tee_fs_common_unlink,
	.mkdir = tee_fs_common_mkdir,
	.opendir = tee_fs_common_opendir,
	.closedir = tee_fs_common_closedir,
	.readdir = tee_fs_common_readdir,
	.rmdir = tee_fs_common_rmdir,
	.access = tee_fs_common_access
};
