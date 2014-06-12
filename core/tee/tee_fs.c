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

#include <tee/tee_fs.h>
#include <tee/tee_fs_defs.h>

#include <kernel/tee_rpc.h>
#include <kernel/tee_rpc_types.h>
#include <kernel/thread.h>
#include <sm/teesmc.h>
#include <mm/core_mmu.h>

#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>


#include "tee_api_defines.h"
#include <kernel/tee_common_unpg.h>

/* TEE FS operation */
#define TEE_FS_OPEN       1
#define TEE_FS_CLOSE      2
#define TEE_FS_READ       3
#define TEE_FS_WRITE      4
#define TEE_FS_SEEK       5
#define TEE_FS_UNLINK     6
#define TEE_FS_RENAME     7
#define TEE_FS_TRUNC      8
#define TEE_FS_MKDIR      9
#define TEE_FS_OPENDIR   10
#define TEE_FS_CLOSEDIR  11
#define TEE_FS_READDIR   12
#define TEE_FS_RMDIR     13
#define TEE_FS_ACCESS    14

#define TEE_FS_MODE_NONE 0
#define TEE_FS_MODE_IN   1
#define TEE_FS_MODE_OUT  2

struct tee_fs_rpc {
	int op;
	int flags;
	int arg;
	int fd;
	uint32_t len;
	int res;
};

struct tee_fs_fd {
	int nw_fd;		/* normal world fd */
	uint32_t flags;
	uint32_t fp;		/* file pointer offset */
	uint32_t len;
};

struct tee_fs_dir {
	uint32_t nw_dir;
	struct tee_fs_dirent d;
};

/*
 * File descriptors are generated based on virtual address
 * of the effective descriptors in RAM. As all descriptor structures
 * are allocated from teecore "malloc" support, descriptor IDs
 * are generated as the offset from malloc pool start address to
 * the effective descriptor structure in RAM.
 * Could use another way. this one is quick and reliable.
 */

/* Get file descriptor from tee_fs_fd pointer */
#define TEE_FS_GET_FD(_x) ((uint32_t)(_x) - TEE_HEAP_START0)
/* Get tee_fs_fd pointer from file descriptor */
#define TEE_FS_GET_FDP(_x) ((void *)((uint32_t)(_x) + TEE_HEAP_START0))

static int tee_fs_send_cmd(struct tee_fs_rpc *bf_cmd, void *data, uint32_t len,
			   uint32_t mode)
{
	struct teesmc32_arg *arg;
	struct teesmc32_param *params;
	const size_t num_params = 1;
	paddr_t pharg = 0;
	paddr_t phpayload = 0;
	paddr_t cookie = 0;
	struct tee_fs_rpc *bf;
	int res = -1;

	pharg = thread_rpc_alloc_arg(TEESMC32_GET_ARG_SIZE(num_params));
	thread_st_rpc_alloc_payload(sizeof(struct tee_fs_rpc) + len,
					        &phpayload, &cookie);
	if (!pharg || !phpayload)
		goto exit;

	if (!TEE_ALIGNMENT_IS_OK(pharg, struct teesmc32_arg) ||
	    !TEE_ALIGNMENT_IS_OK(phpayload, struct tee_fs_rpc))
		goto exit;

	if (core_pa2va(pharg, (uint32_t *)&arg) ||
	    core_pa2va(phpayload, (uint32_t *)&bf))
		goto exit;

	arg->cmd = TEE_RPC_FS;
	arg->ret = TEE_ERROR_GENERIC;
	arg->num_params = num_params;
	params = TEESMC32_GET_PARAMS(arg);
	params[0].attr = TEESMC_ATTR_TYPE_MEMREF_INOUT |
			 (TEESMC_ATTR_CACHE_I_WRITE_THR |
			  TEESMC_ATTR_CACHE_O_WRITE_THR) <<
				TEESMC_ATTR_CACHE_SHIFT;

	params[0].u.memref.buf_ptr = phpayload;
	params[0].u.memref.size = sizeof(struct tee_fs_rpc) + len;

	/* fill in parameters */
	*bf = *bf_cmd;

	if (mode & TEE_FS_MODE_IN)
		memcpy((void *)(bf + 1), data, len);

	thread_rpc_cmd(pharg);
	/* update result */
	*bf_cmd = *bf;
	if (arg->ret != TEE_SUCCESS)
		goto exit;

	if (mode & TEE_FS_MODE_OUT) {
		uint32_t olen = MIN(len, bf->len);

		memcpy(data, (void *)(bf + 1), olen);
	}

	res = 0;

exit:
	thread_rpc_free_arg(pharg);
	thread_st_rpc_free_payload(cookie);
	return res;
}

int tee_fs_open(const char *file, int flags, ...)
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
	res = TEE_FS_GET_FD(fd);

exit:
	if (res == -1)
		free(fd);

	return res;
}

int tee_fs_close(int fd)
{
	int res = -1;
	struct tee_fs_fd *fdp = TEE_FS_GET_FDP(fd);
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

int tee_fs_read(int fd, void *buf, size_t len)
{
	int res = -1;
	struct tee_fs_fd *fdp = TEE_FS_GET_FDP(fd);
	struct tee_fs_rpc head = { 0 };

	if (len == 0) {
		res = 0;
		goto exit;
	}

	if (fdp == NULL || buf == NULL) {
		res = -1;
		goto exit;
	}

	/* fill in parameters */
	head.op = TEE_FS_READ;
	head.fd = fdp->nw_fd;
	head.len = (uint32_t) len;

	res = tee_fs_send_cmd(&head, (void *)buf, len, TEE_FS_MODE_OUT);
	if (res)
		goto exit;

	res = head.res;

exit:
	return res;
}

int tee_fs_write(int fd, const void *buf, size_t len)
{
	int res = -1;
	struct tee_fs_fd *fdp = TEE_FS_GET_FDP(fd);
	struct tee_fs_rpc head = { 0 };

	if (len == 0) {
		res = 0;
		goto exit;
	}

	if (buf == NULL) {
		res = -1;
		goto exit;
	}

	if (fdp == NULL) {
		res = -1;
		goto exit;
	}

	/* fill in parameters */
	head.op = TEE_FS_WRITE;
	head.fd = fdp->nw_fd;
	head.len = len;

	res = tee_fs_send_cmd(&head, (void *)buf, len, TEE_FS_MODE_IN);
	if (res)
		goto exit;

	res = head.res;

exit:
	return res;
}

tee_fs_off_t tee_fs_lseek(int fd, tee_fs_off_t offset, int whence)
{
	tee_fs_off_t res = -1;
	struct tee_fs_fd *fdp = TEE_FS_GET_FDP(fd);
	struct tee_fs_rpc head = { 0 };

	/* fill in parameters */
	head.op = TEE_FS_SEEK;
	head.fd = fdp->nw_fd;
	head.arg = offset;
	head.flags = whence;

	res = tee_fs_send_cmd(&head, NULL, 0, TEE_FS_MODE_NONE);
	if (res)
		goto exit;

	res = head.res;

exit:
	return res;
}

int tee_fs_rename(const char *old, const char *new)
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
	if (res)
		goto exit;

	res = head.res;

exit:
	free(tmp);
	return res;
}

int tee_fs_unlink(const char *file)
{
	int res = -1;
	struct tee_fs_rpc head = { 0 };

	size_t len = strlen(file) + 1;
	if (len > TEE_FS_NAME_MAX)
		goto exit;

	head.op = TEE_FS_UNLINK;

	res = tee_fs_send_cmd(&head, (void *)file, len, TEE_FS_MODE_IN);
	if (res)
		goto exit;

	res = head.res;

exit:
	return res;
}

int tee_fs_ftruncate(int fd, tee_fs_off_t length)
{
	int res = -1;
	struct tee_fs_fd *fdp = TEE_FS_GET_FDP(fd);
	struct tee_fs_rpc head = { 0 };

	if (fdp == NULL)
		goto exit;

	head.op = TEE_FS_TRUNC;
	head.fd = fdp->nw_fd;
	head.arg = length;

	res = tee_fs_send_cmd(&head, NULL, 0, TEE_FS_MODE_NONE);
	if (res)
		goto exit;

	res = head.res;

exit:
	return res;
}

int tee_fs_mkdir(const char *path, tee_fs_mode_t mode)
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
	if (res)
		goto exit;

	res = head.res;

exit:
	return res;
}

tee_fs_dir *tee_fs_opendir(const char *name)
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

	if (head.res == 0)
		goto exit;

	dir = malloc(sizeof(struct tee_fs_dir));
	if (dir == NULL)
		goto exit;

	dir->nw_dir = head.res;
	dir->d.d_name = NULL;

exit:
	return dir;
}

int tee_fs_closedir(tee_fs_dir *d)
{
	int res = -1;
	struct tee_fs_rpc head = { 0 };

	if (d == NULL) {
		res = 0;
		goto exit;
	}

	head.op = TEE_FS_CLOSEDIR;
	head.arg = (int)d->nw_dir;

	res = tee_fs_send_cmd(&head, NULL, 0, TEE_FS_MODE_NONE);
	if (res)
		goto exit;

	res = head.res;

exit:
	if (d)
		free(d->d.d_name);
	free(d);

	return res;
}

struct tee_fs_dirent *tee_fs_readdir(tee_fs_dir *d)
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

	if (!head.res) {
		free(d->d.d_name);
		d->d.d_name = NULL;
		goto exit;
	}

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

int tee_fs_rmdir(const char *name)
{
	int res = -1;
	struct tee_fs_rpc head = { 0 };
	uint32_t len;

	len = strlen(name) + 1;
	if (len > TEE_FS_NAME_MAX)
		goto exit;

	head.op = TEE_FS_RMDIR;

	res = tee_fs_send_cmd(&head, (void *)name, len, TEE_FS_MODE_IN);
	if (res)
		goto exit;

	res = head.res;

exit:
	return res;
}

int tee_fs_access(const char *name, int mode)
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
	if (res)
		goto exit;

	res = head.res;

exit:
	return res;
}
