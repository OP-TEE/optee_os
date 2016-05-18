/*
 * Copyright (c) 2016, Linaro Limited
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
#include <kernel/thread.h>
#include <mm/core_memprot.h>
#include <stdlib.h>
#include <string.h>
#include <tee/tee_fs.h>
#include <tee/tee_fs_rpc.h>
#include <trace.h>
#include <util.h>

#define RPC_FAILED -1

struct tee_fs_dir {
	int nw_dir;
	struct tee_fs_dirent d;
};

static TEE_Result tee_fs_rpc_send_cmd(int cmd_id, struct tee_fs_rpc *bf_cmd,
				      void *data, uint32_t len, uint32_t mode)
{
	TEE_Result ret;
	struct optee_msg_param params;
	paddr_t phpayload = 0;
	uint64_t cpayload = 0;
	struct tee_fs_rpc *bf;
	int res = TEE_ERROR_GENERIC;

	assert(cmd_id == OPTEE_MSG_RPC_CMD_FS ||
	       cmd_id == OPTEE_MSG_RPC_CMD_SQL_FS);

	thread_rpc_alloc_payload(sizeof(struct tee_fs_rpc) + len,
				 &phpayload, &cpayload);
	if (!phpayload)
		return TEE_ERROR_OUT_OF_MEMORY;

	if (!ALIGNMENT_IS_OK(phpayload, struct tee_fs_rpc))
		goto exit;

	bf = phys_to_virt(phpayload, MEM_AREA_NSEC_SHM);
	if (!bf)
		goto exit;

	memset(&params, 0, sizeof(params));
	params.attr = OPTEE_MSG_ATTR_TYPE_TMEM_INOUT;
	params.u.tmem.buf_ptr = phpayload;
	params.u.tmem.size = sizeof(struct tee_fs_rpc) + len;
	params.u.tmem.shm_ref = cpayload;

	/* fill in parameters */
	*bf = *bf_cmd;

	if (mode & TEE_FS_MODE_IN)
		memcpy((void *)(bf + 1), data, len);

	ret = thread_rpc_cmd(cmd_id, 1, &params);
	/* update result */
	*bf_cmd = *bf;
	if (ret != TEE_SUCCESS)
		goto exit;

	if (mode & TEE_FS_MODE_OUT) {
		uint32_t olen = MIN(len, bf->len);

		memcpy(data, (void *)(bf + 1), olen);
	}

	res = TEE_SUCCESS;

exit:
	thread_rpc_free_payload(cpayload);
	return res;
}

int tee_fs_rpc_access(int id, const char *name, int mode)
{
	struct tee_fs_rpc head = { 0 };
	TEE_Result res;
	int rc = RPC_FAILED;
	size_t len;

	DMSG("(id: %d, name: %s, mode: %d)...", id, name, mode);

	if (!name)
		goto exit;

	len = strlen(name) + 1;
	if (len <= 1)
		goto exit;

	head.op = TEE_FS_ACCESS;
	head.flags = mode;

	res = tee_fs_rpc_send_cmd(id, &head, (void *)name, len, TEE_FS_MODE_IN);
	if (res != TEE_SUCCESS)
		goto exit;

	rc = head.res;
exit:
	DMSG("...%d", rc);
	return rc;
}

int tee_fs_rpc_begin_transaction(int id)
{
	struct tee_fs_rpc head = { 0 };
	TEE_Result res;
	int rc = RPC_FAILED;

	assert(id == OPTEE_MSG_RPC_CMD_SQL_FS);

	DMSG("(id: %d)...", id);

	/* fill in parameters */
	head.op = TEE_FS_BEGIN;
	head.fd = -1;

	res = tee_fs_rpc_send_cmd(id, &head, NULL, 0,
				  TEE_FS_MODE_NONE);
	if (res != TEE_SUCCESS)
		goto exit;

	rc = head.res;
exit:
	DMSG("...%d", rc);
	return rc;
}

int tee_fs_rpc_close(int id, int fd)
{
	struct tee_fs_rpc head = { 0 };
	TEE_Result res;
	int rc = RPC_FAILED;

	DMSG("(id: %d, fd: %d)...", id, fd);

	head.op = TEE_FS_CLOSE;
	head.fd = fd;

	res = tee_fs_rpc_send_cmd(id, &head, NULL, 0, TEE_FS_MODE_NONE);
	if (res != TEE_SUCCESS)
		goto exit;

	rc = head.res;
exit:
	DMSG("...%d", rc);
	return rc;
}

int tee_fs_rpc_end_transaction(int id, bool rollback)
{
	struct tee_fs_rpc head = { 0 };
	TEE_Result res;
	int rc = RPC_FAILED;

	assert(id == OPTEE_MSG_RPC_CMD_SQL_FS);

	DMSG("(id: %d, rollback: %d)...", id, rollback);

	head.op = TEE_FS_END;
	head.arg = rollback;
	head.fd = -1;

	res = tee_fs_rpc_send_cmd(id, &head, NULL, 0, TEE_FS_MODE_NONE);
	if (res != TEE_SUCCESS)
		goto exit;

	rc = head.res;
exit:
	DMSG("...%d", rc);
	return rc;
}

int tee_fs_rpc_ftruncate(int id, int fd, tee_fs_off_t length)
{
	struct tee_fs_rpc head = { 0 };
	TEE_Result res;
	int rc = RPC_FAILED;

	DMSG("(id: %d, fd: %d, length: %" PRId64 ")...", id, fd, length);

	head.op = TEE_FS_TRUNC;
	head.fd = fd;
	head.arg = length;

	res = tee_fs_rpc_send_cmd(id, &head, NULL, 0, TEE_FS_MODE_NONE);
	if (res != TEE_SUCCESS)
		goto exit;

	rc = head.res;
exit:
	DMSG("...%d", rc);
	return rc;
}

int tee_fs_rpc_link(int id, const char *old, const char *nw)
{
	size_t len_old;
	size_t len_new;
	size_t len;
	struct tee_fs_rpc head = { 0 };
	char *tmp = NULL;
	TEE_Result res;
	int rc = RPC_FAILED;

	DMSG("(id: %d, old: %s, nw: %s)...", id, old, nw);

	if (!old || !nw)
		goto exit;

	len_old = strlen(old) + 1;
	len_new = strlen(nw) + 1;
	len = len_old + len_new;

	tmp = malloc(len);
	if (!tmp)
		goto exit;
	memcpy(tmp, old, len_old);
	memcpy(tmp + len_old, nw, len_new);

	head.op = TEE_FS_LINK;

	res = tee_fs_rpc_send_cmd(id, &head, tmp, len, TEE_FS_MODE_IN);
	if (res != TEE_SUCCESS)
		goto exit;

	rc = head.res;
exit:
	free(tmp);
	DMSG("...%d", rc);
	return rc;
}

tee_fs_off_t tee_fs_rpc_lseek(int id, int fd, tee_fs_off_t offset,
				  int whence)
{
	struct tee_fs_rpc head = { 0 };
	tee_fs_off_t rc = RPC_FAILED;
	TEE_Result res;

	DMSG("(id: %d, fd: %d, offset: %" PRId64 ", whence: %d)...", id, fd,
	     offset, whence);

	head.op = TEE_FS_SEEK;
	head.fd = fd;
	head.arg = offset;
	head.flags = whence;

	res = tee_fs_rpc_send_cmd(id, &head, NULL, 0, TEE_FS_MODE_NONE);
	if (res != TEE_SUCCESS)
		goto exit;

	rc = head.res;
exit:
	DMSG("...%" PRId64, rc);
	return rc;
}

int tee_fs_rpc_mkdir(int id, const char *path, tee_fs_mode_t mode)
{
	struct tee_fs_rpc head = { 0 };
	TEE_Result res;
	uint32_t len;
	int rc = RPC_FAILED;

	DMSG("(id: %d, path: %s, mode: %d)...", id, path, mode);

	if (!path)
		goto exit;

	len = strlen(path) + 1;
	if (len <= 1)
		goto exit;

	head.op = TEE_FS_MKDIR;
	head.flags = mode;

	res = tee_fs_rpc_send_cmd(id, &head, (void *)path, len,
				  TEE_FS_MODE_IN);
	if (res != TEE_SUCCESS)
		goto exit;

	rc = head.res;
exit:
	DMSG("...%d", rc);
	return rc;
}

int tee_fs_rpc_open(int id, const char *file, int flags)
{
	struct tee_fs_rpc head = { 0 };
	TEE_Result res;
	int rc = RPC_FAILED;
	size_t len;

	DMSG("(id: %d, file: %s, flags: %d)...", id, file, flags);

	if (!file)
		goto exit;

	len = strlen(file) + 1;
	if (len <= 1)
		goto exit;

	head.op = TEE_FS_OPEN;
	head.flags = flags;

	res = tee_fs_rpc_send_cmd(id, &head, (void *)file, len,
				  TEE_FS_MODE_IN);
	if (res != TEE_SUCCESS)
		goto exit;

	rc = head.res;
exit:
	DMSG("...%d", rc);
	return rc;
}

struct tee_fs_dir *tee_fs_rpc_opendir(int id, const char *name)
{
	struct tee_fs_rpc head = { 0 };
	struct tee_fs_dir *dir = NULL;
	size_t len;
	TEE_Result res = TEE_SUCCESS;

	DMSG("(id: %d, name: %s)...", id, name);

	if (!name)
		goto exit;

	len = strlen(name) + 1;
	if (len <= 1)
		goto exit;

	dir = malloc(sizeof(struct tee_fs_dir));
	if (!dir)
		goto exit;

	head.op = TEE_FS_OPENDIR;

	res = tee_fs_rpc_send_cmd(id, &head, (void *)name, len,
				  TEE_FS_MODE_IN);
	if (res != TEE_SUCCESS)
		goto free_and_exit;
	if (head.res < 0)
		goto free_and_exit;

	dir->nw_dir = head.res;
	dir->d.d_name = NULL;

	goto exit;

free_and_exit:
	free(dir);
	dir = NULL;
exit:
	DMSG("...%p", (void *)dir);
	return dir;
}

int tee_fs_rpc_read(int id, int fd, void *buf, size_t len)
{
	struct tee_fs_rpc head = { 0 };
	TEE_Result res;
	int rc = RPC_FAILED;

	DMSG("(id: %d, fd: %d, buf: %p, len: %zu)...", id, fd, (void *)buf,
	     len);

	if (!len) {
		res = 0;
		goto exit;
	}

	if (!buf)
		goto exit;

	head.op = TEE_FS_READ;
	head.fd = fd;
	head.len = (uint32_t)len;

	res = tee_fs_rpc_send_cmd(id, &head, (void *)buf, len,
				  TEE_FS_MODE_OUT);
	if (res != TEE_SUCCESS)
		goto exit;

	rc = head.res;
exit:
	DMSG("...%d", rc);
	return rc;
}

struct tee_fs_dirent *tee_fs_rpc_readdir(int id, struct tee_fs_dir *d)
{
	struct tee_fs_dirent *rc = NULL;
	char fname[TEE_FS_NAME_MAX + 1];
	struct tee_fs_rpc head = { 0 };
	TEE_Result res;

	DMSG("(id: %d, d: %p)...", id, (void *)d);

	if (!d)
		goto exit;

	head.op = TEE_FS_READDIR;
	head.arg = (int)d->nw_dir;
	head.len = sizeof(fname);

	res = tee_fs_rpc_send_cmd(id, &head, fname, sizeof(fname),
				  TEE_FS_MODE_OUT);
	if (res != TEE_SUCCESS)
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

	rc = &d->d;
exit:
	DMSG("...%p", (void *)rc);
	return rc;
}

int tee_fs_rpc_rename(int id, const char *old, const char *nw)
{
	size_t len_old;
	size_t len_new;
	size_t len;
	struct tee_fs_rpc head = { 0 };
	char *tmp = NULL;
	TEE_Result res;
	int rc = RPC_FAILED;

	DMSG("(id: %d, old: %s, nw: %s)...", id, old, nw);

	if (!old || !nw)
		goto exit;

	len_old = strlen(old) + 1;
	len_new = strlen(nw) + 1;
	len = len_old + len_new;

	tmp = malloc(len);
	if (!tmp)
		goto exit;

	memcpy(tmp, old, len_old);
	memcpy(tmp + len_old, nw, len_new);

	head.op = TEE_FS_RENAME;

	res = tee_fs_rpc_send_cmd(id, &head, tmp, len, TEE_FS_MODE_IN);
	if (res != TEE_SUCCESS)
		goto exit;

	rc = head.res;
exit:
	free(tmp);
	DMSG("...%d", rc);
	return rc;
}

int tee_fs_rpc_write(int id, int fd, const void *buf, size_t len)
{
	struct tee_fs_rpc head = { 0 };
	TEE_Result res;
	int rc = RPC_FAILED;

	DMSG("(id: %d, fd: %d, buf: %p, len: %zu)...", id, fd, buf, len);

	if (!len) {
		res = 0;
		goto exit;
	}

	if (!buf)
		goto exit;

	head.op = TEE_FS_WRITE;
	head.fd = fd;
	head.len = (uint32_t)len;

	res = tee_fs_rpc_send_cmd(id, &head, (void *)buf, len, TEE_FS_MODE_IN);
	if (res != TEE_SUCCESS)
		goto exit;

	rc = head.res;
exit:
	DMSG("...%d", rc);
	return rc;
}

int tee_fs_rpc_closedir(int id, struct tee_fs_dir *d)
{
	struct tee_fs_rpc head = { 0 };
	TEE_Result res;
	int rc = RPC_FAILED;

	DMSG("(id: %d, d: %p)...", id, (void *)d);

	if (!d) {
		rc = 0;
		goto exit;
	}

	head.op = TEE_FS_CLOSEDIR;
	head.arg = (int)d->nw_dir;

	res = tee_fs_rpc_send_cmd(id, &head, NULL, 0, TEE_FS_MODE_NONE);
	if (res != TEE_SUCCESS)
		goto exit;

	rc = head.res;
exit:
	if (d)
		free(d->d.d_name);
	free(d);

	DMSG("...%d", rc);
	return rc;
}

int tee_fs_rpc_rmdir(int id, const char *name)
{
	struct tee_fs_rpc head = { 0 };
	TEE_Result res;
	int rc = RPC_FAILED;
	size_t len;

	DMSG("(id: %d, name: %s)...", id, name);

	if (!name)
		goto exit;

	len = strlen(name) + 1;
	if (len <= 1)
		goto exit;

	head.op = TEE_FS_RMDIR;

	res = tee_fs_rpc_send_cmd(id, &head, (void *)name, len,
				  TEE_FS_MODE_IN);
	if (res != TEE_SUCCESS)
		goto exit;

	rc = head.res;
exit:
	DMSG("...%d", rc);
	return rc;
}

int tee_fs_rpc_unlink(int id, const char *file)
{
	struct tee_fs_rpc head = { 0 };
	size_t len;
	TEE_Result res;
	int rc = RPC_FAILED;

	DMSG("(id: %d, file: %s)...", id, file);

	if (!file)
		goto exit;

	len = strlen(file) + 1;
	if (len <= 1)
		goto exit;

	head.op = TEE_FS_UNLINK;

	res = tee_fs_rpc_send_cmd(id, &head, (void *)file, len,
				  TEE_FS_MODE_IN);
	if (res != TEE_SUCCESS)
		goto exit;

	rc = head.res;
exit:
	DMSG("...%d", rc);
	return rc;
}
