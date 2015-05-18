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
#include <tee/tee_enc_fs_key_manager.h>
#include <kernel/tee_rpc.h>
#include <kernel/tee_rpc_types.h>
#include <mm/core_mmu.h>
#include "tee_api_defines.h"
#include <kernel/tee_common_unpg.h>
#include <trace.h>
#include <kernel/handle.h>

#include "tee_fs_private.h"

/*
 * This file implements file-based operations for secure storage,
 * file content is encrypted and MACed before storing on normal
 * world file system.
 *
 * File hole is not implemented because this is meaningless in
 * the context of secure storage.
 */

struct tee_enc_fs_fd {
	int nw_fd;		/* normal world fd */
	uint32_t flags;
	uint32_t pos;
	uint32_t len;
	uint8_t is_new_file;
	char *filename;
	uint8_t *data;
};

static struct handle_db fs_handle_db = HANDLE_DB_INITIALIZER;

static int get_file_length(int fd, size_t *length)
{
	size_t file_len;
	int res;

	*length = 0;

	res = tee_fs_common_lseek(fd, 0, TEE_FS_SEEK_END);
	if (res < 0)
		return res;
	file_len = res;

	res = tee_fs_common_lseek(fd, 0, TEE_FS_SEEK_SET);
	if (res < 0)
		return res;

	*length = file_len;
	return 0;
}

static int update_file_size(struct tee_enc_fs_fd *fdp,
		size_t new_file_len)
{
	size_t old_file_len = fdp->len;

	if (!fdp->data)
		fdp->data = malloc(new_file_len);
	else
		fdp->data = realloc(fdp->data, new_file_len);
	if (!fdp->data)
		return -1;

	fdp->len = new_file_len;

	/* if size is increased, zero fill the gap */
	if (new_file_len > old_file_len) {
		size_t diff =
			new_file_len - old_file_len;
		memset(fdp->data + old_file_len, 0, diff);
	}

	return 0;
}

static void do_fail_recovery(struct tee_enc_fs_fd *fdp)
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

static int tee_enc_fs_open(const char *file, int flags, ...)
{
	int nw_fd, res = -1;
	size_t name_len;
	size_t encrypted_data_len, file_len;
	size_t file_header_len = tee_enc_fs_get_file_header_size();
	void *encrypted_data;
	TEE_Result ret;
	struct tee_enc_fs_fd *fd = NULL;
	struct tee_fs_rpc head = { 0 };

	DMSG("open, file=%s", file);

	name_len = strlen(file) + 1;
	if (name_len > TEE_FS_NAME_MAX)
		goto exit;

	head.op = TEE_FS_OPEN;
	head.flags = TEE_FS_O_RDWR;
	if (flags & TEE_FS_O_CREATE)
		head.flags |= TEE_FS_O_CREATE;
	head.fd = 0;
	res = tee_fs_send_cmd(&head, (void *)file, name_len, TEE_FS_MODE_IN);
	if (res != 0)
		goto exit;

	nw_fd = head.res;
	if (nw_fd < 0) {
		res = -1;
		goto exit;
	}

	fd = (struct tee_enc_fs_fd *)malloc(sizeof(struct tee_enc_fs_fd));
	if (!fd) {
		res = -1;
		goto exit;
	}

	res = get_file_length(nw_fd, &encrypted_data_len);
	if (res < 0) {
		res = -1;
		goto exit_free_fd;
	}

	fd->nw_fd = nw_fd;
	fd->flags = flags;
	fd->pos = 0;
	fd->filename = malloc(name_len);
	if (!fd->filename) {
		res = -1;
		goto exit_free_fd;
	}
	memcpy(fd->filename, file, name_len);

	/* new created file? */
	if (encrypted_data_len == 0) {
		fd->len = 0;
		fd->is_new_file = 1;
		fd->data = NULL;
		return handle_get(&fs_handle_db, fd);
	}

	/*
	 * The file stored on normal world filesystem is encrypted data
	 * with an additional file header
	 */
	TEE_ASSERT(encrypted_data_len > file_header_len);
	file_len = encrypted_data_len - file_header_len;

	/* allocate buffer to hold encrypted file context + header */
	encrypted_data = malloc(encrypted_data_len);
	if (!encrypted_data) {
		res = -1;
		goto exit_free_fd;
	}

	/*
	 * init internal status, also allocate buffer for
	 * decrypted file content
	 */
	fd->len = file_len;
	fd->is_new_file = 0;
	fd->data = malloc(file_len);
	if (!fd->data) {
		res = -1;
		goto exit_free_encrypted_data;
	}

	/* read encrypted file content */
	res = tee_fs_common_read(nw_fd, encrypted_data, encrypted_data_len);
	if (res != (int)encrypted_data_len) {
		res = -1;
		goto exit_free_decrypted_data;
	}
	DMSG("%d bytes read", res);

	/* decrypt and authenticate the file content */
	ret = tee_enc_fs_file_decryption(encrypted_data, encrypted_data_len,
			fd->data, &file_len);
	if (ret != TEE_SUCCESS) {
		res = -1;
		goto exit_free_decrypted_data;
	}

	res = handle_get(&fs_handle_db, fd);

exit_free_decrypted_data:
	if (res < 0)
		free(fd->data);
exit_free_encrypted_data:
	free(encrypted_data);
exit_free_fd:
	if (res < 0) {
		if (fd->filename)
			free(fd->filename);
		free(fd);
	}
exit:
	return res;
}

static int tee_enc_fs_close(int fd)
{
	int res = -1;
	int res2 = -1;
	size_t encrypted_data_len;
	size_t file_header_len = tee_enc_fs_get_file_header_size();
	void *encrypted_data;
	TEE_Result ret;
	struct tee_enc_fs_fd *fdp = handle_put(&fs_handle_db, fd);

	DMSG("close, fd=%d", fd);

	if (!fdp)
		return -1;

	encrypted_data_len = fdp->len + file_header_len;

	/* allocate buffer to hold encrypted file content */
	encrypted_data = malloc(encrypted_data_len);
	if (!encrypted_data)
		goto exit_free_fd;

	/* encrypt the file content and calculate MAC */
	ret = tee_enc_fs_file_encryption(fdp->data, fdp->len,
			encrypted_data, &encrypted_data_len);
	if (ret != TEE_SUCCESS)
		goto exit_free_encrypted_data;

	res = tee_fs_common_lseek(fdp->nw_fd, 0, TEE_FS_SEEK_SET);
	if (res < 0)
		goto exit_free_encrypted_data;

	res = tee_fs_common_ftruncate(fdp->nw_fd, encrypted_data_len);
	if (res < 0)
		goto exit_free_encrypted_data;

	/* write encrypted file content to normal world file system */
	res = tee_fs_common_write(fdp->nw_fd, encrypted_data,
					encrypted_data_len);
	if (res != (int)encrypted_data_len) {
		res = -1;
		goto exit_free_encrypted_data;
	}
	DMSG("%d bytes written", res);

exit_free_encrypted_data:
	free(encrypted_data);

exit_free_fd:
	res2 = tee_fs_common_close(fdp->nw_fd);

	if (res < 0 || res2 < 0) {
		EMSG("Fail to close file, start fail recovery function");
		do_fail_recovery(fdp);
	}

	free(fdp->data);
	free(fdp->filename);
	free(fdp);

	return res;
}

static int tee_enc_fs_read(int fd, void *buf, size_t len)
{
	int res = -1;
	size_t remain;
	struct tee_enc_fs_fd *fdp = handle_lookup(&fs_handle_db, fd);

	DMSG("read, fd=%d, buf=%p, len=%zu", fd, buf, len);

	if (len == 0) {
		res = 0;
		goto exit;
	}

	if (!fdp || !buf)
		goto exit;

	if (fdp->flags & TEE_FS_O_WRONLY)
		goto exit;

	remain = fdp->len - fdp->pos;
	if (len > remain)
		len = remain;

	memcpy(buf, fdp->data + fdp->pos, len);
	res = len;

exit:
	return res;
}

static int tee_enc_fs_write(int fd, const void *buf, size_t len)
{
	int res = -1;
	size_t remain;
	struct tee_enc_fs_fd *fdp = handle_lookup(&fs_handle_db, fd);

	DMSG("write, fd=%d, buf=%p, len=%zu", fd, buf, len);

	if (len == 0) {
		res = 0;
		goto exit;
	}

	if (!buf)
		goto exit;

	if (!fdp)
		goto exit;

	/* restrict this to avoid file hole */
	if (fdp->pos > fdp->len)
		goto exit;

	if (fdp->flags & TEE_FS_O_RDONLY)
		goto exit;

	/* check if we need to update file size */
	remain = fdp->len - fdp->pos;
	if (len > remain) {
		size_t new_file_len = fdp->len + (len - remain);

		res = update_file_size(fdp, new_file_len);
		if (res != 0)
			goto exit;
	}

	memcpy(fdp->data + fdp->pos, buf, len);
	fdp->pos += len;
	res = len;

exit:
	return res;
}

static tee_fs_off_t tee_enc_fs_lseek(int fd, tee_fs_off_t offset, int whence)
{
	tee_fs_off_t res = -1;
	tee_fs_off_t new_pos;
	struct tee_enc_fs_fd *fdp = handle_lookup(&fs_handle_db, fd);

	if (!fdp)
		goto exit;

	switch (whence) {

	case TEE_FS_SEEK_SET:
		new_pos = offset;
		break;

	case TEE_FS_SEEK_CUR:
		new_pos = fdp->pos + offset;
		break;

	case TEE_FS_SEEK_END:
		new_pos = fdp->len + offset;
		break;

	default:
		goto exit;
	}

	/*
	 * file hole is not supported in this implementation,
	 * restrict the file postion within file length
	 * for simplicity
	 */
	if (new_pos > (tee_fs_off_t)fdp->len)
		goto exit;

	res = fdp->pos = new_pos;
exit:
	return res;
}

static int tee_enc_fs_ftruncate(int fd, tee_fs_off_t length)
{
	int res = -1;
	struct tee_enc_fs_fd *fdp = handle_lookup(&fs_handle_db, fd);

	if (!fdp)
		goto exit;

	if (fdp->flags & TEE_FS_O_RDONLY)
		goto exit;

	res = update_file_size(fdp, length);

exit:
	return res;
}

struct tee_file_operations tee_file_ops = {
	.open = tee_enc_fs_open,
	.close = tee_enc_fs_close,
	.read = tee_enc_fs_read,
	.write = tee_enc_fs_write,
	.lseek = tee_enc_fs_lseek,
	.ftruncate = tee_enc_fs_ftruncate,
	.rename = tee_fs_common_rename,
	.unlink = tee_fs_common_unlink,
	.mkdir = tee_fs_common_mkdir,
	.opendir = tee_fs_common_opendir,
	.closedir = tee_fs_common_closedir,
	.readdir = tee_fs_common_readdir,
	.rmdir = tee_fs_common_rmdir,
	.access = tee_fs_common_access
};
