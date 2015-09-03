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

#include "tee_fs_private.h"

/*
 * This file implements file-based operations for secure storage,
 * file content is encrypted and MACed before storing on normal
 * world file system.
 *
 * File hole is not implemented because this is meaningless in
 * the context of secure storage.
 */

struct tee_enc_fs_private {
	uint32_t pos;
	uint32_t len;
	uint8_t *data;
};

static int update_file_size(struct tee_enc_fs_private *priv,
		size_t new_file_len)
{
	size_t old_file_len = priv->len;

	if (!priv->data)
		priv->data = malloc(new_file_len);
	else
		priv->data = realloc(priv->data, new_file_len);
	if (!priv->data)
		return -1;

	priv->len = new_file_len;

	/* if size is increased, zero fill the gap */
	if (new_file_len > old_file_len) {
		size_t diff =
			new_file_len - old_file_len;
		memset(priv->data + old_file_len, 0, diff);
	}

	return 0;
}

static int tee_enc_fs_open(const char *file, int flags, ...)
{
	int fd, open_flags, res = -1;
	size_t encrypted_data_len, file_len;
	size_t file_header_len = tee_enc_fs_get_file_header_size();
	void *encrypted_data;
	struct tee_fs_fd *fdp;
	struct tee_enc_fs_private *priv;
	TEE_Result ret;

	DMSG("open, file=%s, flags=%x", file, flags);
	open_flags = TEE_FS_O_RDWR;
	if (flags & TEE_FS_O_CREATE)
		open_flags |= TEE_FS_O_CREATE;

	fd = tee_fs_common_open(file, open_flags);
	if (fd < 0)
		goto exit;

	fdp = tee_fs_fd_lookup(fd);
	if (!fdp)
		goto exit;

	priv = (struct tee_enc_fs_private *)
		malloc(sizeof(struct tee_enc_fs_private));
	if (!priv)
		goto exit;
	tee_fs_fd_priv(fdp) = priv;

	if (fdp->is_new_file) {
		priv->len = 0;
		priv->pos = 0;
		priv->data = NULL;
		return fd;
	}

	res = tee_fs_get_file_length(fdp, &encrypted_data_len);
	if (res < 0) {
		res = -1;
		goto exit_close_file;
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
		goto exit_close_file;
	}

	/*
	 * init internal status, also allocate buffer for
	 * decrypted file content
	 */
	priv->pos = 0;
	priv->len = file_len;
	priv->data = malloc(file_len);
	if (!priv->data) {
		res = -1;
		goto exit_free_encrypted_data;
	}

	/* read encrypted file content */
	res = tee_fs_common_read(fdp, encrypted_data, encrypted_data_len);
	if (res != (int)encrypted_data_len) {
		res = -1;
		goto exit_free_decrypted_data;
	}
	DMSG("%d bytes read", res);

	/* decrypt and authenticate the file content */
	ret = tee_enc_fs_file_decryption(encrypted_data, encrypted_data_len,
			priv->data, &file_len);
	if (ret != TEE_SUCCESS) {
		res = -1;
		goto exit_free_decrypted_data;
	}
	res = fd;

exit_free_decrypted_data:
	if (res < 0)
		free(priv->data);
exit_free_encrypted_data:
	free(encrypted_data);
exit_close_file:
	if (res < 0 && fd >= 0)
		tee_fs_common_close(fdp);
exit:
	return res;
}

static int tee_enc_fs_close(int fd)
{
	int res = -1;
	size_t encrypted_data_len;
	size_t file_header_len = tee_enc_fs_get_file_header_size();
	void *encrypted_data;
	TEE_Result ret;
	struct tee_fs_fd *fdp = tee_fs_fd_lookup(fd);
	struct tee_enc_fs_private *priv;

	DMSG("close, fd=%d", fd);

	if (!fdp)
		return -1;
	priv = tee_fs_fd_priv(fdp);

	encrypted_data_len = priv->len + file_header_len;

	/* allocate buffer to hold encrypted file content */
	encrypted_data = malloc(encrypted_data_len);
	if (!encrypted_data)
		goto exit_free_fd;

	/* encrypt the file content and calculate MAC */
	ret = tee_enc_fs_file_encryption(priv->data, priv->len,
			encrypted_data, &encrypted_data_len);
	if (ret != TEE_SUCCESS)
		goto exit_free_encrypted_data;

	res = tee_fs_common_lseek(fdp, 0, TEE_FS_SEEK_SET);
	if (res < 0)
		goto exit_free_encrypted_data;

	res = tee_fs_common_ftruncate(fdp, 0);
	if (res < 0)
		goto exit_free_encrypted_data;

	/* write encrypted file content to normal world file system */
	res = tee_fs_common_write(fdp, encrypted_data,
					encrypted_data_len);
	if (res != (int)encrypted_data_len) {
		res = -1;
		goto exit_free_encrypted_data;
	}
	DMSG("%d bytes written", res);

exit_free_encrypted_data:
	free(encrypted_data);
exit_free_fd:
	free(priv->data);

	if (res < 0) {
		tee_fs_fail_recovery(fdp);
		return res;
	}

	res = tee_fs_common_close(fdp);

	return res;
}

static int tee_enc_fs_read(int fd, void *buf, size_t len)
{
	int res = -1;
	size_t remain;
	struct tee_fs_fd *fdp = tee_fs_fd_lookup(fd);
	struct tee_enc_fs_private *priv;

	DMSG("read, fd=%d, buf=%p, len=%zu", fd, buf, len);

	if (len == 0) {
		res = 0;
		goto exit;
	}

	if (!fdp || !buf)
		goto exit;

	priv = tee_fs_fd_priv(fdp);

	if (fdp->flags & TEE_FS_O_WRONLY)
		goto exit;

	remain = priv->len - priv->pos;
	if (len > remain)
		len = remain;

	memcpy(buf, priv->data + priv->pos, len);
	res = len;

exit:
	return res;
}

static int tee_enc_fs_write(int fd, const void *buf, size_t len)
{
	int res = -1;
	size_t remain;
	struct tee_fs_fd *fdp = tee_fs_fd_lookup(fd);
	struct tee_enc_fs_private *priv;

	DMSG("write, fd=%d, buf=%p, len=%zu", fd, buf, len);

	if (len == 0) {
		res = 0;
		goto exit;
	}

	if (!buf)
		goto exit;

	if (!fdp)
		goto exit;

	priv = tee_fs_fd_priv(fdp);

	/* restrict this to avoid file hole */
	if (priv->pos > priv->len)
		goto exit;

	if (fdp->flags & TEE_FS_O_RDONLY)
		goto exit;

	/* check if we need to update file size */
	remain = priv->len - priv->pos;
	if (len > remain) {
		size_t new_file_len = priv->len + (len - remain);

		res = update_file_size(priv, new_file_len);
		if (res != 0)
			goto exit;
	}

	memcpy(priv->data + priv->pos, buf, len);
	priv->pos += len;
	res = len;

exit:
	return res;
}

static tee_fs_off_t tee_enc_fs_lseek(int fd, tee_fs_off_t offset, int whence)
{
	tee_fs_off_t res = -1;
	tee_fs_off_t new_pos;
	struct tee_fs_fd *fdp = tee_fs_fd_lookup(fd);
	struct tee_enc_fs_private *priv;

	if (!fdp)
		goto exit;
	priv = tee_fs_fd_priv(fdp);

	switch (whence) {

	case TEE_FS_SEEK_SET:
		new_pos = offset;
		break;

	case TEE_FS_SEEK_CUR:
		new_pos = priv->pos + offset;
		break;

	case TEE_FS_SEEK_END:
		new_pos = priv->len + offset;
		break;

	default:
		goto exit;
	}

	/*
	 * file hole is not supported in this implementation,
	 * restrict the file postion within file length
	 * for simplicity
	 */
	if ((new_pos < 0) || (new_pos > (tee_fs_off_t)priv->len))
		goto exit;

	res = priv->pos = new_pos;
exit:
	return res;
}

static int tee_enc_fs_ftruncate(int fd, tee_fs_off_t length)
{
	int res = -1;
	struct tee_fs_fd *fdp = tee_fs_fd_lookup(fd);
	struct tee_enc_fs_private *priv;

	if (!fdp)
		goto exit;
	priv = tee_fs_fd_priv(fdp);

	if (fdp->flags & TEE_FS_O_RDONLY)
		goto exit;

	res = update_file_size(priv, length);

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
