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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string_ext.h>
#include <tee/tee_fs.h>
#include <tee/tee_fs_defs.h>
#include <tee/tee_cryp_provider.h>
#include <kernel/tee_common_unpg.h>
#include <kernel/handle.h>
#include <trace.h>

#include "tee_fs_private.h"

static struct handle_db fs_handle_db = HANDLE_DB_INITIALIZER;

struct block_operation_args {
	struct tee_fs_fd *fdp;
	tee_fs_off_t offset;
	int block_num;
	void *buf;
	size_t len;
};

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

static int ree_fs_write(int fd,
			const void *buf, size_t len)
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
	head.len = len;

	res = tee_fs_send_cmd(&head, (void *)buf, len, TEE_FS_MODE_IN);
	if (!res)
		res = head.res;
exit:
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

static int ree_fs_mkdir(const char *path, tee_fs_mode_t mode)
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

static int ree_fs_rmdir(const char *name)
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

static int ree_fs_unlink(const char *file)
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

static TEE_Result sha256_digest(uint8_t *digest,
			const uint8_t *data, size_t data_size)
{
	TEE_Result res;
	size_t ctx_size;
	void *ctx;

	res = crypto_ops.hash.get_ctx_size(TEE_ALG_SHA256, &ctx_size);
	if (res != TEE_SUCCESS)
		return res;

	ctx = malloc(ctx_size);
	if (!ctx)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = crypto_ops.hash.init(ctx, TEE_ALG_SHA256);
	if (res != TEE_SUCCESS)
		goto exit;

	res = crypto_ops.hash.update(ctx, TEE_ALG_SHA256,
			data, data_size);
	if (res != TEE_SUCCESS)
		goto exit;

	res = crypto_ops.hash.final(ctx, TEE_ALG_SHA256,
			digest, TEE_SHA256_HASH_SIZE);
	if (res != TEE_SUCCESS)
		goto exit;

	free(ctx);

	return TEE_SUCCESS;
exit:
	return res;
}

static TEE_Result sha256_check(const uint8_t *hash, const uint8_t *data,
		size_t data_size)
{
	TEE_Result res;
	uint8_t digest[TEE_SHA256_HASH_SIZE];
	res = sha256_digest(digest, data, data_size);
	if (res != TEE_SUCCESS)
		return res;

	if (buf_compare_ct(digest, hash, sizeof(digest)) != 0)
		return TEE_ERROR_SECURITY;
	return TEE_SUCCESS;
}


static void get_meta_filepath(const char *file, char *meta_path)
{
	snprintf(meta_path, REE_FS_NAME_MAX, "%s/meta", file);
}

static void get_block_filepath(const char *file, int block_num,
						char *meta_path)
{
	snprintf(meta_path, REE_FS_NAME_MAX, "%s/block%d", file,
			block_num);
}

static int alloc_block(struct tee_fs_fd *fdp, int block_num)
{
	char block_path[REE_FS_NAME_MAX];

	get_block_filepath(fdp->filename, block_num, block_path);
	DMSG("%s", block_path);

	return ree_fs_open(block_path, TEE_FS_O_CREATE | TEE_FS_O_WRONLY);
}

static int free_block(struct tee_fs_fd *fdp, int block_num)
{
	char block_path[REE_FS_NAME_MAX];

	get_block_filepath(fdp->filename, block_num, block_path);
	DMSG("%s", block_path);

	return ree_fs_unlink(block_path);
}

static bool is_tee_file_meta_valid(struct tee_fs_file_meta *meta)
{
	TEE_Result res;
	res = sha256_check(meta->hash, (void *)&meta->info,
			sizeof(meta->info));
	if (res != TEE_SUCCESS)
		return false;
	else
		return true;
}

static struct tee_fs_file_meta *tee_fs_file_create(const char *file)
{
	struct tee_fs_file_meta *meta;
	int res = ree_fs_mkdir(file,
			TEE_FS_S_IRUSR | TEE_FS_S_IWUSR);
	if (res)
		goto exit;

	meta = malloc(sizeof(struct tee_fs_file_meta));
	if (!meta)
		goto exit_rmdir;

	meta->info.length = 0;
	return meta;

exit_rmdir:
	ree_fs_rmdir(file);
exit:
	return NULL;
}

static int write_file_meta(struct tee_fs_fd *fdp)
{
	TEE_Result ret;
	int res, fd;
	char meta_path[REE_FS_NAME_MAX];
	struct tee_fs_file_meta *meta;
	get_meta_filepath(fdp->filename, meta_path);

	meta = fdp->meta;
	ret = sha256_digest(meta->hash, (void *)&meta->info,
				sizeof(meta->info));
	if (ret != TEE_SUCCESS)
		return -1;

	fd = ree_fs_open(meta_path, TEE_FS_O_CREATE | TEE_FS_O_WRONLY);
	if (fd < 0)
		return fd;

	res = ree_fs_write(fd, meta, sizeof(*meta));
	if (res != sizeof(*meta))
		return res;

	return ree_fs_close(fd);
}

static int read_file_meta(const char *meta_path,
		struct tee_fs_file_meta *meta)
{
	int res, fd;

	res = ree_fs_open(meta_path, TEE_FS_O_RDWR);
	if (res < 0)
		return res;

	fd = res;
	res = ree_fs_read(fd, meta, sizeof(*meta));
	if (res != sizeof(*meta))
		return -1;

	if (!is_tee_file_meta_valid(meta))
		return -1;

	return ree_fs_close(fd);
}

static struct tee_fs_file_meta *tee_fs_meta_open(const char *file)
{
	int res;
	char meta_path[REE_FS_NAME_MAX];
	struct tee_fs_file_meta *meta;

	meta = malloc(sizeof(struct tee_fs_file_meta));
	if (!meta)
		return NULL;

	get_meta_filepath(file, meta_path);
	res = read_file_meta(meta_path, meta);
	if (res)
		goto exit_free_meta;

	return meta;

exit_free_meta:
	free(meta);
	return NULL;
}

static bool need_to_allocate_new_block(struct tee_fs_fd *fdp,
					int block_num)
{
	int num_blocks_allocated =
		size_to_num_blocks(fdp->meta->info.length);
	return (block_num >= num_blocks_allocated);
}

static int write_one_block(struct block_operation_args *args)
{
	int fd, res, bytes;
	struct tee_fs_fd *fdp = args->fdp;
	int block_num = args->block_num;
	tee_fs_off_t off = args->offset;
	size_t len = args->len;
	const void *buf = args->buf;

	if (need_to_allocate_new_block(fdp, block_num)) {
		fd = alloc_block(fdp, block_num);
	} else {
		char block_path[REE_FS_NAME_MAX];
		get_block_filepath(fdp->filename, block_num, block_path);
		fd = ree_fs_open(block_path, TEE_FS_O_RDWR);
	}
	if (fd < 0)
		return fd;

	if (off) {
		res = ree_fs_lseek(fd, off, TEE_FS_SEEK_SET);
		if (res != off)
			return res;
	}

	bytes = ree_fs_write(fd, buf, len);
	if (bytes < 0)
		return -1;

	res = ree_fs_close(fd);
	if (res)
		return res;

	return bytes;
}

static int read_one_block(struct block_operation_args *args)
{
	int fd, res, bytes;
	struct tee_fs_fd *fdp = args->fdp;
	int block_num = args->block_num;
	tee_fs_off_t off = args->offset;
	size_t len = args->len;
	void *buf = args->buf;
	char block_path[REE_FS_NAME_MAX];

	get_block_filepath(fdp->filename, block_num,
			block_path);
	fd = ree_fs_open(block_path, TEE_FS_O_RDWR);
	if (fd < 0)
		return fd;

	if (off) {
		res = ree_fs_lseek(fd, off, TEE_FS_SEEK_SET);
		if (res != off)
			return res;
	}

	bytes = ree_fs_read(fd, buf, len);
	if (bytes < 0)
		return -1;

	res = ree_fs_close(fd);
	if (res)
		return res;

	return bytes;
}

static int tee_fs_do_block_operation(struct tee_fs_fd *fdp,
		int (*do_block_ops)(struct block_operation_args *args),
		void *buf, size_t len)
{
	int start_block, end_block, num_blocks_to_process;
	int block_num, remain_bytes = len;
	size_t offset_in_block;
	uint8_t *data = buf;

	start_block = pos_to_block_num(fdp->pos);
	end_block = pos_to_block_num(fdp->pos + len);
	num_blocks_to_process = end_block - start_block + 1;
	block_num = start_block;
	offset_in_block = fdp->pos & (FILE_BLOCK_SIZE - 1);

	while (num_blocks_to_process) {
		struct block_operation_args args = {
			.fdp = fdp,
			.offset = offset_in_block,
			.block_num = block_num,
			.buf = data,
			.len = (remain_bytes > FILE_BLOCK_SIZE) ?
				FILE_BLOCK_SIZE :
				remain_bytes
		};
		int bytes_consumed = do_block_ops(&args);

		if (bytes_consumed < 0)
			return -1;

		DMSG("block_num: %d, offset: %d, bytes_consumed: %d",
			block_num, offset_in_block, bytes_consumed);

		data += bytes_consumed;
		remain_bytes -= bytes_consumed;
		block_num++;
		num_blocks_to_process--;

		/* only the first block needs block offset */
		if (offset_in_block)
			offset_in_block = 0;
	}

	fdp->pos += len;

	return len;
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

int tee_fs_common_open(const char *file, int flags, ...)
{
	int res = -1;
	size_t len;
	struct tee_fs_file_meta *meta;
	struct tee_fs_fd *fdp = NULL;

	DMSG("file=%s", file);

	len = strlen(file) + 1;
	if (len > TEE_FS_NAME_MAX)
		goto exit;

	meta = tee_fs_meta_open(file);
	if (!meta) {
		/* cannot find meta file, assumed file not existed */
		if (flags & TEE_FS_O_CREATE) {
			meta = tee_fs_file_create(file);
			if (!meta)
				return -1;
		} else
			return -1;
	}

	fdp = (struct tee_fs_fd *)malloc(sizeof(struct tee_fs_fd));
	if (!fdp)
		goto exit_free_fd;

	/* init internal status */
	fdp->flags = flags;
	fdp->private = NULL;
	fdp->meta = meta;
	fdp->pos = 0;
	fdp->filename = malloc(len);
	if (!fdp->filename) {
		res = -1;
		goto exit_free_fd;
	}
	memcpy(fdp->filename, file, len);

	/* return fd */
	res = handle_get(&fs_handle_db, fdp);
	fdp->fd = res;

exit_free_fd:
	if (res == -1)
		free(fdp);
exit:
	return res;
}

int tee_fs_common_close(struct tee_fs_fd *fdp)
{
	int res = -1;

	if (!fdp)
		return -1;

	handle_put(&fs_handle_db, fdp->fd);

	res = write_file_meta(fdp);
	if (res)
		return res;

	if (fdp->private)
		free(fdp->private);
	free(fdp->meta);
	free(fdp->filename);
	free(fdp);

	return res;
}

tee_fs_off_t tee_fs_common_lseek(struct tee_fs_fd *fdp,
				tee_fs_off_t offset, int whence)
{
	tee_fs_off_t res = -1;
	tee_fs_off_t new_pos;
	size_t filelen;

	DMSG("offset=%d", offset);

	if (!fdp)
		return -1;

	filelen = fdp->meta->info.length;

	switch (whence) {
	case TEE_FS_SEEK_SET:
		new_pos = offset;
		break;

	case TEE_FS_SEEK_CUR:
		new_pos = fdp->pos + offset;
		break;

	case TEE_FS_SEEK_END:
		new_pos = filelen + offset;
		break;

	default:
		goto exit;
	}

	/*
	 * file hole is not supported in this implementation,
	 * restrict the file postion within file length
	 * for simplicity
	 */
	if (new_pos > (tee_fs_off_t)filelen)
		goto exit;

	res = fdp->pos = new_pos;
exit:
	return res;
}

int tee_fs_common_ftruncate(struct tee_fs_fd *fdp,
				tee_fs_off_t new_file_len)
{
	int res = -1;
	size_t old_file_len;
	int old_block_num, new_block_num, diff_blocks, i = 0;

	if (!fdp)
		goto exit;

	if (fdp->flags & TEE_FS_O_RDONLY)
		goto exit;

	if (new_file_len > (tee_fs_off_t)fdp->meta->info.length)
		goto exit;

	old_file_len = fdp->meta->info.length;
	old_block_num = pos_to_block_num(old_file_len);
	new_block_num = pos_to_block_num(new_file_len);
	diff_blocks = new_block_num - old_block_num;

	/* free blocks */
	TEE_ASSERT(diff_blocks <= 0);
	while (diff_blocks) {
		res = free_block(fdp, old_block_num - i);
		if (res)
			goto exit;
		i++;
		diff_blocks++;
	}

	fdp->meta->info.length = new_file_len;
	DMSG("truncated length=%d", new_file_len);
exit:
	return res;
}

int tee_fs_common_read(struct tee_fs_fd *fdp, void *buf, size_t len)
{
	int res = -1;

	if (!fdp)
		return -1;

	if (!len) {
		res = 0;
		goto exit;
	}

	if (!buf)
		goto exit;

	if (fdp->flags & TEE_FS_O_WRONLY)
		goto exit;

	DMSG("len=%d", len);

	if (fdp->pos + len > fdp->meta->info.length) {
		len = fdp->meta->info.length - fdp->pos;
		DMSG("reached EOF, update read length to %d", len);
	}

	res = tee_fs_do_block_operation(
			fdp, read_one_block, buf, len);
exit:
	return res;
}

int tee_fs_common_write(struct tee_fs_fd *fdp,
			const void *buf, size_t len)
{
	int res = -1;

	if (!fdp)
		return -1;

	if (!len) {
		res = 0;
		goto exit;
	}

	if (!buf)
		goto exit;

	if (fdp->flags & TEE_FS_O_RDONLY)
		goto exit;

	DMSG("len=%d", len);
	res = tee_fs_do_block_operation(
			fdp, write_one_block, (void *)buf, len);

	/* update file length if necessary */
	if (res > 0) {
		if (fdp->pos > (tee_fs_off_t)fdp->meta->info.length)
			fdp->meta->info.length = fdp->pos;
	}

	/*
	 * TODO:
	 * Ideally we should write meta file every time we
	 * update TEE file, we will do it when implemnting
	 * atomic update for TEE file. Current we write the
	 * meta file upon close.
	 */
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
	size_t len = strlen(file) + 1;
	struct tee_fs_dirent *dirent;
	struct tee_fs_dir *dir;
	DMSG("file=%s", file);

	if (len > TEE_FS_NAME_MAX)
		goto exit;

	dir = tee_fs_common_opendir(file);
	if (!dir)
		goto exit;

	dirent = tee_fs_common_readdir(dir);
	while (dirent) {
		char path[REE_FS_NAME_MAX];

		snprintf(path, REE_FS_NAME_MAX, "%s/%s",
			file, dirent->d_name);

		DMSG("unlink %s", path);
		res = ree_fs_unlink(path);
		if (res)
			goto exit;

		dirent = tee_fs_common_readdir(dir);
	}

	res = tee_fs_common_closedir(dir);
	if (res)
		goto exit;

	res = tee_fs_common_rmdir(file);
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
