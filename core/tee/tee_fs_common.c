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
	void *extra;
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


static void get_meta_filepath(const char *file, int version,
				char *meta_path)
{
	snprintf(meta_path, REE_FS_NAME_MAX, "%s/meta.%d",
			file, version);
}

static void get_block_filepath(const char *file, int block_num,
				int version, char *meta_path)
{
	snprintf(meta_path, REE_FS_NAME_MAX, "%s/block%d.%d",
			file, block_num, version);
}

static int alloc_block(struct tee_fs_fd *fdp, int block_num)
{
	char block_path[REE_FS_NAME_MAX];

	get_block_filepath(fdp->filename, block_num, 0, block_path);
	DMSG("%s", block_path);

	return ree_fs_open(block_path, TEE_FS_O_CREATE | TEE_FS_O_WRONLY);
}

static int free_block(struct tee_fs_fd *fdp, int block_num)
{
	char block_path[REE_FS_NAME_MAX];
	uint8_t version =
		get_backup_version_of_block(fdp->meta, block_num);

	get_block_filepath(fdp->filename, block_num, version, block_path);
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

	memset(&meta->info, 0, sizeof(meta->info));
	return meta;

exit_rmdir:
	ree_fs_rmdir(file);
exit:
	return NULL;
}

static struct tee_fs_file_meta *create_new_file_meta(
		struct tee_fs_fd *fdp)
{
	struct tee_fs_file_meta *new_meta;

	new_meta = malloc(sizeof(*new_meta));
	if (!new_meta)
		goto exit;
	memcpy(new_meta, fdp->meta, sizeof(*new_meta));
exit:
	return new_meta;
}

static int commit_file_meta(struct tee_fs_fd *fdp,
		struct tee_fs_file_meta *new_meta)
{
	TEE_Result ret;
	int res, fd;
	uint8_t new_version, old_version;
	char meta_path[REE_FS_NAME_MAX];

	old_version = fdp->meta_version;
	new_version = !old_version;
	get_meta_filepath(fdp->filename, new_version, meta_path);
	DMSG("%s", meta_path);

	ret = sha256_digest(new_meta->hash, (void *)&new_meta->info,
				sizeof(new_meta->info));
	if (ret != TEE_SUCCESS)
		return -1;

	fd = ree_fs_open(meta_path, TEE_FS_O_CREATE | TEE_FS_O_WRONLY);
	if (fd < 0)
		return fd;

	res = ree_fs_write(fd, new_meta, sizeof(*new_meta));
	if (res != sizeof(*new_meta))
		return res;

	res = ree_fs_close(fd);
	if (res < 0)
		return res;

	/*
	 * From now on new meta is successfully committed,
	 * change tee_fd_fd accordingly
	 */
	memcpy(fdp->meta, new_meta, sizeof(*new_meta));
	fdp->meta_version = new_version;

	/*
	 * Remove outdated file meta, there is nothing we can
	 * do if we fail here, but that is OK because both
	 * new & old version of block files are kept. The context
	 * of the file is still consistent.
	 */
	get_meta_filepath(fdp->filename, old_version, meta_path);
	ree_fs_unlink(meta_path);

	return res;
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

static struct tee_fs_file_meta *tee_fs_meta_open(
		const char *file, int version)
{
	int res;
	char meta_path[REE_FS_NAME_MAX];
	struct tee_fs_file_meta *meta;

	meta = malloc(sizeof(struct tee_fs_file_meta));
	if (!meta)
		return NULL;

	get_meta_filepath(file, version, meta_path);
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

static int create_new_version_for_block(struct tee_fs_fd *fdp,
		struct tee_fs_file_meta *new_meta, int block_num)
{
	char block_path[REE_FS_NAME_MAX];
	char buffer[COPY_BUF_SIZE];
	uint8_t version =
		get_backup_version_of_block(fdp->meta, block_num);
	int new_fd, fd, num_read, res = -1;

	get_block_filepath(fdp->filename, block_num, version,
			block_path);
	fd = ree_fs_open(block_path, TEE_FS_O_RDONLY);
	if (fd < 0)
		goto exit;

	get_block_filepath(fdp->filename, block_num, !version,
			block_path);
	new_fd = ree_fs_open(block_path, TEE_FS_O_CREATE | TEE_FS_O_RDWR);
	if (new_fd < 0)
		goto exit_close_fd;

	res = ree_fs_ftruncate(new_fd, 0);
	if (res)
		goto exit_close_fd;

	while ((num_read = ree_fs_read(fd, buffer, COPY_BUF_SIZE)) > 0) {
		if (num_read < 0)
			goto exit_close_new_fd;

		if (ree_fs_write(new_fd, buffer, num_read) != num_read)
			goto exit_close_new_fd;
	}

	res = ree_fs_lseek(new_fd, 0, TEE_FS_SEEK_SET);
	if (res != 0)
		return res;

	/*
	 * toggle block version in new meta to indicate
	 * we are currently working on new block file
	 */
	toggle_backup_version_for_block(new_meta, block_num);
	res = new_fd;

exit_close_new_fd:
	if (res < 0)
		ree_fs_close(new_fd);
exit_close_fd:
	ree_fs_close(fd);
exit:
	return res;
}

static int write_one_block(struct block_operation_args *args)
{
	int fd, res, bytes;
	struct tee_fs_fd *fdp = args->fdp;
	int block_num = args->block_num;
	tee_fs_off_t off = args->offset;
	size_t len = args->len;
	const void *buf = args->buf;
	struct tee_fs_file_meta *new_meta = args->extra;

	if (need_to_allocate_new_block(fdp, block_num))
		fd = alloc_block(fdp, block_num);
	else
		/*
		 * Create new version of current block file,
		 * consequent write will happen on new version,
		 * old version is still valid until new file meta
		 * is written.
		 */
		fd = create_new_version_for_block(
				fdp, new_meta, block_num);

	if (fd < 0)
		return fd;

	if (off) {
		res = ree_fs_lseek(fd, off, TEE_FS_SEEK_SET);
		if (res != off)
			return res;
	}

	bytes = ree_fs_write(fd, buf, len);

	ree_fs_close(fd);
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
	uint8_t version =
		get_backup_version_of_block(fdp->meta, block_num);

	get_block_filepath(fdp->filename, block_num, version,
			block_path);
	fd = ree_fs_open(block_path, TEE_FS_O_RDONLY);
	if (fd < 0)
		return fd;

	if (off) {
		res = ree_fs_lseek(fd, off, TEE_FS_SEEK_SET);
		if (res != off)
			return res;
	}

	bytes = ree_fs_read(fd, buf, len);

	ree_fs_close(fd);
	return bytes;
}

static int tee_fs_do_block_operation(struct tee_fs_fd *fdp,
		int (*do_block_ops)(struct block_operation_args *args),
		void *buf, size_t len, void *extra)
{
	int start_block, end_block, num_blocks_to_process;
	int block_num, remain_bytes = len;
	size_t offset_in_block;
	uint8_t *data = buf;

	start_block = pos_to_block_num(fdp->pos);
	end_block = pos_to_block_num(fdp->pos + len - 1);
	num_blocks_to_process = end_block - start_block + 1;
	block_num = start_block;
	offset_in_block = fdp->pos & (FILE_BLOCK_SIZE - 1);

	DMSG("start_block:%d, end_block:%d", start_block, end_block);

	while (num_blocks_to_process) {
		struct block_operation_args args = {
			.fdp = fdp,
			.offset = offset_in_block,
			.block_num = block_num,
			.buf = data,
			.extra = extra,
			.len = (remain_bytes > FILE_BLOCK_SIZE) ?
				FILE_BLOCK_SIZE :
				remain_bytes
		};
		int bytes_consumed = do_block_ops(&args);

		if (bytes_consumed < 0)
			return -1;

		DMSG("block_num: %d, offset: %zu, bytes_consumed: %d",
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

static inline int create_hard_link(const char *old_dir,
			const char *new_dir,
			const char *filename)
{
	char old_path[REE_FS_NAME_MAX];
	char new_path[REE_FS_NAME_MAX];

	snprintf(old_path, REE_FS_NAME_MAX, "%s/%s",
			old_dir, filename);
	snprintf(new_path, REE_FS_NAME_MAX, "%s/%s",
			new_dir, filename);

	DMSG("create hard link %s -> %s", old_path, new_path);
	return ree_fs_link(old_path, new_path);
}


static int unlink_tee_file(const char *file)
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
	int meta_version;
	size_t len;
	struct tee_fs_file_meta *meta;
	struct tee_fs_fd *fdp = NULL;

	DMSG("file=%s", file);

	len = strlen(file) + 1;
	if (len > TEE_FS_NAME_MAX)
		goto exit;

	meta_version = 0;
	meta = tee_fs_meta_open(file, meta_version);
	if (!meta) {
		meta_version = 1;
		meta = tee_fs_meta_open(file, meta_version);

		/* cannot find meta file, assumed file not existed */
		if (!meta) {
			if (flags & TEE_FS_O_CREATE) {
				meta = tee_fs_file_create(file);
				if (!meta)
					return -1;
			} else
				return -1;
		}
	}

	fdp = (struct tee_fs_fd *)malloc(sizeof(struct tee_fs_fd));
	if (!fdp)
		goto exit_free_fd;

	/* init internal status */
	fdp->flags = flags;
	fdp->private = NULL;
	fdp->meta = meta;
	fdp->meta_version = meta_version;
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

/*
 * To ensure atomic ftruncate operation, we can:
 *
 *  - update file length to new length
 *  - commit new meta
 *
 * (Any failure in above steps is considered as update failed,
 *  and the file context will be keepped as is before the update
 *  operation)
 *
 * After previous step the update is considered complete, but
 * we should do the following clean-up step(s):
 *
 *  - free the trucated file blocks
 *
 * (Any failure in above steps is considered as a successfully
 *  update)
 */
int tee_fs_common_ftruncate(struct tee_fs_fd *fdp,
				tee_fs_off_t new_file_len)
{
	int res = -1;
	size_t old_file_len;
	int old_block_num, new_block_num, diff_blocks, i = 0;
	struct tee_fs_file_meta *new_meta;

	if (!fdp)
		goto exit;

	if (fdp->flags & TEE_FS_O_RDONLY)
		goto exit;

	if (new_file_len > (tee_fs_off_t)fdp->meta->info.length)
		goto exit;

	new_meta = create_new_file_meta(fdp);
	if (!new_meta)
		goto exit;

	old_file_len = fdp->meta->info.length;
	old_block_num = pos_to_block_num(old_file_len - 1);
	new_block_num = pos_to_block_num(new_file_len - 1);
	diff_blocks = new_block_num - old_block_num;

	new_meta->info.length = new_file_len;
	DMSG("truncated length=%d", new_file_len);

	res = commit_file_meta(fdp, new_meta);
	if (res < 0)
		goto exit;

	/* now we are safe to free blocks */
	TEE_ASSERT(diff_blocks <= 0);
	while (diff_blocks) {
		res = free_block(fdp, old_block_num - i);
		if (res)
			goto exit;
		i++;
		diff_blocks++;
	}
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

	DMSG("len=%zu", len);

	if (fdp->pos + len > fdp->meta->info.length) {
		len = fdp->meta->info.length - fdp->pos;
		DMSG("reached EOF, update read length to %zu", len);
	}

	res = tee_fs_do_block_operation(fdp, read_one_block,
			buf, len, NULL);
exit:
	return res;
}

/*
 * To ensure atomicity of write operation, we need to
 * do the following steps:
 * (The sequence of operations is very important)
 *
 *  - Create a new backup version of file meta as a copy
 *    of current file meta.
 *  - For each blocks to write:
 *    - Create new backup version for current block.
 *    - Write data to new backup version.
 *    - Update the new file meta accordingly.
 *  - Write the new file meta.
 *
 * (Any failure in above steps is considered as update failed,
 *  and the file context will be keepped as is before the update
 *  operation)
 *
 * After previous step the update is considered complete, but
 * we should do the following clean-up step(s):
 *
 *  - Delete the old file meta.
 *
 * (Any failure in above steps is considered as a successfully
 *  update)
 */
int tee_fs_common_write(struct tee_fs_fd *fdp,
			const void *buf, size_t len)
{
	int res = -1;
	struct tee_fs_file_meta *new_meta;

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

	new_meta = create_new_file_meta(fdp);
	if (!new_meta)
		goto exit;

	DMSG("len=%zu", len);
	res = tee_fs_do_block_operation(fdp, write_one_block,
			(void *)buf, len, new_meta);

	if (res > 0) {
		int r;

		/* update file length if necessary */
		if (fdp->pos > (tee_fs_off_t)new_meta->info.length)
			new_meta->info.length = fdp->pos;

		r = commit_file_meta(fdp, new_meta);
		if (r)
			res = r;
	}

	free(new_meta);
exit:
	return res;
}

/*
 * To ensure atomicity of rename operation, we need to
 * do the following steps:
 *
 *  - Create a new folder that represents the renamed TEE file
 *  - For each REE blocks files, create a hard link under the just
 *    created folder (new TEE file)
 *  - Now we are ready to commit meta, create hard link for the
 *    mata file
 *
 * (Any failure in above steps is considered as update failed,
 *  and the file context will be keepped as is before the update
 *  operation)
 *
 * After previous step the update is considered complete, but
 * we should do the following clean-up step(s):
 *
 *  - Unlink all REE files represents the old TEE file (including
 *    meta and block files)
 *
 * (Any failure in above steps is considered as a successfully
 *  update)
 */
int tee_fs_common_rename(const char *old, const char *new)
{
	int res = -1;
	size_t old_len = strlen(old) + 1;
	size_t new_len = strlen(old) + 1;
	struct tee_fs_dir *old_dir;
	struct tee_fs_dirent *dirent;
	char *meta_filename = NULL;

	DMSG("old=%s, new=%s", old, new);

	if (old_len > TEE_FS_NAME_MAX || new_len >TEE_FS_NAME_MAX)
		goto exit;

	res = ree_fs_mkdir(new,
			TEE_FS_S_IRUSR | TEE_FS_S_IWUSR);
	if (res)
		goto exit;

	old_dir = tee_fs_common_opendir(old);
	if (!old_dir)
		goto exit;

	dirent = tee_fs_common_readdir(old_dir);
	while (dirent) {
		if (!strncmp(dirent->d_name, "meta.", 5)) {
			meta_filename = strdup(dirent->d_name);
		} else {
			res = create_hard_link(old, new, dirent->d_name);
			if (res)
				goto exit_close_old_dir;
		}

		dirent = tee_fs_common_readdir(old_dir);
	}

	/* finally, link the meta file, rename operation completed */
	TEE_ASSERT(meta_filename);
	res = create_hard_link(old, new, meta_filename);
	if (res)
		goto exit_close_old_dir;

	/* we are safe now, remove old TEE file */
	unlink_tee_file(old);

exit_close_old_dir:
	tee_fs_common_closedir(old_dir);
exit:
	free(meta_filename);
	return res;
}

/*
 * To ensure atomic unlink operation, we can simply
 * split the unlink operation into:
 *
 *  - rename("file", "file.trash");
 *
 * (Any failure in above steps is considered as update failed,
 *  and the file context will be keepped as is before the update
 *  operation)
 *
 * After previous step the update is considered complete, but
 * we should do the following clean-up step(s):
 *
 *  - unlink("file.trash");
 *
 * (Any failure in above steps is considered as a successfully
 *  update)
 */
int tee_fs_common_unlink(const char *file)
{
	int res = -1;
	char trash_file[TEE_FS_NAME_MAX + 6];

	snprintf(trash_file, REE_FS_NAME_MAX + 6, "%s.trash",
		file);

	res = tee_fs_common_rename(file, trash_file);
	if (res < 0)
		return res;

	unlink_tee_file(trash_file);

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
