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
	size_t block_num;
	void *buf;
	size_t len;
	void *extra;
};

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

static int ree_fs_access(const char *name, int mode)
{
	int res = -1;
	struct tee_fs_rpc head = { 0 };
	uint32_t len;

	if (!name)
		goto exit;

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

static int get_file_length(int fd, size_t *length)
{
	size_t file_len;
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

static void get_meta_filepath(const char *file, int version,
				char *meta_path)
{
	snprintf(meta_path, REE_FS_NAME_MAX, "%s/meta.%d",
			file, version);
}

static void get_block_filepath(const char *file, size_t block_num,
				int version, char *meta_path)
{
	snprintf(meta_path, REE_FS_NAME_MAX, "%s/block%zu.%d",
			file, block_num, version);
}

static int alloc_block(struct tee_fs_fd *fdp, size_t block_num)
{
	char block_path[REE_FS_NAME_MAX];

	get_block_filepath(fdp->filename, block_num, 0, block_path);
	DMSG("%s", block_path);

	return ree_fs_open(block_path, TEE_FS_O_CREATE | TEE_FS_O_WRONLY);
}

static int free_block(struct tee_fs_fd *fdp, size_t block_num)
{
	char block_path[REE_FS_NAME_MAX];
	uint8_t version =
		get_backup_version_of_block(fdp->meta, block_num);

	get_block_filepath(fdp->filename, block_num, version, block_path);
	DMSG("%s", block_path);

	return ree_fs_unlink(block_path);
}

/*
 * encrypted_fek: as input for META_FILE and BLOCK_FILE
 */
static int encrypt_and_write_file(int fd,
		enum tee_fs_file_type file_type,
		void *data_in, size_t data_in_size,
		uint8_t *encrypted_fek)
{
	TEE_Result tee_res;
	int res = 0;
	int bytes;
	uint8_t *ciphertext;
	size_t header_size = tee_fs_get_header_size(file_type);
	size_t ciphertext_size = header_size + data_in_size;

	ciphertext = malloc(ciphertext_size);
	if (!ciphertext) {
		EMSG("Failed to allocate ciphertext buffer, size=%zd",
				ciphertext_size);
		return -1;
	}

	tee_res = tee_fs_encrypt_file(file_type,
			data_in, data_in_size,
			ciphertext, &ciphertext_size, encrypted_fek);
	if (tee_res != TEE_SUCCESS) {
		EMSG("error code=%x", tee_res);
		res = -1;
		goto fail;
	}

	bytes = ree_fs_write(fd, ciphertext, ciphertext_size);
	if (bytes != (int)ciphertext_size) {
		EMSG("bytes(%d) != ciphertext size(%zu)",
				bytes, ciphertext_size);
		res = -1;
		goto fail;
	}

fail:
	free(ciphertext);

	return res;
}

/*
 * encrypted_fek: as output for META_FILE
 *                as input for BLOCK_FILE
 */
static int read_and_decrypt_file(int fd,
		enum tee_fs_file_type file_type,
		void *data_out, size_t *data_out_size,
		uint8_t *encrypted_fek)
{
	TEE_Result tee_res;
	int res;
	int bytes;
	void *ciphertext = NULL;
	size_t file_size;
	size_t header_size = tee_fs_get_header_size(file_type);

	res = get_file_length(fd, &file_size);
	if (res < 0)
		return res;

	TEE_ASSERT(file_size >= header_size);

	ciphertext = malloc(file_size);
	if (!ciphertext) {
		EMSG("Failed to allocate file data buffer, size=%zd",
				file_size);
		return -1;
	}

	bytes = ree_fs_read(fd, ciphertext, file_size);
	if (bytes != (int)file_size) {
		EMSG("return bytes(%d) != file_size(%zd)",
				bytes, file_size);
		res = -1;
		goto fail;
	}

	tee_res = tee_fs_decrypt_file(file_type,
			ciphertext, file_size,
			data_out, data_out_size,
			encrypted_fek);
	if (tee_res != TEE_SUCCESS) {
		EMSG("Failed to decrypt file, res=0x%x", tee_res);
		res = -1;
	}

fail:
	free(ciphertext);

	return (res < 0) ? res : 0;
}

static struct tee_fs_file_meta *duplicate_meta(
		struct tee_fs_fd *fdp)
{
	struct tee_fs_file_meta *new_meta = NULL;

	new_meta = malloc(sizeof(*new_meta));
	if (!new_meta) {
		EMSG("Failed to allocate memory for new meta");
		goto exit;
	}

	memcpy(new_meta, fdp->meta, sizeof(*new_meta));

exit:
	return new_meta;
}

static int write_meta_file(const char *filename,
		struct tee_fs_file_meta *meta)
{
	int res, fd = -1;
	char meta_path[REE_FS_NAME_MAX];

	get_meta_filepath(filename, meta->backup_version, meta_path);

	fd = ree_fs_open(meta_path, TEE_FS_O_CREATE |
			TEE_FS_O_TRUNC | TEE_FS_O_WRONLY);
	if (fd < 0)
		return -1;

	res = encrypt_and_write_file(fd, META_FILE,
			(void *)&meta->info, sizeof(meta->info),
			meta->encrypted_fek);

	ree_fs_close(fd);
	return res;
}

static struct tee_fs_file_meta *create_meta_file(const char *file)
{
	TEE_Result tee_res;
	struct tee_fs_file_meta *meta = NULL;
	int res;
	const uint8_t default_backup_version = 0;

	meta = malloc(sizeof(struct tee_fs_file_meta));
	if (!meta) {
		EMSG("Failed to allocate memory");
		goto exit;
	}

	memset(&meta->info, 0, sizeof(meta->info));
	tee_res = tee_fs_generate_fek(meta->encrypted_fek, TEE_FS_KM_FEK_SIZE);
	if (tee_res != TEE_SUCCESS)
		goto exit;

	meta->backup_version = default_backup_version;

	res = write_meta_file(file, meta);
	if (res < 0)
		goto exit;

	return meta;

exit:
	free(meta);

	return NULL;
}

static int commit_meta_file(struct tee_fs_fd *fdp,
		struct tee_fs_file_meta *new_meta)
{
	int res;
	uint8_t old_version;
	char meta_path[REE_FS_NAME_MAX];

	old_version = new_meta->backup_version;
	new_meta->backup_version = !new_meta->backup_version;

	res = write_meta_file(fdp->filename, new_meta);

	if (res < 0)
		return res;

	/*
	 * From now on the new meta is successfully committed,
	 * change tee_fs_fd accordingly
	 */
	memcpy(fdp->meta, new_meta, sizeof(*new_meta));

	/*
	 * Remove old meta file, there is nothing we can
	 * do if we fail here, but that is OK because both
	 * new & old version of block files are kept. The context
	 * of the file is still consistent.
	 */
	get_meta_filepath(fdp->filename, old_version, meta_path);
	ree_fs_unlink(meta_path);

	return res;
}

static int read_meta_file(const char *meta_path,
		struct tee_fs_file_meta *meta)
{
	int res, fd;
	size_t meta_info_size = sizeof(struct tee_fs_file_info);

	res = ree_fs_open(meta_path, TEE_FS_O_RDWR);
	if (res < 0)
		return res;

	fd = res;

	res = read_and_decrypt_file(fd, META_FILE,
			(void *)&meta->info, &meta_info_size,
			meta->encrypted_fek);

	ree_fs_close(fd);

	return res;
}

static struct tee_fs_file_meta *open_meta_file(
		const char *file, int version)
{
	int res;
	char meta_path[REE_FS_NAME_MAX];
	struct tee_fs_file_meta *meta = NULL;

	meta = malloc(sizeof(struct tee_fs_file_meta));
	if (!meta)
		return NULL;

	get_meta_filepath(file, version, meta_path);
	res = read_meta_file(meta_path, meta);
	if (res < 0)
		goto exit_free_meta;

	meta->backup_version = version;

	return meta;

exit_free_meta:
	free(meta);
	return NULL;
}

static bool need_to_allocate_new_block(struct tee_fs_fd *fdp,
					size_t block_num)
{
	size_t file_size = fdp->meta->info.length;

	if (file_size == 0)
		return true;

	return block_num > (size_t)get_last_block_num(file_size);
}

#ifdef CFG_ENC_FS
static int read_one_block(struct block_operation_args *args)
{
	int fd, res;
	struct tee_fs_fd *fdp = args->fdp;
	uint8_t *plaintext = NULL;
	char block_path[REE_FS_NAME_MAX];
	size_t block_file_size = FILE_BLOCK_SIZE;
	uint8_t version = get_backup_version_of_block(fdp->meta,
			args->block_num);

	get_block_filepath(fdp->filename, args->block_num, version,
			block_path);

	fd = ree_fs_open(block_path, TEE_FS_O_RDONLY);
	if (fd < 0)
		return fd;

	plaintext = malloc(block_file_size);
	if (!plaintext) {
		EMSG("Failed to allocate plaintext buffer, size=%zd",
				block_file_size);
		res = -1;
		goto fail;
	}

	res = read_and_decrypt_file(fd, BLOCK_FILE,
			plaintext, &block_file_size,
			fdp->meta->encrypted_fek);
	if (res < 0) {
		EMSG("Failed to read and decrypt file");
		goto fail;
	}

	if (args->len == READ_ALL) {
		DMSG("read all");
		args->len = block_file_size;
		args->offset = 0;
	}

	DMSG("offset=%zu, length=%zu, block_file_size=%zu",
			(size_t)args->offset, args->len, block_file_size);

	if ((args->offset + args->len) > block_file_size) {
		EMSG("offset(%zu) + length(%zu) > block file size(%zu)",
				(size_t)args->offset, args->len,
				block_file_size);
		res = -1;
		goto fail;
	}

	memcpy(args->buf, plaintext + args->offset, args->len);

	res = args->len;

fail:
	free(plaintext);
	ree_fs_close(fd);

	return res;
}

static int create_empty_new_version_block(struct tee_fs_fd *fdp,
		struct tee_fs_file_meta *new_meta, int block_num)
{
	int fd;
	int res = -1;
	char block_path[REE_FS_NAME_MAX];
	uint8_t new_version =
		!get_backup_version_of_block(fdp->meta, block_num);

	get_block_filepath(fdp->filename, block_num, new_version,
			block_path);

	fd = ree_fs_open(block_path, TEE_FS_O_CREATE | TEE_FS_O_RDWR);
	if (fd < 0)
		goto exit;

	res = ree_fs_ftruncate(fd, 0);
	if (res < 0)
		goto exit;

	/*
	 * toggle block version in new meta to indicate
	 * we are currently working on new block file
	 */
	toggle_backup_version_of_block(new_meta, block_num);
	res = fd;

exit:
	return res;
}

static int write_one_block(struct block_operation_args *args)
{
	int fd = -1;
	int res;
	struct tee_fs_fd *fdp = args->fdp;
	size_t block_num = args->block_num;
	struct tee_fs_file_meta *new_meta = args->extra;
	uint8_t *plaintext;
	size_t old_file_size, new_file_size;

	DMSG("offset=%zu, length=%zu",
			(size_t)args->offset, args->len);

	if ((args->offset + args->len) > FILE_BLOCK_SIZE) {
		EMSG("offset(%zu) + length(%zu) > FILE_BLOCK_SIZE(%u)",
				(size_t)args->offset, args->len,
				FILE_BLOCK_SIZE);
		return -1;
	}

	plaintext = malloc(FILE_BLOCK_SIZE);
	if (!plaintext) {
		EMSG("Failed to allocate plaintext buffer, size=%d",
				FILE_BLOCK_SIZE);
		res = -1;
		goto fail;
	}

	if (need_to_allocate_new_block(fdp, block_num)) {
		fd = alloc_block(fdp, block_num);
		if (fd < 0) {
			EMSG("Failed to allocate block");
			res = -1;
			goto fail;
		}
		old_file_size = 0;
	} else {
		struct block_operation_args read_op_args = {
			.fdp = fdp,
			.block_num = args->block_num,
			.buf = plaintext,
			.extra = NULL,
			.len = READ_ALL
		};

		res = read_one_block(&read_op_args);
		if (res < 0) {
			EMSG("Failed to read block");
			goto fail;
		}

		old_file_size = read_op_args.len;

		fd = create_empty_new_version_block(
				fdp, new_meta, block_num);
		if (fd < 0) {
			EMSG("Failed to create new version of block");
			res = -1;
			goto fail;
		}
	}

	memcpy(plaintext + args->offset, args->buf, args->len);

	if ((args->offset + args->len) > old_file_size)
		new_file_size = args->offset + args->len;
	else
		new_file_size = old_file_size;

	res = encrypt_and_write_file(fd, BLOCK_FILE,
			plaintext, new_file_size,
			new_meta->encrypted_fek);
	if (res < 0) {
		EMSG("Failed to encrypt and write block file");
		goto fail;
	}

	res = args->len;

fail:
	free(plaintext);

	if (fd > 0)
		ree_fs_close(fd);

	return res;
}
#else
static int create_new_version_block(struct tee_fs_fd *fdp,
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
	toggle_backup_version_of_block(new_meta, block_num);
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
		fd = create_new_version_block(
				fdp, new_meta, block_num);

	if (fd < 0) {
		EMSG("fd < 0");
		return fd;
	}

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
#endif

static inline size_t fix_block_ops_length(size_t offset, size_t len)
{
	return (len + offset > FILE_BLOCK_SIZE) ?
			FILE_BLOCK_SIZE - offset : len;
}

static int tee_fs_do_multi_blocks_transfer(struct tee_fs_fd *fdp,
		int (*do_block_ops)(struct block_operation_args *args),
		void *buf, size_t len, void *extra)
{
	int start_block, end_block, num_blocks_to_process;
	size_t block_num, remain_bytes = len;
	size_t offset_in_block;
	uint8_t *data = buf;

	start_block = pos_to_block_num(fdp->pos);
	end_block = pos_to_block_num(fdp->pos + len - 1);
	num_blocks_to_process = end_block - start_block + 1;
	block_num = start_block;
	offset_in_block = fdp->pos & (FILE_BLOCK_SIZE - 1);

	DMSG("start_block:%d, end_block:%d, len:%zu",
			start_block, end_block, len);

	while (num_blocks_to_process) {
		struct block_operation_args args = {
			.fdp = fdp,
			.offset = offset_in_block,
			.block_num = block_num,
			.buf = data,
			.extra = extra,
			.len = fix_block_ops_length(offset_in_block,
					remain_bytes)
		};
		int bytes_consumed = do_block_ops(&args);

		if (bytes_consumed < 0)
			return -1;

		if (args.len != (size_t)bytes_consumed) {
			EMSG("consumed doesn't match requested(%d, %zu)",
				bytes_consumed, args.len);
			return -1;
		}

		DMSG("block_num: %zu, offset: %zu, bytes_consumed: %d",
			block_num, offset_in_block, bytes_consumed);

		TEE_ASSERT(remain_bytes >= (size_t)bytes_consumed);

		data += bytes_consumed;
		remain_bytes -= bytes_consumed;
		block_num++;
		num_blocks_to_process--;

		/* only the first block needs block offset */
		if (offset_in_block)
			offset_in_block = 0;
	}

	fdp->pos += len;

	return 0;
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
		if (res) {
			tee_fs_common_closedir(dir);
			goto exit;
		}

		dirent = tee_fs_common_readdir(dir);
	}

	res = tee_fs_common_closedir(dir);
	if (res)
		goto exit;

	res = tee_fs_common_rmdir(file);
exit:
	return res;
}

static bool is_tee_file_exist(const char *file)
{
	return !ree_fs_access(file, TEE_FS_F_OK);
}

static struct tee_fs_file_meta *create_tee_file(const char *file)
{
	struct tee_fs_file_meta *meta = NULL;
	int res;

	DMSG("Creating TEE file=%s", file);

	/* create TEE file directory */
	res = ree_fs_mkdir(file,
			TEE_FS_S_IRUSR | TEE_FS_S_IWUSR);
	if (res) {
		EMSG("Failed to create TEE file directory, filename=%s",
				file);
		goto exit;
	}

	/* create meta file in TEE file directory */
	meta = create_meta_file(file);
	if (!meta)
		EMSG("Failed to create new meta file");

exit:
	return meta;
}

static struct tee_fs_file_meta *open_tee_file(const char *file)
{
	struct tee_fs_file_meta *meta = NULL;
	int backup_version = 0;

	DMSG("Opening TEE file=%s", file);

	meta = open_meta_file(file, backup_version);
	if (!meta) {
		meta = open_meta_file(file, !backup_version);
		if (!meta) {
			/*
			 * cannot open meta file, assumed the TEE file
			 * is corrupted
			 */
			EMSG("Can not open meta file");
		}
	}

	return meta;
}

struct tee_fs_fd *tee_fs_fd_lookup(int fd)
{
	return handle_lookup(&fs_handle_db, fd);
}

int tee_fs_common_open(TEE_Result *errno, const char *file, int flags, ...)
{
	int res = -1;
	size_t len;
	struct tee_fs_file_meta *meta = NULL;
	struct tee_fs_fd *fdp = NULL;
	bool file_exist;

	assert(errno != NULL);
	*errno = TEE_SUCCESS;

	if (!file) {
		*errno = TEE_ERROR_BAD_PARAMETERS;
		goto exit;
	}

	len = strlen(file) + 1;
	if (len > TEE_FS_NAME_MAX) {
		*errno = TEE_ERROR_BAD_PARAMETERS;
		goto exit;
	}

	file_exist = is_tee_file_exist(file);
	if (flags & TEE_FS_O_CREATE) {
		if ((flags & TEE_FS_O_EXCL) && file_exist) {
			EMSG("tee file already exists");
			*errno = TEE_ERROR_ACCESS_CONFLICT;
			goto exit;
		}

		if (!file_exist)
			meta = create_tee_file(file);
		else
			meta = open_tee_file(file);

	} else {
		if (!file_exist) {
			EMSG("tee file not exists");
			*errno = TEE_ERROR_ITEM_NOT_FOUND;
			goto exit;
		}

		meta = open_tee_file(file);
	}

	if (!meta) {
		EMSG("Failed to open TEE file");
		*errno = TEE_ERROR_CORRUPT_OBJECT;
		goto exit;
	}

	fdp = (struct tee_fs_fd *)malloc(sizeof(struct tee_fs_fd));
	if (!fdp) {
		*errno = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_free_fd;
	}

	/* init internal status */
	fdp->flags = flags;
	fdp->private = NULL;
	fdp->meta = meta;
	fdp->pos = 0;
	fdp->filename = malloc(len);
	if (!fdp->filename) {
		res = -1;
		*errno = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_free_fd;
	}
	memcpy(fdp->filename, file, len);

	if ((flags & TEE_FS_O_TRUNC) &&
		(flags & TEE_FS_O_WRONLY || flags & TEE_FS_O_RDWR)) {
		res = tee_fs_common_ftruncate(errno, fdp, 0);
		if (res < 0) {
			EMSG("Unable to truncate file");
			goto exit_free_fd;
		}
	}

	/* return fd */
	res = handle_get(&fs_handle_db, fdp);
	fdp->fd = res;

exit_free_fd:
	if (res < 0) {
		free(meta);
		if (fdp) {
			free(fdp->filename);
			free(fdp);
		}
	}
exit:
	return res;
}

int tee_fs_common_close(struct tee_fs_fd *fdp)
{
	int res = -1;

	if (!fdp)
		return -1;

	handle_put(&fs_handle_db, fdp->fd);

	free(fdp->private);
	free(fdp->meta);
	free(fdp->filename);
	free(fdp);

	return res;
}

tee_fs_off_t tee_fs_common_lseek(TEE_Result *errno, struct tee_fs_fd *fdp,
				tee_fs_off_t offset, int whence)
{
	tee_fs_off_t res = -1;
	tee_fs_off_t new_pos;
	size_t filelen;

	assert(errno != NULL);
	*errno = TEE_SUCCESS;

	if (!fdp) {
		*errno = TEE_ERROR_BAD_PARAMETERS;
		goto exit;
	}

	DMSG("offset=%d, whence=%d", (int)offset, whence);

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
		*errno = TEE_ERROR_BAD_PARAMETERS;
		goto exit;
	}

	if (new_pos < 0)
		new_pos = 0;

	if (new_pos > TEE_DATA_MAX_POSITION) {
		EMSG("Position is beyond TEE_DATA_MAX_POSITION");
		*errno = TEE_ERROR_BAD_PARAMETERS;
		goto exit;
	}

	res = fdp->pos = new_pos;
exit:
	return res;
}

/*
 * To ensure atomic truncate operation, we can:
 *
 *  - update file length to new length
 *  - commit new meta
 *  - free unused blocks
 *
 * To ensure atomic extend operation, we can:
 *
 *  - update file length to new length
 *  - allocate and fill zero data to new blocks
 *  - commit new meta
 *
 * Any failure before committing new meta is considered as
 * update failed, and the file content will not be updated
 *
 */
int tee_fs_common_ftruncate(TEE_Result *errno, struct tee_fs_fd *fdp,
				tee_fs_off_t new_file_len)
{
	int res = -1;
	size_t old_file_len = fdp->meta->info.length;
	struct tee_fs_file_meta *new_meta = NULL;
	uint8_t *buf = NULL;

	assert(errno != NULL);
	*errno = TEE_SUCCESS;

	if (!fdp) {
		*errno = TEE_ERROR_BAD_PARAMETERS;
		res = -1;
		goto exit;
	}

	if (fdp->flags & TEE_FS_O_RDONLY) {
		*errno = TEE_ERROR_BAD_PARAMETERS;
		EMSG("Read only");
		res = -1;
		goto exit;
	}

	if ((size_t)new_file_len == old_file_len) {
		DMSG("Ignore due to file length does not changed");
		res = 0;
		goto exit;
	}

	if (new_file_len > MAX_FILE_SIZE) {
		*errno = TEE_ERROR_BAD_PARAMETERS;
		EMSG("Over maximum file size(%d)", MAX_FILE_SIZE);
		res = -1;
		goto exit;
	}

	new_meta = duplicate_meta(fdp);
	if (!new_meta) {
		*errno = TEE_ERROR_OUT_OF_MEMORY;
		res = -1;
		goto free;
	}

	new_meta->info.length = new_file_len;

	if ((size_t)new_file_len < old_file_len) {
		int old_block_num = get_last_block_num(old_file_len);
		int new_block_num = get_last_block_num(new_file_len);

		DMSG("Truncate file length to %zu", (size_t)new_file_len);

		res = commit_meta_file(fdp, new_meta);
		if (res < 0) {
			*errno = TEE_ERROR_CORRUPT_OBJECT;
			EMSG("Failed to commit meta file");
			goto free;
		}

		/* now we are safe to free unused blocks */
		while (old_block_num > new_block_num) {
			if (free_block(fdp, old_block_num)) {
				IMSG("Warning: Failed to free block: %d",
						old_block_num);
			}

			old_block_num--;
		}

	} else {
		size_t ext_len = new_file_len - old_file_len;
		int orig_pos = fdp->pos;

		buf = malloc(FILE_BLOCK_SIZE);
		if (!buf) {
			*errno = TEE_ERROR_OUT_OF_MEMORY;
			EMSG("Failed to allocate buffer, size=%d",
					FILE_BLOCK_SIZE);
			res = -1;
			goto free;
		}

		memset(buf, 0x0, FILE_BLOCK_SIZE);

		DMSG("Extend file length to %zu", (size_t)new_file_len);

		fdp->pos = old_file_len;

		res = 0;
		while (ext_len > 0) {
			size_t data_len = (ext_len > FILE_BLOCK_SIZE) ?
					FILE_BLOCK_SIZE : ext_len;

			DMSG("fill len=%zu", data_len);
			res = tee_fs_do_multi_blocks_transfer(fdp,
					write_one_block, (void *)buf,
					data_len, new_meta);
			if (res < 0) {
				*errno = TEE_ERROR_CORRUPT_OBJECT;
				EMSG("Failed to fill data");
				break;
			}

			ext_len -= data_len;
		}

		fdp->pos = orig_pos;

		if (res == 0) {
			res = commit_meta_file(fdp, new_meta);
			if (res < 0) {
				*errno = TEE_ERROR_CORRUPT_OBJECT;
				EMSG("Failed to commit meta file");
			}
		}
	}

free:
	free(new_meta);
	free(buf);

exit:
	return res;
}

int tee_fs_common_read(TEE_Result *errno, struct tee_fs_fd *fdp,
		       void *buf, size_t len)
{
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

	if (fdp->flags & TEE_FS_O_WRONLY) {
		*errno = TEE_ERROR_ACCESS_CONFLICT;
		goto exit;
	}

	DMSG("len=%zu", len);

	if (fdp->pos + len > fdp->meta->info.length) {
		len = fdp->meta->info.length - fdp->pos;
		DMSG("reached EOF, update read length to %zu", len);
	}

	res = tee_fs_do_multi_blocks_transfer(fdp, read_one_block,
			buf, len, NULL);
	if (res < 0)
		*errno = TEE_ERROR_CORRUPT_OBJECT;
exit:
	return (res < 0) ? res : (int)len;
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
 *  and the file content will not be updated)
 *
 * After previous step the update is considered complete, but
 * we should do the following clean-up step(s):
 *
 *  - Delete the old file meta.
 *
 * (Any failure in above steps is considered as a successfully
 *  update)
 */
int tee_fs_common_write(TEE_Result *errno, struct tee_fs_fd *fdp,
			const void *buf, size_t len)
{
	int res = -1;
	struct tee_fs_file_meta *new_meta = NULL;
	size_t file_size = fdp->meta->info.length;

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

	if (fdp->flags & TEE_FS_O_RDONLY) {
		EMSG("Write to a read-only file, denied");
		*errno = TEE_ERROR_ACCESS_CONFLICT;
		goto exit;
	}

	if ((fdp->pos + len) > MAX_FILE_SIZE) {
		EMSG("Over maximum file size(%d)", MAX_FILE_SIZE);
		*errno = TEE_ERROR_BAD_PARAMETERS;
		goto exit;
	}

	DMSG("data len=%zu", len);

	if (file_size < (size_t)fdp->pos) {
		DMSG("File hole detected, try to extend file size");
		res = tee_fs_common_ftruncate(errno, fdp, fdp->pos);
		if (res < 0)
			goto exit;
	}

	new_meta = duplicate_meta(fdp);
	if (!new_meta) {
		*errno = TEE_ERROR_OUT_OF_MEMORY;
		goto exit;
	}

	res = tee_fs_do_multi_blocks_transfer(fdp, write_one_block,
			(void *)buf, len, new_meta);

	if (res < 0) {
		*errno = TEE_ERROR_CORRUPT_OBJECT;
		goto exit;
	} else {
		int r;

		/* update file length if necessary */
		if (fdp->pos > (tee_fs_off_t)new_meta->info.length)
			new_meta->info.length = fdp->pos;

		r = commit_meta_file(fdp, new_meta);
		if (r < 0) {
			*errno = TEE_ERROR_CORRUPT_OBJECT;
			res = -1;
		}
	}

exit:
	free(new_meta);
	return (res < 0) ? res : (int)len;
}

/*
 * To ensure atomicity of rename operation, we need to
 * do the following steps:
 *
 *  - Create a new folder that represents the renamed TEE file
 *  - For each REE block files, create a hard link under the just
 *    created folder (new TEE file)
 *  - Now we are ready to commit meta, create hard link for the
 *    meta file
 *
 * (Any failure in above steps is considered as update failed,
 *  and the file content will not be updated)
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
	size_t old_len;
	size_t new_len;
	size_t meta_count = 0;
	struct tee_fs_dir *old_dir;
	struct tee_fs_dirent *dirent;
	char *meta_filename = NULL;

	if (!old || !new)
		return -1;

	DMSG("old=%s, new=%s", old, new);

	old_len = strlen(old) + 1;
	new_len = strlen(new) + 1;

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
			meta_count++;
		} else {
			res = create_hard_link(old, new, dirent->d_name);
			if (res)
				goto exit_close_old_dir;
		}

		dirent = tee_fs_common_readdir(old_dir);
	}

	/* finally, link the meta file, rename operation completed */
	TEE_ASSERT(meta_filename);

	/*
	 * TODO: This will cause memory leakage at previous strdup()
	 * if we accidently have two meta files in a TEE file.
	 *
	 * It's not easy to handle the case above (e.g. Which meta file
	 * should be linked first? What to do if a power cut happened
	 * during creating links for the two meta files?)
	 *
	 * We will solve this issue using another approach: merging
	 * both meta and block files into a single REE file. This approach
	 * can completely remove tee_fs_common_rename(). We can simply
	 * rename TEE file using REE rename() system call, which is also
	 * atomic.
	 */
	if (meta_count > 1)
		EMSG("Warning: more than one meta file in your TEE file\n"
		     "This will cause memory leakage.");

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
 *  and the file content will not be updated)
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

	if (!file)
		return -1;

	snprintf(trash_file, TEE_FS_NAME_MAX + 6, "%s.trash",
		file);

	res = tee_fs_common_rename(file, trash_file);
	if (res < 0)
		return res;

	unlink_tee_file(trash_file);

	return res;
}

int tee_fs_common_mkdir(const char *path, tee_fs_mode_t mode)
{
	return ree_fs_mkdir(path, mode);
}

tee_fs_dir *tee_fs_common_opendir(const char *name)
{
	return ree_fs_opendir(name);
}

int tee_fs_common_closedir(tee_fs_dir *d)
{
	return ree_fs_closedir(d);
}

struct tee_fs_dirent *tee_fs_common_readdir(tee_fs_dir *d)
{
	return ree_fs_readdir(d);
}

int tee_fs_common_rmdir(const char *name)
{
	return ree_fs_rmdir(name);
}

int tee_fs_common_access(const char *name, int mode)
{
	return ree_fs_access(name, mode);
}
