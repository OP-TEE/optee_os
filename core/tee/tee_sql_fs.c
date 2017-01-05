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

/*
 * This file implements the tee_file_operations structure for a secure
 * filesystem based on an SQLite database in normal world.
 * The atomicity of each operation is ensured by using SQL transactions.
 * The main purpose of the code below is to perform block encryption and
 * authentication of the file data, and properly handle seeking through the
 * file. One file (in the sense of struct tee_file_operations) maps to one
 * file in the SQL filesystem, and has the following structure:
 *
 * [       File meta-data       ][      Block #0        ][Block #1]...
 * [meta_header|sql_fs_file_meta][block_header|user data][        ]...
 *
 * meta_header and block_header are defined in tee_fs_key_manager.h.
 */

#include <assert.h>
#include <kernel/mutex.h>
#include <optee_msg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string_ext.h>
#include <sys/queue.h>
#include <tee/tee_cryp_provider.h>
#include <tee/tee_fs.h>
#include <tee/tee_fs_defs.h>
#include <tee/tee_fs_key_manager.h>
#include <tee/tee_fs_rpc.h>
#include <trace.h>
#include <utee_defines.h>
#include <util.h>

/* Block size for encryption */
#define BLOCK_SHIFT 12
#define BLOCK_SIZE (1 << BLOCK_SHIFT)

struct sql_fs_file_meta {
	size_t length;
};

/* File descriptor */
struct sql_fs_fd {
	struct sql_fs_file_meta meta;
	uint8_t encrypted_fek[TEE_FS_KM_FEK_SIZE];
	tee_fs_off_t pos;
	int fd; /* returned by normal world */
	int flags; /* open flags */
};

struct tee_fs_dir {
	int nw_dir;
	struct tee_fs_dirent d;
};

static struct mutex sql_fs_mutex = MUTEX_INITIALIZER;

/*
 * Interface with tee-supplicant
 */

static TEE_Result sql_fs_begin_transaction_rpc(void)
{
	return tee_fs_rpc_begin_transaction(OPTEE_MSG_RPC_CMD_SQL_FS);
}

static TEE_Result sql_fs_end_transaction_rpc(bool rollback)
{
	return tee_fs_rpc_end_transaction(OPTEE_MSG_RPC_CMD_SQL_FS,
					     rollback);
}

static TEE_Result sql_fs_opendir_rpc(const char *name, struct tee_fs_dir **d)
{
	return tee_fs_rpc_opendir(OPTEE_MSG_RPC_CMD_SQL_FS, name, d);
}

static TEE_Result sql_fs_readdir_rpc(struct tee_fs_dir *d,
				     struct tee_fs_dirent **ent)
{
	return tee_fs_rpc_readdir(OPTEE_MSG_RPC_CMD_SQL_FS, d, ent);
}

static TEE_Result sql_fs_remove_rpc(const char *file)
{
	return tee_fs_rpc_remove(OPTEE_MSG_RPC_CMD_SQL_FS, file);
}

static TEE_Result sql_fs_rename_rpc(const char *old, const char *nw,
				    bool overwrite)
{
	return tee_fs_rpc_rename(OPTEE_MSG_RPC_CMD_SQL_FS, old, nw, overwrite);
}

static void sql_fs_closedir_rpc(struct tee_fs_dir *d)
{
	if (d)
		tee_fs_rpc_closedir(OPTEE_MSG_RPC_CMD_SQL_FS, d);
}

/*
 * End of interface with tee-supplicant
 */

static size_t meta_size(void)
{
	return tee_fs_get_header_size(META_FILE) +
	       sizeof(struct sql_fs_file_meta);
}

static size_t block_header_size(void)
{
	return tee_fs_get_header_size(BLOCK_FILE);
}

static size_t block_size_raw(void)
{
	return block_header_size() + BLOCK_SIZE;
}

/* Return the block number from a position in the user data */
static ssize_t block_num(tee_fs_off_t pos)
{
	return pos / BLOCK_SIZE;
}

/* Return the position of a block in the DB file */
static ssize_t block_pos_raw(size_t block_num)
{
	return meta_size() + block_num * block_size_raw();
}

static TEE_Result write_meta(struct sql_fs_fd *fdp)
{
	TEE_Result res;
	size_t ct_size = meta_size();
	void *ct;
	struct tee_fs_rpc_operation op;

	res = tee_fs_rpc_write_init(&op, OPTEE_MSG_RPC_CMD_SQL_FS, fdp->fd, 0,
				    ct_size, &ct);
	if (res != TEE_SUCCESS)
		return res;


	res = tee_fs_encrypt_file(META_FILE,
				  (const uint8_t *)&fdp->meta,
				  sizeof(fdp->meta), ct, &ct_size,
				  fdp->encrypted_fek);
	if (res != TEE_SUCCESS)
		return res;

	return tee_fs_rpc_write_final(&op);
}

static TEE_Result create_meta(struct sql_fs_fd *fdp, const char *fname)
{
	TEE_Result res;

	memset(&fdp->meta, 0, sizeof(fdp->meta));

	res = tee_fs_generate_fek(fdp->encrypted_fek, TEE_FS_KM_FEK_SIZE);
	if (res != TEE_SUCCESS)
		return res;

	res = tee_fs_rpc_create(OPTEE_MSG_RPC_CMD_SQL_FS, fname, &fdp->fd);
	if (res != TEE_SUCCESS)
		return res;

	return write_meta(fdp);
}

static TEE_Result read_meta(struct sql_fs_fd *fdp, const char *fname)
{
	TEE_Result res;
	size_t msize = meta_size();
	size_t out_size = sizeof(fdp->meta);
	void *meta;
	size_t bytes;
	struct tee_fs_rpc_operation op;

	res = tee_fs_rpc_open(OPTEE_MSG_RPC_CMD_SQL_FS, fname, &fdp->fd);
	if (res != TEE_SUCCESS)
		return res;

	res = tee_fs_rpc_read_init(&op, OPTEE_MSG_RPC_CMD_SQL_FS, fdp->fd, 0,
				   msize, &meta);
	if (res != TEE_SUCCESS)
		return res;

	res = tee_fs_rpc_read_final(&op, &bytes);
	if (res != TEE_SUCCESS)
		return res;

	return tee_fs_decrypt_file(META_FILE, meta, msize,
				   (uint8_t *)&fdp->meta, &out_size,
				   fdp->encrypted_fek);
}

/*
 * Read one block of user data.
 * Returns:
 *  < 0: read error
 *    0: block does not exist (reading past last block)
 *  > 0: success
 */
static TEE_Result read_block(struct sql_fs_fd *fdp, size_t bnum, uint8_t *data)
{
	TEE_Result res;
	size_t ct_size = block_size_raw();
	size_t out_size = BLOCK_SIZE;
	ssize_t pos = block_pos_raw(bnum);
	size_t bytes;
	void *ct;
	struct tee_fs_rpc_operation op;

	res = tee_fs_rpc_read_init(&op, OPTEE_MSG_RPC_CMD_SQL_FS, fdp->fd, pos,
				   ct_size, &ct);
	if (res != TEE_SUCCESS)
		return res;
	res = tee_fs_rpc_read_final(&op, &bytes);
	if (res != TEE_SUCCESS)
		return res;
	if (!bytes)
		return TEE_SUCCESS; /* Block does not exist */

	return tee_fs_decrypt_file(BLOCK_FILE, ct, bytes, data,
				   &out_size, fdp->encrypted_fek);
}

/* Write one block of user data */
static TEE_Result write_block(struct sql_fs_fd *fdp, size_t bnum, uint8_t *data)
{
	TEE_Result res;
	size_t ct_size = block_size_raw();
	ssize_t pos = block_pos_raw(bnum);
	void *ct;
	struct tee_fs_rpc_operation op;

	res = tee_fs_rpc_write_init(&op, OPTEE_MSG_RPC_CMD_SQL_FS, fdp->fd, pos,
				    ct_size, &ct);
	if (res != TEE_SUCCESS)
		return res;

	res = tee_fs_encrypt_file(BLOCK_FILE, data, BLOCK_SIZE, ct,
				  &ct_size, fdp->encrypted_fek);
	if (res != TEE_SUCCESS)
		return res;

	return tee_fs_rpc_write_final(&op);
}

/*
 * Partial write (< BLOCK_SIZE) into a block: read/update/write
 * To save memory, passing data == NULL is equivalent to passing a buffer
 * filled with zeroes.
 */
static TEE_Result write_block_partial(struct sql_fs_fd *fdp, size_t bnum,
				      const uint8_t *data, size_t len,
				      size_t offset)
{
	TEE_Result res;
	size_t buf_size = BLOCK_SIZE;
	uint8_t *buf = NULL;

	if ((offset >= buf_size) || (offset + len > buf_size))
		return TEE_ERROR_BAD_PARAMETERS;

	buf = malloc(buf_size);
	if (!buf)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = read_block(fdp, bnum, buf);
	if (res != TEE_SUCCESS)
		goto exit;

	if (data)
		memcpy(buf + offset, data, len);
	else
		memset(buf + offset, 0, len);

	res = write_block(fdp, bnum, buf);
exit:
	free(buf);
	return res;
}

static TEE_Result sql_fs_ftruncate_internal(struct sql_fs_fd *fdp,
					    tee_fs_off_t new_length)
{
	TEE_Result res;
	tee_fs_off_t old_length;

	old_length = (tee_fs_off_t)fdp->meta.length;

	if (new_length == old_length)
		return TEE_SUCCESS;

	sql_fs_begin_transaction_rpc();

	if (new_length < old_length) {
		/* Trim unused blocks */
		int old_last_block = block_num(old_length);
		int last_block = block_num(new_length);
		tee_fs_off_t off;

		if (last_block < old_last_block) {
			off = block_pos_raw(last_block);
			res = tee_fs_rpc_truncate(OPTEE_MSG_RPC_CMD_SQL_FS,
						  fdp->fd, off);
			if (res != TEE_SUCCESS)
				goto exit;
		}
	} else {
		/* Extend file with zeroes */
		tee_fs_off_t off = old_length % BLOCK_SIZE;
		size_t bnum = block_num(old_length);
		size_t end_bnum = block_num(new_length);

		while (bnum <= end_bnum) {
			size_t len = (size_t)BLOCK_SIZE - (size_t)off;

			res = write_block_partial(fdp, bnum, NULL, len, off);
			if (res != TEE_SUCCESS)
				goto exit;
			off = 0;
			bnum++;
		}
	}

	fdp->meta.length = new_length;
	res = write_meta(fdp);
exit:
	sql_fs_end_transaction_rpc(res != TEE_SUCCESS);
	return res;
}

static TEE_Result sql_fs_seek(struct tee_file_handle *fh, int32_t offset,
			      TEE_Whence whence, int32_t *new_offs)
{
	TEE_Result res;
	struct sql_fs_fd *fdp = (struct sql_fs_fd *)fh;
	tee_fs_off_t pos;

	mutex_lock(&sql_fs_mutex);

	switch (whence) {
	case TEE_DATA_SEEK_SET:
		pos = offset;
		break;

	case TEE_DATA_SEEK_CUR:
		pos = fdp->pos + offset;
		break;

	case TEE_DATA_SEEK_END:
		pos = fdp->meta.length + offset;
		break;

	default:
		res = TEE_ERROR_BAD_PARAMETERS;
		goto exit_ret;
	}

	if (pos > TEE_DATA_MAX_POSITION) {
		EMSG("Position is beyond TEE_DATA_MAX_POSITION");
		res = TEE_ERROR_BAD_PARAMETERS;
		goto exit_ret;
	}

	if (pos < 0)
		pos = 0;

	fdp->pos = pos;
	if (new_offs)
		*new_offs = pos;
	res = TEE_SUCCESS;
exit_ret:
	mutex_unlock(&sql_fs_mutex);
	return res;
}

static void sql_fs_close(struct tee_file_handle **fh)
{
	struct sql_fs_fd *fdp = (struct sql_fs_fd *)*fh;

	if (fdp) {
	tee_fs_rpc_close(OPTEE_MSG_RPC_CMD_SQL_FS, fdp->fd);
		free(fdp);
		*fh = NULL;
	}
}

static TEE_Result open_internal(const char *file, bool create,
				struct tee_file_handle **fh)
{
	TEE_Result res;
	struct sql_fs_fd *fdp;
	bool created = false;

	fdp = calloc(1, sizeof(*fdp));
	if (!fdp)
		return TEE_ERROR_OUT_OF_MEMORY;
	fdp->fd = -1;

	mutex_lock(&sql_fs_mutex);

	if (create)
		res = create_meta(fdp, file);
	else
		res = read_meta(fdp, file);

	if (res == TEE_SUCCESS) {
		*fh = (struct tee_file_handle *)fdp;
	} else {
		if (fdp && fdp->fd != -1)
			tee_fs_rpc_close(OPTEE_MSG_RPC_CMD_SQL_FS, fdp->fd);
		if (created)
			tee_fs_rpc_remove(OPTEE_MSG_RPC_CMD_SQL_FS, file);
		free(fdp);
	}
	mutex_unlock(&sql_fs_mutex);
	return res;
}

static TEE_Result sql_fs_open(const char *file, struct tee_file_handle **fh)
{
	return open_internal(file, false, fh);
}

static TEE_Result sql_fs_create(const char *file, struct tee_file_handle **fh)
{
	return open_internal(file, true, fh);
}


static TEE_Result sql_fs_read(struct tee_file_handle *fh, void *buf,
			      size_t *len)
{
	TEE_Result res;
	struct sql_fs_fd *fdp = (struct sql_fs_fd *)fh;
	size_t remain_bytes = *len;
	uint8_t *data_ptr = buf;
	uint8_t *block = NULL;
	int start_block_num;
	int end_block_num;

	mutex_lock(&sql_fs_mutex);

	if ((fdp->pos + remain_bytes) < remain_bytes ||
	    fdp->pos > (tee_fs_off_t)fdp->meta.length)
		remain_bytes = 0;
	else if (fdp->pos + remain_bytes > fdp->meta.length)
		remain_bytes = fdp->meta.length - fdp->pos;

	*len = remain_bytes;

	if (!remain_bytes) {
		res = TEE_SUCCESS;
		goto exit;
	}

	start_block_num = block_num(fdp->pos);
	end_block_num = block_num(fdp->pos + remain_bytes - 1);

	block = malloc(BLOCK_SIZE);
	if (!block) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto exit;
	}

	while (start_block_num <= end_block_num) {
		tee_fs_off_t offset = fdp->pos % BLOCK_SIZE;
		size_t size_to_read = MIN(remain_bytes, (size_t)BLOCK_SIZE);

		if (size_to_read + offset > BLOCK_SIZE)
			size_to_read = BLOCK_SIZE - offset;

		/*
		 * REVISIT: implement read_block_partial() since we have
		 * write_block_partial()?
		 */
		res = read_block(fdp, start_block_num, block);
		if (res != TEE_SUCCESS)
			goto exit;

		memcpy(data_ptr, block + offset, size_to_read);

		data_ptr += size_to_read;
		remain_bytes -= size_to_read;
		fdp->pos += size_to_read;

		start_block_num++;
	}
	res = TEE_SUCCESS;
exit:
	free(block);
	mutex_unlock(&sql_fs_mutex);
	return res;
}

static TEE_Result sql_fs_write(struct tee_file_handle *fh, const void *buf,
			       size_t len)
{
	TEE_Result res;
	struct sql_fs_fd *fdp = (struct sql_fs_fd *)fh;
	size_t remain_bytes = len;
	const uint8_t *data_ptr = buf;
	int start_block_num;
	int end_block_num;

	if (!len)
		return TEE_SUCCESS;

	mutex_lock(&sql_fs_mutex);

	sql_fs_begin_transaction_rpc();

	if (fdp->meta.length < (size_t)fdp->pos) {
		/* Fill hole */
		res = sql_fs_ftruncate_internal(fdp, fdp->pos);
		if (res != TEE_SUCCESS)
			goto exit;
	}

	start_block_num = block_num(fdp->pos);
	end_block_num = block_num(fdp->pos + len - 1);

	while (start_block_num <= end_block_num) {
		tee_fs_off_t offset = fdp->pos % BLOCK_SIZE;
		size_t size_to_write = MIN(remain_bytes, (size_t)BLOCK_SIZE);

		if (size_to_write + offset > BLOCK_SIZE)
			size_to_write = BLOCK_SIZE - offset;

		res = write_block_partial(fdp, start_block_num, data_ptr,
					  size_to_write, offset);
		if (res != TEE_SUCCESS)
			goto exit;

		data_ptr += size_to_write;
		remain_bytes -= size_to_write;
		fdp->pos += size_to_write;

		start_block_num++;
	}

	if (fdp->meta.length < (size_t)fdp->pos) {
		fdp->meta.length = fdp->pos;
		res = write_meta(fdp);
	}
exit:
	sql_fs_end_transaction_rpc(res != TEE_SUCCESS);
	mutex_unlock(&sql_fs_mutex);
	return res;
}

static TEE_Result sql_fs_truncate(struct tee_file_handle *fh, size_t len)
{
	TEE_Result res;
	struct sql_fs_fd *fdp = (struct sql_fs_fd *)fh;

	mutex_lock(&sql_fs_mutex);
	res = sql_fs_ftruncate_internal(fdp, len);
	mutex_unlock(&sql_fs_mutex);

	return res;
}

const struct tee_file_operations sql_fs_ops = {
	.open = sql_fs_open,
	.create = sql_fs_create,
	.close = sql_fs_close,
	.read = sql_fs_read,
	.write = sql_fs_write,
	.seek = sql_fs_seek,
	.truncate = sql_fs_truncate,

	.opendir = sql_fs_opendir_rpc,
	.closedir = sql_fs_closedir_rpc,
	.readdir = sql_fs_readdir_rpc,
	.rename = sql_fs_rename_rpc,
	.remove = sql_fs_remove_rpc,
};
