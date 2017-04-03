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
 */

#include <assert.h>
#include <kernel/mutex.h>
#include <optee_msg_supplicant.h>
#include <stdio.h>
#include <stdlib.h>
#include <string_ext.h>
#include <string.h>
#include <sys/queue.h>
#include <tee/fs_htree.h>
#include <tee/tee_cryp_provider.h>
#include <tee/tee_fs.h>
#include <tee/tee_fs_rpc.h>
#include <trace.h>
#include <utee_defines.h>
#include <util.h>

/* Block size for encryption */
#define BLOCK_SHIFT 12
#define BLOCK_SIZE (1 << BLOCK_SHIFT)

/* File descriptor */
struct sql_fs_fd {
	struct tee_fs_htree *ht;
	int fd; /* returned by normal world */
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

static TEE_Result sql_fs_opendir_rpc(const TEE_UUID *uuid,
				     struct tee_fs_dir **d)
{
	return tee_fs_rpc_opendir(OPTEE_MSG_RPC_CMD_SQL_FS, uuid, d);
}

static TEE_Result sql_fs_readdir_rpc(struct tee_fs_dir *d,
				     struct tee_fs_dirent **ent)
{
	return tee_fs_rpc_readdir(OPTEE_MSG_RPC_CMD_SQL_FS, d, ent);
}

static TEE_Result sql_fs_remove_rpc(struct tee_pobj *po)
{
	return tee_fs_rpc_remove(OPTEE_MSG_RPC_CMD_SQL_FS, po);
}

static TEE_Result sql_fs_rename_rpc(struct tee_pobj *old, struct tee_pobj *new,
				    bool overwrite)
{
	return tee_fs_rpc_rename(OPTEE_MSG_RPC_CMD_SQL_FS, old, new, overwrite);
}

static void sql_fs_closedir_rpc(struct tee_fs_dir *d)
{
	if (d)
		tee_fs_rpc_closedir(OPTEE_MSG_RPC_CMD_SQL_FS, d);
}

/*
 * End of interface with tee-supplicant
 */


/* Return the block number from a position in the user data */
static ssize_t block_num(tee_fs_off_t pos)
{
	return pos / BLOCK_SIZE;
}

static TEE_Result get_offs_size(enum tee_fs_htree_type type, size_t idx,
				size_t *offs, size_t *size)
{
	const size_t node_size = sizeof(struct tee_fs_htree_node_image);
	const size_t block_nodes = BLOCK_SIZE / node_size;
	size_t pbn;
	size_t bidx;


	/*
	 * File layout
	 *
	 * phys block 0:
	 * tee_fs_htree_image @ offs = 0
	 *
	 * phys block 1:
	 * tee_fs_htree_node_image 0  @ offs = 0
	 * tee_fs_htree_node_image 1  @ offs = node_size * 2
	 * ...
	 * tee_fs_htree_node_image 61 @ offs = node_size * 122
	 *
	 * phys block 2:
	 * data block 0
	 *
	 * ...
	 *
	 * phys block 64:
	 * data block 61
	 *
	 * phys block 65:
	 * tee_fs_htree_node_image 62  @ offs = 0
	 * tee_fs_htree_node_image 63  @ offs = node_size * 2
	 * ...
	 * tee_fs_htree_node_image 121 @ offs = node_size * 123
	 *
	 * ...
	 */

	switch (type) {
	case TEE_FS_HTREE_TYPE_HEAD:
		*offs = 0;
		*size = sizeof(struct tee_fs_htree_image);
		return TEE_SUCCESS;
	case TEE_FS_HTREE_TYPE_NODE:
		pbn = 1 + ((idx / block_nodes) * block_nodes);
		*offs = pbn * BLOCK_SIZE + node_size * (idx % block_nodes);
		*size = node_size;
		return TEE_SUCCESS;
	case TEE_FS_HTREE_TYPE_BLOCK:
		bidx = idx;
		pbn = 2 + bidx + bidx / (block_nodes - 1);
		*offs = pbn * BLOCK_SIZE;
		*size = BLOCK_SIZE;
		return TEE_SUCCESS;
	default:
		return TEE_ERROR_GENERIC;
	}
}

static TEE_Result sql_fs_rpc_read_init(void *aux,
				       struct tee_fs_rpc_operation *op,
				       enum tee_fs_htree_type type, size_t idx,
				       uint8_t vers __unused, void **data)
{
	struct sql_fs_fd *fdp = aux;
	TEE_Result res;
	size_t offs;
	size_t size;

	res = get_offs_size(type, idx, &offs, &size);
	if (res != TEE_SUCCESS)
		return res;

	return tee_fs_rpc_read_init(op, OPTEE_MSG_RPC_CMD_SQL_FS, fdp->fd,
				    offs, size, data);
}

static TEE_Result sql_fs_rpc_write_init(void *aux,
					struct tee_fs_rpc_operation *op,
					enum tee_fs_htree_type type, size_t idx,
					uint8_t vers __unused, void **data)
{
	struct sql_fs_fd *fdp = aux;
	TEE_Result res;
	size_t offs;
	size_t size;

	res = get_offs_size(type, idx, &offs, &size);
	if (res != TEE_SUCCESS)
		return res;

	return tee_fs_rpc_write_init(op, OPTEE_MSG_RPC_CMD_SQL_FS, fdp->fd,
				     offs, size, data);
}

static const struct tee_fs_htree_storage sql_fs_storage_ops = {
	.block_size = BLOCK_SIZE,
	.rpc_read_init = sql_fs_rpc_read_init,
	.rpc_read_final = tee_fs_rpc_read_final,
	.rpc_write_init = sql_fs_rpc_write_init,
	.rpc_write_final = tee_fs_rpc_write_final,
};

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

	if (bnum * BLOCK_SIZE <
	    ROUNDUP(tee_fs_htree_get_meta(fdp->ht)->length, BLOCK_SIZE)) {
		res = tee_fs_htree_read_block(&fdp->ht, bnum, buf);
		if (res != TEE_SUCCESS)
			goto exit;
	} else {
		memset(buf, 0, BLOCK_SIZE);
	}

	if (data)
		memcpy(buf + offset, data, len);
	else
		memset(buf + offset, 0, len);

	res = tee_fs_htree_write_block(&fdp->ht, bnum, buf);
exit:
	free(buf);
	return res;
}

static TEE_Result sql_fs_ftruncate_internal(struct sql_fs_fd *fdp,
					    tee_fs_off_t new_length)
{
	TEE_Result res;
	struct tee_fs_htree_meta *meta = tee_fs_htree_get_meta(fdp->ht);

	if ((size_t)new_length == meta->length)
		return TEE_SUCCESS;

	sql_fs_begin_transaction_rpc();

	if ((size_t)new_length < meta->length) {
		/* Trim unused blocks */
		int old_last_block = block_num(meta->length);
		int last_block = block_num(new_length);

		if (last_block < old_last_block) {
			size_t offs;
			size_t sz;

			res = get_offs_size(TEE_FS_HTREE_TYPE_BLOCK,
					    ROUNDUP(new_length, BLOCK_SIZE) /
						BLOCK_SIZE, &offs, &sz);
			if (res != TEE_SUCCESS)
				goto exit;

			res = tee_fs_htree_truncate(&fdp->ht,
						    new_length / BLOCK_SIZE);
			if (res != TEE_SUCCESS)
				goto exit;

			res = tee_fs_rpc_truncate(OPTEE_MSG_RPC_CMD_SQL_FS,
						  fdp->fd, offs + sz);
			if (res != TEE_SUCCESS)
				goto exit;
		}
	} else {
		/* Extend file with zeroes */
		tee_fs_off_t off = meta->length % BLOCK_SIZE;
		size_t bnum = block_num(meta->length);
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

	meta->length = new_length;
	res = TEE_SUCCESS;
exit:
	if (res == TEE_SUCCESS)
		res = tee_fs_htree_sync_to_storage(&fdp->ht);
	sql_fs_end_transaction_rpc(res != TEE_SUCCESS);
	return res;
}

static void sql_fs_close(struct tee_file_handle **fh)
{
	struct sql_fs_fd *fdp = (struct sql_fs_fd *)*fh;

	if (fdp) {
		tee_fs_htree_close(&fdp->ht);
		tee_fs_rpc_close(OPTEE_MSG_RPC_CMD_SQL_FS, fdp->fd);
		free(fdp);
		*fh = NULL;
	}
}

static TEE_Result open_internal(struct tee_pobj *po, bool create,
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
		res = tee_fs_rpc_create(OPTEE_MSG_RPC_CMD_SQL_FS, po, &fdp->fd);
	else
		res = tee_fs_rpc_open(OPTEE_MSG_RPC_CMD_SQL_FS, po, &fdp->fd);
	if (res != TEE_SUCCESS)
		goto out;

	res = tee_fs_htree_open(create, &sql_fs_storage_ops, fdp, &fdp->ht);
out:
	if (res == TEE_SUCCESS) {
		*fh = (struct tee_file_handle *)fdp;
	} else {
		if (fdp && fdp->fd != -1)
			tee_fs_rpc_close(OPTEE_MSG_RPC_CMD_SQL_FS, fdp->fd);
		if (created)
			tee_fs_rpc_remove(OPTEE_MSG_RPC_CMD_SQL_FS, po);
		free(fdp);
	}
	mutex_unlock(&sql_fs_mutex);
	return res;
}

static TEE_Result sql_fs_open(struct tee_pobj *po, struct tee_file_handle **fh)
{
	return open_internal(po, false, fh);
}

static TEE_Result sql_fs_create(struct tee_pobj *po,
				struct tee_file_handle **fh)
{
	return open_internal(po, true, fh);
}


static TEE_Result sql_fs_read(struct tee_file_handle *fh, size_t pos,
			      void *buf, size_t *len)
{
	TEE_Result res;
	struct sql_fs_fd *fdp = (struct sql_fs_fd *)fh;
	size_t remain_bytes = *len;
	uint8_t *data_ptr = buf;
	uint8_t *block = NULL;
	int start_block_num;
	int end_block_num;
	size_t file_size;

	mutex_lock(&sql_fs_mutex);

	file_size = tee_fs_htree_get_meta(fdp->ht)->length;
	if ((pos + remain_bytes) < remain_bytes || pos > file_size)
		remain_bytes = 0;
	else if (pos + remain_bytes > file_size)
		remain_bytes = file_size - pos;

	*len = remain_bytes;

	if (!remain_bytes) {
		res = TEE_SUCCESS;
		goto exit;
	}

	start_block_num = block_num(pos);
	end_block_num = block_num(pos + remain_bytes - 1);

	block = malloc(BLOCK_SIZE);
	if (!block) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto exit;
	}

	while (start_block_num <= end_block_num) {
		size_t offset = pos % BLOCK_SIZE;
		size_t size_to_read = MIN(remain_bytes, (size_t)BLOCK_SIZE);

		if (size_to_read + offset > BLOCK_SIZE)
			size_to_read = BLOCK_SIZE - offset;

		res = tee_fs_htree_read_block(&fdp->ht, start_block_num, block);
		if (res != TEE_SUCCESS)
			goto exit;

		memcpy(data_ptr, block + offset, size_to_read);

		data_ptr += size_to_read;
		remain_bytes -= size_to_read;
		pos += size_to_read;

		start_block_num++;
	}
	res = TEE_SUCCESS;
exit:
	free(block);
	mutex_unlock(&sql_fs_mutex);
	return res;
}

static TEE_Result sql_fs_write(struct tee_file_handle *fh, size_t pos,
			       const void *buf, size_t len)
{
	TEE_Result res;
	struct sql_fs_fd *fdp = (struct sql_fs_fd *)fh;
	struct tee_fs_htree_meta *meta = tee_fs_htree_get_meta(fdp->ht);
	size_t remain_bytes = len;
	const uint8_t *data_ptr = buf;
	int start_block_num;
	int end_block_num;

	if (!len)
		return TEE_SUCCESS;

	mutex_lock(&sql_fs_mutex);

	sql_fs_begin_transaction_rpc();

	if (meta->length < pos) {
		/* Fill hole */
		res = sql_fs_ftruncate_internal(fdp, pos);
		if (res != TEE_SUCCESS)
			goto exit;
	}

	start_block_num = block_num(pos);
	end_block_num = block_num(pos + len - 1);

	while (start_block_num <= end_block_num) {
		size_t offset = pos % BLOCK_SIZE;
		size_t size_to_write = MIN(remain_bytes, (size_t)BLOCK_SIZE);

		if (size_to_write + offset > BLOCK_SIZE)
			size_to_write = BLOCK_SIZE - offset;

		res = write_block_partial(fdp, start_block_num, data_ptr,
					  size_to_write, offset);
		if (res != TEE_SUCCESS)
			goto exit;

		data_ptr += size_to_write;
		remain_bytes -= size_to_write;
		pos += size_to_write;

		start_block_num++;
	}

	if (pos > meta->length)
		meta->length = pos;

exit:
	if (res == TEE_SUCCESS)
		res = tee_fs_htree_sync_to_storage(&fdp->ht);
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
	.truncate = sql_fs_truncate,

	.opendir = sql_fs_opendir_rpc,
	.closedir = sql_fs_closedir_rpc,
	.readdir = sql_fs_readdir_rpc,
	.rename = sql_fs_rename_rpc,
	.remove = sql_fs_remove_rpc,
};
