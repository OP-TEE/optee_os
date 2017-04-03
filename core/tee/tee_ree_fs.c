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
#include <kernel/mutex.h>
#include <kernel/panic.h>
#include <kernel/thread.h>
#include <mm/core_memprot.h>
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

#define BLOCK_SHIFT	12

#define BLOCK_SIZE	(1 << BLOCK_SHIFT)

struct tee_fs_fd {
	struct tee_fs_htree *ht;
	int fd;
};

static int pos_to_block_num(int position)
{
	return position >> BLOCK_SHIFT;
}

static struct mutex ree_fs_mutex = MUTEX_INITIALIZER;

static TEE_Result ree_fs_opendir_rpc(const TEE_UUID *uuid,
				     struct tee_fs_dir **d)

{
	return tee_fs_rpc_opendir(OPTEE_MSG_RPC_CMD_FS, uuid, d);
}

static void ree_fs_closedir_rpc(struct tee_fs_dir *d)
{
	if (d)
		tee_fs_rpc_closedir(OPTEE_MSG_RPC_CMD_FS, d);
}

static TEE_Result ree_fs_readdir_rpc(struct tee_fs_dir *d,
				     struct tee_fs_dirent **ent)
{
	return tee_fs_rpc_readdir(OPTEE_MSG_RPC_CMD_FS, d, ent);
}

static TEE_Result out_of_place_write(struct tee_fs_fd *fdp, size_t pos,
				     const void *buf, size_t len)
{
	TEE_Result res;
	size_t start_block_num = pos_to_block_num(pos);
	size_t end_block_num = pos_to_block_num(pos + len - 1);
	size_t remain_bytes = len;
	uint8_t *data_ptr = (uint8_t *)buf;
	uint8_t *block;
	struct tee_fs_htree_meta *meta = tee_fs_htree_get_meta(fdp->ht);

	block = malloc(BLOCK_SIZE);
	if (!block)
		return TEE_ERROR_OUT_OF_MEMORY;

	while (start_block_num <= end_block_num) {
		size_t offset = pos % BLOCK_SIZE;
		size_t size_to_write = MIN(remain_bytes, (size_t)BLOCK_SIZE);

		if (size_to_write + offset > BLOCK_SIZE)
			size_to_write = BLOCK_SIZE - offset;

		if (start_block_num * BLOCK_SIZE <
		    ROUNDUP(meta->length, BLOCK_SIZE)) {
			res = tee_fs_htree_read_block(&fdp->ht,
						      start_block_num, block);
			if (res != TEE_SUCCESS)
				goto exit;
		} else {
			memset(block, 0, BLOCK_SIZE);
		}

		if (data_ptr)
			memcpy(block + offset, data_ptr, size_to_write);
		else
			memset(block + offset, 0, size_to_write);

		res = tee_fs_htree_write_block(&fdp->ht, start_block_num,
					       block);
		if (res != TEE_SUCCESS)
			goto exit;

		if (data_ptr)
			data_ptr += size_to_write;
		remain_bytes -= size_to_write;
		start_block_num++;
		pos += size_to_write;
	}

	if (pos > meta->length)
		meta->length = pos;

exit:
	free(block);
	return res;
}

static TEE_Result get_offs_size(enum tee_fs_htree_type type, size_t idx,
				uint8_t vers, size_t *offs, size_t *size)
{
	const size_t node_size = sizeof(struct tee_fs_htree_node_image);
	const size_t block_nodes = BLOCK_SIZE / (node_size * 2);
	size_t pbn;
	size_t bidx;

	assert(vers == 0 || vers == 1);

	/*
	 * File layout
	 *
	 * phys block 0:
	 * tee_fs_htree_image vers 0 @ offs = 0
	 * tee_fs_htree_image vers 1 @ offs = sizeof(tee_fs_htree_image)
	 *
	 * phys block 1:
	 * tee_fs_htree_node_image 0  vers 0 @ offs = 0
	 * tee_fs_htree_node_image 0  vers 1 @ offs = node_size
	 * tee_fs_htree_node_image 1  vers 0 @ offs = node_size * 2
	 * tee_fs_htree_node_image 1  vers 1 @ offs = node_size * 3
	 * ...
	 * tee_fs_htree_node_image 61 vers 0 @ offs = node_size * 122
	 * tee_fs_htree_node_image 61 vers 1 @ offs = node_size * 123
	 *
	 * phys block 2:
	 * data block 0 vers 0
	 *
	 * phys block 3:
	 * data block 0 vers 1
	 *
	 * ...
	 * phys block 63:
	 * data block 61 vers 0
	 *
	 * phys block 64:
	 * data block 61 vers 1
	 *
	 * phys block 65:
	 * tee_fs_htree_node_image 62  vers 0 @ offs = 0
	 * tee_fs_htree_node_image 62  vers 1 @ offs = node_size
	 * tee_fs_htree_node_image 63  vers 0 @ offs = node_size * 2
	 * tee_fs_htree_node_image 63  vers 1 @ offs = node_size * 3
	 * ...
	 * tee_fs_htree_node_image 121 vers 0 @ offs = node_size * 122
	 * tee_fs_htree_node_image 121 vers 1 @ offs = node_size * 123
	 *
	 * ...
	 */

	switch (type) {
	case TEE_FS_HTREE_TYPE_HEAD:
		*offs = sizeof(struct tee_fs_htree_image) * vers;
		*size = sizeof(struct tee_fs_htree_image);
		return TEE_SUCCESS;
	case TEE_FS_HTREE_TYPE_NODE:
		pbn = 1 + ((idx / block_nodes) * block_nodes * 2);
		*offs = pbn * BLOCK_SIZE +
			2 * node_size * (idx % block_nodes) +
			node_size * vers;
		*size = node_size;
		return TEE_SUCCESS;
	case TEE_FS_HTREE_TYPE_BLOCK:
		bidx = 2 * idx + vers;
		pbn = 2 + bidx + bidx / (block_nodes * 2 - 1);
		*offs = pbn * BLOCK_SIZE;
		*size = BLOCK_SIZE;
		return TEE_SUCCESS;
	default:
		return TEE_ERROR_GENERIC;
	}
}

static TEE_Result ree_fs_rpc_read_init(void *aux,
				       struct tee_fs_rpc_operation *op,
				       enum tee_fs_htree_type type, size_t idx,
				       uint8_t vers, void **data)
{
	struct tee_fs_fd *fdp = aux;
	TEE_Result res;
	size_t offs;
	size_t size;

	res = get_offs_size(type, idx, vers, &offs, &size);
	if (res != TEE_SUCCESS)
		return res;

	return tee_fs_rpc_read_init(op, OPTEE_MSG_RPC_CMD_FS, fdp->fd,
				    offs, size, data);
}

static TEE_Result ree_fs_rpc_write_init(void *aux,
					struct tee_fs_rpc_operation *op,
					enum tee_fs_htree_type type, size_t idx,
					uint8_t vers, void **data)
{
	struct tee_fs_fd *fdp = aux;
	TEE_Result res;
	size_t offs;
	size_t size;

	res = get_offs_size(type, idx, vers, &offs, &size);
	if (res != TEE_SUCCESS)
		return res;

	return tee_fs_rpc_write_init(op, OPTEE_MSG_RPC_CMD_FS, fdp->fd,
				     offs, size, data);
}

static const struct tee_fs_htree_storage ree_fs_storage_ops = {
	.block_size = BLOCK_SIZE,
	.rpc_read_init = ree_fs_rpc_read_init,
	.rpc_read_final = tee_fs_rpc_read_final,
	.rpc_write_init = ree_fs_rpc_write_init,
	.rpc_write_final = tee_fs_rpc_write_final,
};

static TEE_Result open_internal(struct tee_pobj *po, bool create,
				struct tee_file_handle **fh)
{
	TEE_Result res;
	struct tee_fs_fd *fdp = NULL;

	fdp = calloc(1, sizeof(struct tee_fs_fd));
	if (!fdp)
		return TEE_ERROR_OUT_OF_MEMORY;
	fdp->fd = -1;

	mutex_lock(&ree_fs_mutex);

	if (create)
		res = tee_fs_rpc_create(OPTEE_MSG_RPC_CMD_FS, po, &fdp->fd);
	else
		res = tee_fs_rpc_open(OPTEE_MSG_RPC_CMD_FS, po, &fdp->fd);

	if (res != TEE_SUCCESS)
		goto out;

	res = tee_fs_htree_open(create, &ree_fs_storage_ops, fdp, &fdp->ht);
out:
	if (res == TEE_SUCCESS) {
		*fh = (struct tee_file_handle *)fdp;
	} else {
		if (fdp->fd != -1)
			tee_fs_rpc_close(OPTEE_MSG_RPC_CMD_FS, fdp->fd);
		if (create)
			tee_fs_rpc_remove(OPTEE_MSG_RPC_CMD_FS, po);
		free(fdp);
	}

	mutex_unlock(&ree_fs_mutex);
	return res;
}

static TEE_Result ree_fs_open(struct tee_pobj *po, struct tee_file_handle **fh)
{
	return open_internal(po, false, fh);
}

static TEE_Result ree_fs_create(struct tee_pobj *po,
				struct tee_file_handle **fh)
{
	return open_internal(po, true, fh);
}

static void ree_fs_close(struct tee_file_handle **fh)
{
	struct tee_fs_fd *fdp = (struct tee_fs_fd *)*fh;

	if (fdp) {
		tee_fs_htree_close(&fdp->ht);
		tee_fs_rpc_close(OPTEE_MSG_RPC_CMD_FS, fdp->fd);
		free(fdp);
		*fh = NULL;
	}
}

static TEE_Result ree_fs_ftruncate_internal(struct tee_fs_fd *fdp,
					    tee_fs_off_t new_file_len)
{
	TEE_Result res;
	struct tee_fs_htree_meta *meta = tee_fs_htree_get_meta(fdp->ht);

	if ((size_t)new_file_len > meta->length) {
		size_t ext_len = new_file_len - meta->length;

		res = out_of_place_write(fdp, meta->length, NULL, ext_len);
		if (res != TEE_SUCCESS)
			return res;
	} else {
		size_t offs;
		size_t sz;

		res = get_offs_size(TEE_FS_HTREE_TYPE_BLOCK,
				    ROUNDUP(new_file_len, BLOCK_SIZE) /
					BLOCK_SIZE, 1, &offs, &sz);
		if (res != TEE_SUCCESS)
			return res;

		res = tee_fs_htree_truncate(&fdp->ht,
					    new_file_len / BLOCK_SIZE);
		if (res != TEE_SUCCESS)
			return res;

		res = tee_fs_rpc_truncate(OPTEE_MSG_RPC_CMD_FS, fdp->fd,
					  offs + sz);
		if (res != TEE_SUCCESS)
			return res;

		meta->length = new_file_len;
	}

	return tee_fs_htree_sync_to_storage(&fdp->ht);
}

static TEE_Result ree_fs_read(struct tee_file_handle *fh, size_t pos,
			      void *buf, size_t *len)
{
	TEE_Result res;
	int start_block_num;
	int end_block_num;
	size_t remain_bytes;
	uint8_t *data_ptr = buf;
	uint8_t *block = NULL;
	struct tee_fs_fd *fdp = (struct tee_fs_fd *)fh;
	struct tee_fs_htree_meta *meta = tee_fs_htree_get_meta(fdp->ht);

	mutex_lock(&ree_fs_mutex);

	remain_bytes = *len;
	if ((pos + remain_bytes) < remain_bytes || pos > meta->length)
		remain_bytes = 0;
	else if (pos + remain_bytes > meta->length)
		remain_bytes = meta->length - pos;

	*len = remain_bytes;

	if (!remain_bytes) {
		res = TEE_SUCCESS;
		goto exit;
	}

	start_block_num = pos_to_block_num(pos);
	end_block_num = pos_to_block_num(pos + remain_bytes - 1);

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
	mutex_unlock(&ree_fs_mutex);
	free(block);
	return res;
}

static TEE_Result ree_fs_write(struct tee_file_handle *fh, size_t pos,
			       const void *buf, size_t len)
{
	TEE_Result res;
	struct tee_fs_fd *fdp = (struct tee_fs_fd *)fh;
	size_t file_size;

	if (!len)
		return TEE_SUCCESS;

	mutex_lock(&ree_fs_mutex);

	file_size = tee_fs_htree_get_meta(fdp->ht)->length;

	if ((pos + len) < len) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto exit;
	}

	if (file_size < pos) {
		res = ree_fs_ftruncate_internal(fdp, pos);
		if (res != TEE_SUCCESS)
			goto exit;
	}

	res = out_of_place_write(fdp, pos, buf, len);
	if (res != TEE_SUCCESS)
		goto exit;

exit:
	if (res == TEE_SUCCESS)
		res = tee_fs_htree_sync_to_storage(&fdp->ht);
	mutex_unlock(&ree_fs_mutex);
	return res;
}

static TEE_Result ree_fs_rename(struct tee_pobj *old, struct tee_pobj *new,
				bool overwrite)
{
	TEE_Result res;

	mutex_lock(&ree_fs_mutex);
	res = tee_fs_rpc_rename(OPTEE_MSG_RPC_CMD_FS, old, new, overwrite);
	mutex_unlock(&ree_fs_mutex);

	return res;
}

static TEE_Result ree_fs_remove(struct tee_pobj *po)
{
	TEE_Result res;

	mutex_lock(&ree_fs_mutex);
	res = tee_fs_rpc_remove(OPTEE_MSG_RPC_CMD_FS, po);
	mutex_unlock(&ree_fs_mutex);

	return res;
}

static TEE_Result ree_fs_truncate(struct tee_file_handle *fh, size_t len)
{
	TEE_Result res;
	struct tee_fs_fd *fdp = (struct tee_fs_fd *)fh;

	mutex_lock(&ree_fs_mutex);
	res = ree_fs_ftruncate_internal(fdp, len);
	mutex_unlock(&ree_fs_mutex);

	return res;
}

const struct tee_file_operations ree_fs_ops = {
	.open = ree_fs_open,
	.create = ree_fs_create,
	.close = ree_fs_close,
	.read = ree_fs_read,
	.write = ree_fs_write,
	.truncate = ree_fs_truncate,
	.rename = ree_fs_rename,
	.remove = ree_fs_remove,
	.opendir = ree_fs_opendir_rpc,
	.closedir = ree_fs_closedir_rpc,
	.readdir = ree_fs_readdir_rpc,
};
