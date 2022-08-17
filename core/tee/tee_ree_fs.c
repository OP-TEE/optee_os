// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015, Linaro Limited
 */

#include <assert.h>
#include <config.h>
#include <kernel/mutex.h>
#include <kernel/panic.h>
#include <kernel/thread.h>
#include <mempool.h>
#include <mm/core_memprot.h>
#include <mm/tee_pager.h>
#include <optee_rpc_cmd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string_ext.h>
#include <string.h>
#include <sys/queue.h>
#include <tee/fs_dirfile.h>
#include <tee/fs_htree.h>
#include <tee/tee_fs.h>
#include <tee/tee_fs_rpc.h>
#include <tee/tee_pobj.h>
#include <trace.h>
#include <utee_defines.h>
#include <util.h>

#define BLOCK_SHIFT	12

#define BLOCK_SIZE	(1 << BLOCK_SHIFT)

struct tee_fs_fd {
	struct tee_fs_htree *ht;
	int fd;
	struct tee_fs_dirfile_fileh dfh;
	const TEE_UUID *uuid;
};

struct tee_fs_dir {
	struct tee_fs_dirfile_dirh *dirh;
	int idx;
	struct tee_fs_dirent d;
	const TEE_UUID *uuid;
};

static int pos_to_block_num(int position)
{
	return position >> BLOCK_SHIFT;
}

static struct mutex ree_fs_mutex = MUTEX_INITIALIZER;

static void *get_tmp_block(void)
{
	return mempool_alloc(mempool_default, BLOCK_SIZE);
}

static void put_tmp_block(void *tmp_block)
{
	mempool_free(mempool_default, tmp_block);
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

	/*
	 * It doesn't make sense to call this function if nothing is to be
	 * written. This also guards against end_block_num getting an
	 * unexpected value when pos == 0 and len == 0.
	 */
	if (!len)
		return TEE_ERROR_BAD_PARAMETERS;

	block = get_tmp_block();
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

	if (pos > meta->length) {
		meta->length = pos;
		tee_fs_htree_meta_set_dirty(fdp->ht);
	}

exit:
	if (block)
		put_tmp_block(block);
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
	 * [demo with input:
	 * BLOCK_SIZE = 4096,
	 * node_size = 66,
	 * block_nodes = 4096/(66*2) = 31 ]
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
	 * tee_fs_htree_node_image 30 vers 0 @ offs = node_size * 60
	 * tee_fs_htree_node_image 30 vers 1 @ offs = node_size * 61
	 *
	 * phys block 2:
	 * data block 0 vers 0
	 *
	 * phys block 3:
	 * data block 0 vers 1
	 *
	 * ...
	 * phys block 62:
	 * data block 30 vers 0
	 *
	 * phys block 63:
	 * data block 30 vers 1
	 *
	 * phys block 64:
	 * tee_fs_htree_node_image 31  vers 0 @ offs = 0
	 * tee_fs_htree_node_image 31  vers 1 @ offs = node_size
	 * tee_fs_htree_node_image 32  vers 0 @ offs = node_size * 2
	 * tee_fs_htree_node_image 32  vers 1 @ offs = node_size * 3
	 * ...
	 * tee_fs_htree_node_image 61 vers 0 @ offs = node_size * 60
	 * tee_fs_htree_node_image 61 vers 1 @ offs = node_size * 61
	 *
	 * phys block 65:
	 * data block 31 vers 0
	 *
	 * phys block 66:
	 * data block 31 vers 1
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

	return tee_fs_rpc_read_init(op, OPTEE_RPC_CMD_FS, fdp->fd,
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

	return tee_fs_rpc_write_init(op, OPTEE_RPC_CMD_FS, fdp->fd,
				     offs, size, data);
}

static const struct tee_fs_htree_storage ree_fs_storage_ops = {
	.block_size = BLOCK_SIZE,
	.rpc_read_init = ree_fs_rpc_read_init,
	.rpc_read_final = tee_fs_rpc_read_final,
	.rpc_write_init = ree_fs_rpc_write_init,
	.rpc_write_final = tee_fs_rpc_write_final,
};

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

		res = tee_fs_rpc_truncate(OPTEE_RPC_CMD_FS, fdp->fd,
					  offs + sz);
		if (res != TEE_SUCCESS)
			return res;

		meta->length = new_file_len;
		tee_fs_htree_meta_set_dirty(fdp->ht);
	}

	return TEE_SUCCESS;
}

static TEE_Result ree_fs_read_primitive(struct tee_file_handle *fh, size_t pos,
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

	block = get_tmp_block();
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
	if (block)
		put_tmp_block(block);
	return res;
}

static TEE_Result ree_fs_read(struct tee_file_handle *fh, size_t pos,
			      void *buf, size_t *len)
{
	TEE_Result res;

	mutex_lock(&ree_fs_mutex);
	res = ree_fs_read_primitive(fh, pos, buf, len);
	mutex_unlock(&ree_fs_mutex);

	return res;
}

static TEE_Result ree_fs_write_primitive(struct tee_file_handle *fh, size_t pos,
					 const void *buf, size_t len)
{
	TEE_Result res;
	struct tee_fs_fd *fdp = (struct tee_fs_fd *)fh;
	size_t file_size;

	if (!len)
		return TEE_SUCCESS;

	file_size = tee_fs_htree_get_meta(fdp->ht)->length;

	if ((pos + len) < len)
		return TEE_ERROR_BAD_PARAMETERS;

	if (file_size < pos) {
		res = ree_fs_ftruncate_internal(fdp, pos);
		if (res != TEE_SUCCESS)
			return res;
	}

	return out_of_place_write(fdp, pos, buf, len);
}

static TEE_Result ree_fs_open_primitive(bool create, uint8_t *hash,
					const TEE_UUID *uuid,
					struct tee_fs_dirfile_fileh *dfh,
					struct tee_file_handle **fh)
{
	TEE_Result res;
	struct tee_fs_fd *fdp;

	fdp = calloc(1, sizeof(struct tee_fs_fd));
	if (!fdp)
		return TEE_ERROR_OUT_OF_MEMORY;
	fdp->fd = -1;
	fdp->uuid = uuid;

	if (create)
		res = tee_fs_rpc_create_dfh(OPTEE_RPC_CMD_FS,
					    dfh, &fdp->fd);
	else
		res = tee_fs_rpc_open_dfh(OPTEE_RPC_CMD_FS, dfh, &fdp->fd);

	if (res != TEE_SUCCESS)
		goto out;

	res = tee_fs_htree_open(create, hash, uuid, &ree_fs_storage_ops,
				fdp, &fdp->ht);
out:
	if (res == TEE_SUCCESS) {
		if (dfh)
			fdp->dfh = *dfh;
		else
			fdp->dfh.idx = -1;
		*fh = (struct tee_file_handle *)fdp;
	} else {
		if (res == TEE_ERROR_SECURITY)
			DMSG("Secure storage corruption detected");
		if (fdp->fd != -1)
			tee_fs_rpc_close(OPTEE_RPC_CMD_FS, fdp->fd);
		if (create)
			tee_fs_rpc_remove_dfh(OPTEE_RPC_CMD_FS, dfh);
		free(fdp);
	}

	return res;
}

static void ree_fs_close_primitive(struct tee_file_handle *fh)
{
	struct tee_fs_fd *fdp = (struct tee_fs_fd *)fh;

	if (fdp) {
		tee_fs_htree_close(&fdp->ht);
		tee_fs_rpc_close(OPTEE_RPC_CMD_FS, fdp->fd);
		free(fdp);
	}
}

static TEE_Result ree_dirf_commit_writes(struct tee_file_handle *fh,
					 uint8_t *hash)
{
	TEE_Result res;
	struct tee_fs_fd *fdp = (struct tee_fs_fd *)fh;

	res = tee_fs_htree_sync_to_storage(&fdp->ht, fdp->dfh.hash);

	if (!res && hash)
		memcpy(hash, fdp->dfh.hash, sizeof(fdp->dfh.hash));

	return res;
}

static const struct tee_fs_dirfile_operations ree_dirf_ops = {
	.open = ree_fs_open_primitive,
	.close = ree_fs_close_primitive,
	.read = ree_fs_read_primitive,
	.write = ree_fs_write_primitive,
	.commit_writes = ree_dirf_commit_writes,
};

static struct tee_fs_dirfile_dirh *ree_fs_dirh;
static size_t ree_fs_dirh_refcount;

#ifdef CFG_REE_FS_INTEGRITY_RPMB
static struct tee_file_handle *ree_fs_rpmb_fh;

static TEE_Result open_dirh(struct tee_fs_dirfile_dirh **dirh)
{
	TEE_Result res;
	uint8_t hash[TEE_FS_HTREE_HASH_SIZE];
	uint8_t *hashp = NULL;
	const char fname[] = "dirfile.db.hash";

	res = tee_rpmb_fs_raw_open(fname, false, &ree_fs_rpmb_fh);
	if (!res) {
		size_t l = sizeof(hash);

		res = rpmb_fs_ops.read(ree_fs_rpmb_fh, 0, hash, &l);
		if (res)
			return res;
		if (l == sizeof(hash))
			hashp = hash;
	} else if (res == TEE_ERROR_ITEM_NOT_FOUND) {
		res = tee_rpmb_fs_raw_open(fname, true, &ree_fs_rpmb_fh);
	}
	if (res)
		return res;

	res = tee_fs_dirfile_open(false, hashp, &ree_dirf_ops, dirh);

	if (res == TEE_ERROR_ITEM_NOT_FOUND) {
		if (hashp) {
			if (IS_ENABLED(CFG_REE_FS_ALLOW_RESET)) {
				DMSG("dirf.db not found, clear hash in RPMB");
				res = rpmb_fs_ops.truncate(ree_fs_rpmb_fh, 0);
				if (res) {
					DMSG("Can't clear hash: %#"PRIx32, res);
					res = TEE_ERROR_SECURITY;
					goto out;
				}
			} else {
				DMSG("dirf.db file not found");
				res = TEE_ERROR_SECURITY;
				goto out;
			}
		}

		res = tee_fs_dirfile_open(true, NULL, &ree_dirf_ops, dirh);
	}

out:
	if (res)
		rpmb_fs_ops.close(&ree_fs_rpmb_fh);

	return res;
}

static TEE_Result commit_dirh_writes(struct tee_fs_dirfile_dirh *dirh)
{
	TEE_Result res;
	uint8_t hash[TEE_FS_HTREE_HASH_SIZE];

	res = tee_fs_dirfile_commit_writes(dirh, hash);
	if (res)
		return res;
	return rpmb_fs_ops.write(ree_fs_rpmb_fh, 0, hash, sizeof(hash));
}

static void close_dirh(struct tee_fs_dirfile_dirh **dirh)
{
	tee_fs_dirfile_close(*dirh);
	*dirh = NULL;
	rpmb_fs_ops.close(&ree_fs_rpmb_fh);
}

#else /*!CFG_REE_FS_INTEGRITY_RPMB*/
static TEE_Result open_dirh(struct tee_fs_dirfile_dirh **dirh)
{
	TEE_Result res;

	res = tee_fs_dirfile_open(false, NULL, &ree_dirf_ops, dirh);
	if (res == TEE_ERROR_ITEM_NOT_FOUND)
		return tee_fs_dirfile_open(true, NULL, &ree_dirf_ops, dirh);

	return res;
}

static TEE_Result commit_dirh_writes(struct tee_fs_dirfile_dirh *dirh)
{
	return tee_fs_dirfile_commit_writes(dirh, NULL);
}

static void close_dirh(struct tee_fs_dirfile_dirh **dirh)
{
	tee_fs_dirfile_close(*dirh);
	*dirh = NULL;
}
#endif /*!CFG_REE_FS_INTEGRITY_RPMB*/

static TEE_Result get_dirh(struct tee_fs_dirfile_dirh **dirh)
{
	if (!ree_fs_dirh) {
		TEE_Result res = open_dirh(&ree_fs_dirh);

		if (res) {
			*dirh = NULL;
			return res;
		}
	}
	ree_fs_dirh_refcount++;
	assert(ree_fs_dirh);
	assert(ree_fs_dirh_refcount);
	*dirh = ree_fs_dirh;
	return TEE_SUCCESS;
}

static void put_dirh_primitive(bool close)
{
	assert(ree_fs_dirh_refcount);

	/*
	 * During the execution of one of the ree_fs_ops ree_fs_dirh is
	 * guareteed to be a valid pointer. But when the fop has returned
	 * another thread may get an error or something causing that fop
	 * to do a put with close=1.
	 *
	 * For all fops but ree_fs_close() there's a call to get_dirh() to
	 * get a new dirh which will open it again if it was closed before.
	 * But in the ree_fs_close() case there's no call to get_dirh()
	 * only to this function, put_dirh_primitive(), and in this case
	 * ree_fs_dirh may actually be NULL.
	 */
	ree_fs_dirh_refcount--;
	if (ree_fs_dirh && (!ree_fs_dirh_refcount || close))
		close_dirh(&ree_fs_dirh);
}

static void put_dirh(struct tee_fs_dirfile_dirh *dirh, bool close)
{
	if (dirh) {
		assert(dirh == ree_fs_dirh);
		put_dirh_primitive(close);
	}
}

static TEE_Result ree_fs_open(struct tee_pobj *po, size_t *size,
			      struct tee_file_handle **fh)
{
	TEE_Result res;
	struct tee_fs_dirfile_dirh *dirh = NULL;
	struct tee_fs_dirfile_fileh dfh;

	mutex_lock(&ree_fs_mutex);

	res = get_dirh(&dirh);
	if (res != TEE_SUCCESS)
		goto out;

	res = tee_fs_dirfile_find(dirh, &po->uuid, po->obj_id, po->obj_id_len,
				  &dfh);
	if (res != TEE_SUCCESS)
		goto out;

	res = ree_fs_open_primitive(false, dfh.hash, &po->uuid, &dfh, fh);
	if (res == TEE_ERROR_ITEM_NOT_FOUND) {
		/*
		 * If the object isn't found someone has tampered with it,
		 * treat it as corrupt.
		 */
		res = TEE_ERROR_CORRUPT_OBJECT;
	} else if (!res && size) {
		struct tee_fs_fd *fdp = (struct tee_fs_fd *)*fh;

		*size = tee_fs_htree_get_meta(fdp->ht)->length;
	}

out:
	if (res)
		put_dirh(dirh, true);
	mutex_unlock(&ree_fs_mutex);

	return res;
}

static TEE_Result set_name(struct tee_fs_dirfile_dirh *dirh,
			   struct tee_fs_fd *fdp, struct tee_pobj *po,
			   bool overwrite)
{
	TEE_Result res;
	bool have_old_dfh = false;
	struct tee_fs_dirfile_fileh old_dfh = { .idx = -1 };

	res = tee_fs_dirfile_find(dirh, &po->uuid, po->obj_id, po->obj_id_len,
				  &old_dfh);
	if (!overwrite && !res)
		return TEE_ERROR_ACCESS_CONFLICT;

	if (!res)
		have_old_dfh = true;

	/*
	 * If old_dfh wasn't found, the idx will be -1 and
	 * tee_fs_dirfile_rename() will allocate a new index.
	 */
	fdp->dfh.idx = old_dfh.idx;
	old_dfh.idx = -1;
	res = tee_fs_dirfile_rename(dirh, &po->uuid, &fdp->dfh,
				    po->obj_id, po->obj_id_len);
	if (res)
		return res;

	res = commit_dirh_writes(dirh);
	if (res)
		return res;

	if (have_old_dfh)
		tee_fs_rpc_remove_dfh(OPTEE_RPC_CMD_FS, &old_dfh);

	return TEE_SUCCESS;
}

static void ree_fs_close(struct tee_file_handle **fh)
{
	if (*fh) {
		mutex_lock(&ree_fs_mutex);
		put_dirh_primitive(false);
		ree_fs_close_primitive(*fh);
		*fh = NULL;
		mutex_unlock(&ree_fs_mutex);

	}
}

static TEE_Result ree_fs_create(struct tee_pobj *po, bool overwrite,
				const void *head, size_t head_size,
				const void *attr, size_t attr_size,
				const void *data, size_t data_size,
				struct tee_file_handle **fh)
{
	struct tee_fs_fd *fdp;
	struct tee_fs_dirfile_dirh *dirh = NULL;
	struct tee_fs_dirfile_fileh dfh;
	TEE_Result res;
	size_t pos = 0;

	*fh = NULL;
	mutex_lock(&ree_fs_mutex);

	res = get_dirh(&dirh);
	if (res)
		goto out;

	res = tee_fs_dirfile_get_tmp(dirh, &dfh);
	if (res)
		goto out;

	res = ree_fs_open_primitive(true, dfh.hash, &po->uuid, &dfh, fh);
	if (res)
		goto out;

	if (head && head_size) {
		res = ree_fs_write_primitive(*fh, pos, head, head_size);
		if (res)
			goto out;
		pos += head_size;
	}

	if (attr && attr_size) {
		res = ree_fs_write_primitive(*fh, pos, attr, attr_size);
		if (res)
			goto out;
		pos += attr_size;
	}

	if (data && data_size) {
		res = ree_fs_write_primitive(*fh, pos, data, data_size);
		if (res)
			goto out;
	}

	fdp = (struct tee_fs_fd *)*fh;
	res = tee_fs_htree_sync_to_storage(&fdp->ht, fdp->dfh.hash);
	if (res)
		goto out;

	res = set_name(dirh, fdp, po, overwrite);
out:
	if (res) {
		put_dirh(dirh, true);
		if (*fh) {
			ree_fs_close_primitive(*fh);
			*fh = NULL;
			tee_fs_rpc_remove_dfh(OPTEE_RPC_CMD_FS, &dfh);
		}
	}
	mutex_unlock(&ree_fs_mutex);

	return res;
}

static TEE_Result ree_fs_write(struct tee_file_handle *fh, size_t pos,
			       const void *buf, size_t len)
{
	TEE_Result res;
	struct tee_fs_dirfile_dirh *dirh = NULL;
	struct tee_fs_fd *fdp = (struct tee_fs_fd *)fh;

	mutex_lock(&ree_fs_mutex);

	res = get_dirh(&dirh);
	if (res)
		goto out;

	res = ree_fs_write_primitive(fh, pos, buf, len);
	if (res)
		goto out;

	res = tee_fs_htree_sync_to_storage(&fdp->ht, fdp->dfh.hash);
	if (res)
		goto out;

	res = tee_fs_dirfile_update_hash(dirh, &fdp->dfh);
	if (res)
		goto out;
	res = commit_dirh_writes(dirh);
out:
	put_dirh(dirh, res);
	mutex_unlock(&ree_fs_mutex);

	return res;
}

static TEE_Result ree_fs_rename(struct tee_pobj *old, struct tee_pobj *new,
				bool overwrite)
{
	TEE_Result res;
	struct tee_fs_dirfile_dirh *dirh = NULL;
	struct tee_fs_dirfile_fileh dfh;
	struct tee_fs_dirfile_fileh remove_dfh = { .idx = -1 };

	if (!new)
		return TEE_ERROR_BAD_PARAMETERS;

	mutex_lock(&ree_fs_mutex);
	res = get_dirh(&dirh);
	if (res)
		goto out;

	res = tee_fs_dirfile_find(dirh, &new->uuid, new->obj_id,
				  new->obj_id_len, &remove_dfh);
	if (!res && !overwrite) {
		res = TEE_ERROR_ACCESS_CONFLICT;
		goto out;
	}

	res = tee_fs_dirfile_find(dirh, &old->uuid, old->obj_id,
				  old->obj_id_len, &dfh);
	if (res)
		goto out;

	res = tee_fs_dirfile_rename(dirh, &new->uuid, &dfh, new->obj_id,
				    new->obj_id_len);
	if (res)
		goto out;

	if (remove_dfh.idx != -1) {
		res = tee_fs_dirfile_remove(dirh, &remove_dfh);
		if (res)
			goto out;
	}

	res = commit_dirh_writes(dirh);
	if (res)
		goto out;

	if (remove_dfh.idx != -1)
		tee_fs_rpc_remove_dfh(OPTEE_RPC_CMD_FS, &remove_dfh);

out:
	put_dirh(dirh, res);
	mutex_unlock(&ree_fs_mutex);

	return res;

}

static TEE_Result ree_fs_remove(struct tee_pobj *po)
{
	TEE_Result res;
	struct tee_fs_dirfile_dirh *dirh = NULL;
	struct tee_fs_dirfile_fileh dfh;

	mutex_lock(&ree_fs_mutex);
	res = get_dirh(&dirh);
	if (res)
		goto out;

	res = tee_fs_dirfile_find(dirh, &po->uuid, po->obj_id, po->obj_id_len,
				  &dfh);
	if (res)
		goto out;

	res = tee_fs_dirfile_remove(dirh, &dfh);
	if (res)
		goto out;

	res = commit_dirh_writes(dirh);
	if (res)
		goto out;

	tee_fs_rpc_remove_dfh(OPTEE_RPC_CMD_FS, &dfh);

	assert(tee_fs_dirfile_find(dirh, &po->uuid, po->obj_id, po->obj_id_len,
				   &dfh));
out:
	put_dirh(dirh, res);
	mutex_unlock(&ree_fs_mutex);

	return res;
}

static TEE_Result ree_fs_truncate(struct tee_file_handle *fh, size_t len)
{
	TEE_Result res;
	struct tee_fs_dirfile_dirh *dirh = NULL;
	struct tee_fs_fd *fdp = (struct tee_fs_fd *)fh;

	mutex_lock(&ree_fs_mutex);

	res = get_dirh(&dirh);
	if (res)
		goto out;

	res = ree_fs_ftruncate_internal(fdp, len);
	if (res)
		goto out;

	res = tee_fs_htree_sync_to_storage(&fdp->ht, fdp->dfh.hash);
	if (res)
		goto out;

	res = tee_fs_dirfile_update_hash(dirh, &fdp->dfh);
	if (res)
		goto out;
	res = commit_dirh_writes(dirh);
out:
	put_dirh(dirh, res);
	mutex_unlock(&ree_fs_mutex);

	return res;
}

static TEE_Result ree_fs_opendir_rpc(const TEE_UUID *uuid,
				     struct tee_fs_dir **dir)

{
	TEE_Result res;
	struct tee_fs_dir *d = calloc(1, sizeof(*d));

	if (!d)
		return TEE_ERROR_OUT_OF_MEMORY;

	d->uuid = uuid;

	mutex_lock(&ree_fs_mutex);

	res = get_dirh(&d->dirh);
	if (res)
		goto out;

	/* See that there's at least one file */
	d->idx = -1;
	d->d.oidlen = sizeof(d->d.oid);
	res = tee_fs_dirfile_get_next(d->dirh, d->uuid, &d->idx, d->d.oid,
				      &d->d.oidlen);
	d->idx = -1;

out:
	if (!res) {
		*dir = d;
	} else {
		if (d)
			put_dirh(d->dirh, false);
		free(d);
	}
	mutex_unlock(&ree_fs_mutex);

	return res;
}

static void ree_fs_closedir_rpc(struct tee_fs_dir *d)
{
	if (d) {
		mutex_lock(&ree_fs_mutex);

		put_dirh(d->dirh, false);
		free(d);

		mutex_unlock(&ree_fs_mutex);
	}
}

static TEE_Result ree_fs_readdir_rpc(struct tee_fs_dir *d,
				     struct tee_fs_dirent **ent)
{
	TEE_Result res;

	mutex_lock(&ree_fs_mutex);

	d->d.oidlen = sizeof(d->d.oid);
	res = tee_fs_dirfile_get_next(d->dirh, d->uuid, &d->idx, d->d.oid,
				      &d->d.oidlen);
	if (res == TEE_SUCCESS)
		*ent = &d->d;

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
