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
#include <kernel/thread.h>
#include <kernel/mutex.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <optee_msg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string_ext.h>
#include <sys/queue.h>
#include <tee/tee_cryp_provider.h>
#include <tee/tee_fs.h>
#include <tee/tee_fs_defs.h>
#include <tee/tee_fs_rpc.h>
#include <tee/tee_fs_key_manager.h>
#include <trace.h>
#include <utee_defines.h>
#include <util.h>

/*
 * This file implements the tee_file_operations structure for a secure
 * filesystem based on single file in normal world.
 *
 * All fields in the REE file are duplicated with two versions 0 and 1. The
 * active meta-data block is selected by the lowest bit in the
 * meta-counter.  The active file block is selected by corresponding bit
 * number in struct tee_fs_file_info.backup_version_table.
 *
 * The atomicity of each operation is ensured by updating meta-counter when
 * everything in the secondary blocks (both meta-data and file-data blocks)
 * are successfully written.  The main purpose of the code below is to
 * perform block encryption and authentication of the file data, and
 * properly handle seeking through the file. One file (in the sense of
 * struct tee_file_operations) maps to one file in the REE filesystem, and
 * has the following structure:
 *
 * [ 4 bytes meta-counter]
 * [ meta-data version 0][ meta-data version 1 ]
 * [ Block 0 version 0 ][ Block 0 version 1 ]
 * [ Block 1 version 0 ][ Block 1 version 1 ]
 * ...
 * [ Block n version 0 ][ Block n version 1 ]
 *
 * One meta-data block is built up as:
 * [ struct meta_header | struct tee_fs_get_header_size ]
 *
 * One data block is built up as:
 * [ struct block_header | BLOCK_FILE_SIZE bytes ]
 *
 * struct meta_header and struct block_header are defined in
 * tee_fs_key_manager.h.
 *
 */

#define BLOCK_SHIFT	12

#define BLOCK_SIZE	(1 << BLOCK_SHIFT)

#define MAX_FILE_SIZE	(BLOCK_SIZE * NUM_BLOCKS_PER_FILE)

struct tee_fs_fd {
	uint32_t meta_counter;
	struct tee_fs_file_meta meta;
	tee_fs_off_t pos;
	uint32_t flags;
	bool is_new_file;
	int fd;
};

static inline int pos_to_block_num(int position)
{
	return position >> BLOCK_SHIFT;
}

static inline int get_last_block_num(size_t size)
{
	return pos_to_block_num(size - 1);
}

static bool get_backup_version_of_block(struct tee_fs_file_meta *meta,
					size_t block_num)
{
	uint32_t index = (block_num / 32);
	uint32_t block_mask = 1 << (block_num % 32);

	return !!(meta->info.backup_version_table[index] & block_mask);
}

static inline void toggle_backup_version_of_block(
		struct tee_fs_file_meta *meta,
		size_t block_num)
{
	uint32_t index = (block_num / 32);
	uint32_t block_mask = 1 << (block_num % 32);

	meta->info.backup_version_table[index] ^= block_mask;
}

struct block_operations {

	/*
	 * Read a block from REE File System which is corresponding
	 * to the given block_num.
	 */
	struct block *(*read)(struct tee_fs_fd *fdp, int block_num);

	/*
	 * Write the given block to REE File System
	 */
	int (*write)(struct tee_fs_fd *fdp, struct block *b,
			struct tee_fs_file_meta *new_meta);
};

static struct mutex ree_fs_mutex = MUTEX_INITIALIZER;

static TEE_Result ree_fs_opendir_rpc(const char *name, struct tee_fs_dir **d)

{
	return tee_fs_rpc_opendir(OPTEE_MSG_RPC_CMD_FS, name, d);
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

static size_t meta_size(void)
{
	return tee_fs_get_header_size(META_FILE) +
	       sizeof(struct tee_fs_file_meta);
}

static size_t meta_pos_raw(struct tee_fs_fd *fdp, bool active)
{
	size_t offs = sizeof(uint32_t);

	if ((fdp->meta_counter & 1) == active)
		offs += meta_size();
	return offs;
}

static size_t block_size_raw(void)
{
	return tee_fs_get_header_size(BLOCK_FILE) + BLOCK_SIZE;
}

static size_t block_pos_raw(struct tee_fs_file_meta *meta, size_t block_num,
			    bool active)
{
	size_t n = block_num * 2;

	if (active == get_backup_version_of_block(meta, block_num))
		n++;

	return sizeof(uint32_t) + meta_size() * 2 + n * block_size_raw();
}

/*
 * encrypted_fek: as input for META_FILE and BLOCK_FILE
 */
static TEE_Result encrypt_and_write_file(struct tee_fs_fd *fdp,
		enum tee_fs_file_type file_type, size_t offs,
		void *data_in, size_t data_in_size,
		uint8_t *encrypted_fek)
{
	TEE_Result res;
	struct tee_fs_rpc_operation op;
	void *ciphertext;
	size_t header_size = tee_fs_get_header_size(file_type);
	size_t ciphertext_size = header_size + data_in_size;


	res = tee_fs_rpc_write_init(&op, OPTEE_MSG_RPC_CMD_FS, fdp->fd,
				    offs, ciphertext_size, &ciphertext);
	if (res != TEE_SUCCESS)
		return res;

	res = tee_fs_encrypt_file(file_type, data_in, data_in_size,
				  ciphertext, &ciphertext_size, encrypted_fek);
	if (res != TEE_SUCCESS)
		return res;

	return tee_fs_rpc_write_final(&op);
}

/*
 * encrypted_fek: as output for META_FILE
 *                as input for BLOCK_FILE
 */
static TEE_Result read_and_decrypt_file(struct tee_fs_fd *fdp,
		enum tee_fs_file_type file_type, size_t offs,
		void *data_out, size_t *data_out_size,
		uint8_t *encrypted_fek)
{
	TEE_Result res;
	struct tee_fs_rpc_operation op;
	size_t bytes;
	void *ciphertext;

	bytes = *data_out_size + tee_fs_get_header_size(file_type);
	res = tee_fs_rpc_read_init(&op, OPTEE_MSG_RPC_CMD_FS, fdp->fd, offs,
				   bytes, &ciphertext);
	if (res != TEE_SUCCESS)
		return res;

	res = tee_fs_rpc_read_final(&op, &bytes);
	if (res != TEE_SUCCESS)
		return res;

	if (!bytes) {
		*data_out_size = 0;
		return TEE_SUCCESS;
	}

	res = tee_fs_decrypt_file(file_type, ciphertext, bytes, data_out,
				  data_out_size, encrypted_fek);
	if (res != TEE_SUCCESS)
		return TEE_ERROR_CORRUPT_OBJECT;
	return TEE_SUCCESS;
}

static TEE_Result write_meta_file(struct tee_fs_fd *fdp,
		struct tee_fs_file_meta *meta)
{
	size_t offs = meta_pos_raw(fdp, false);

	return encrypt_and_write_file(fdp, META_FILE, offs,
			(void *)&meta->info, sizeof(meta->info),
			meta->encrypted_fek);
}

static TEE_Result write_meta_counter(struct tee_fs_fd *fdp)
{
	TEE_Result res;
	struct tee_fs_rpc_operation op;
	size_t bytes = sizeof(uint32_t);
	void *data;

	res = tee_fs_rpc_write_init(&op, OPTEE_MSG_RPC_CMD_FS, fdp->fd, 0,
				    bytes, &data);
	if (res != TEE_SUCCESS)
		return res;

	memcpy(data, &fdp->meta_counter, bytes);

	return tee_fs_rpc_write_final(&op);
}

static TEE_Result create_meta(struct tee_fs_fd *fdp, const char *fname)
{
	TEE_Result res;

	memset(fdp->meta.info.backup_version_table, 0xff,
		sizeof(fdp->meta.info.backup_version_table));
	fdp->meta.info.length = 0;

	res = tee_fs_generate_fek(fdp->meta.encrypted_fek, TEE_FS_KM_FEK_SIZE);
	if (res != TEE_SUCCESS)
		return res;

	res = tee_fs_rpc_create(OPTEE_MSG_RPC_CMD_FS, fname, &fdp->fd);
	if (res != TEE_SUCCESS)
		return res;

	fdp->meta.counter = fdp->meta_counter;

	res = write_meta_file(fdp, &fdp->meta);
	if (res != TEE_SUCCESS)
		return res;
	return write_meta_counter(fdp);
}

static TEE_Result commit_meta_file(struct tee_fs_fd *fdp,
				   struct tee_fs_file_meta *new_meta)
{
	TEE_Result res;

	new_meta->counter = fdp->meta_counter + 1;

	res = write_meta_file(fdp, new_meta);
	if (res != TEE_SUCCESS)
		return res;

	/*
	 * From now on the new meta is successfully committed,
	 * change tee_fs_fd accordingly
	 */
	fdp->meta = *new_meta;
	fdp->meta_counter = fdp->meta.counter;

	return write_meta_counter(fdp);
}

static TEE_Result read_meta_file(struct tee_fs_fd *fdp,
		struct tee_fs_file_meta *meta)
{
	size_t meta_info_size = sizeof(struct tee_fs_file_info);
	size_t offs = meta_pos_raw(fdp, true);

	return read_and_decrypt_file(fdp, META_FILE, offs,
				     &meta->info, &meta_info_size,
				     meta->encrypted_fek);
}

static TEE_Result read_meta_counter(struct tee_fs_fd *fdp)
{
	TEE_Result res;
	struct tee_fs_rpc_operation op;
	void *data;
	size_t bytes = sizeof(uint32_t);

	res = tee_fs_rpc_read_init(&op, OPTEE_MSG_RPC_CMD_FS, fdp->fd, 0,
				   bytes, &data);
	if (res != TEE_SUCCESS)
		return res;

	res = tee_fs_rpc_read_final(&op, &bytes);
	if (res != TEE_SUCCESS)
		return res;

	if (bytes != sizeof(uint32_t))
		return TEE_ERROR_CORRUPT_OBJECT;

	memcpy(&fdp->meta_counter, data, bytes);

	return TEE_SUCCESS;
}

static TEE_Result read_meta(struct tee_fs_fd *fdp, const char *fname)
{
	TEE_Result res;

	res = tee_fs_rpc_open(OPTEE_MSG_RPC_CMD_FS, fname, &fdp->fd);
	if (res != TEE_SUCCESS)
		return res;

	res = read_meta_counter(fdp);
	if (res != TEE_SUCCESS)
		return res;

	return read_meta_file(fdp, &fdp->meta);
}

static TEE_Result read_block(struct tee_fs_fd *fdp, int bnum, uint8_t *data)
{
	TEE_Result res;
	size_t ct_size = block_size_raw();
	size_t out_size = BLOCK_SIZE;
	ssize_t pos = block_pos_raw(&fdp->meta, bnum, true);
	size_t bytes;
	void *ct;
	struct tee_fs_rpc_operation op;

	res = tee_fs_rpc_read_init(&op, OPTEE_MSG_RPC_CMD_FS, fdp->fd, pos,
				   ct_size, &ct);
	if (res != TEE_SUCCESS)
		return res;
	res = tee_fs_rpc_read_final(&op, &bytes);
	if (res != TEE_SUCCESS)
		return res;
	if (!bytes) {
		memset(data, 0, BLOCK_SIZE);
		return TEE_SUCCESS; /* Block does not exist */
	}

	return tee_fs_decrypt_file(BLOCK_FILE, ct, bytes, data,
				   &out_size, fdp->meta.encrypted_fek);
}

static TEE_Result write_block(struct tee_fs_fd *fdp, size_t bnum, uint8_t *data,
			      struct tee_fs_file_meta *new_meta)
{
	TEE_Result res;
	size_t offs = block_pos_raw(new_meta, bnum, false);

	res = encrypt_and_write_file(fdp, BLOCK_FILE, offs, data,
				     BLOCK_SIZE, new_meta->encrypted_fek);
	if (res == TEE_SUCCESS)
		toggle_backup_version_of_block(new_meta, bnum);
	return res;
}

static TEE_Result out_of_place_write(struct tee_fs_fd *fdp, const void *buf,
		size_t len, struct tee_fs_file_meta *new_meta)
{
	TEE_Result res;
	int start_block_num = pos_to_block_num(fdp->pos);
	int end_block_num = pos_to_block_num(fdp->pos + len - 1);
	size_t remain_bytes = len;
	uint8_t *data_ptr = (uint8_t *)buf;
	uint8_t *block;
	int orig_pos = fdp->pos;

	block = malloc(BLOCK_SIZE);
	if (!block)
		return TEE_ERROR_OUT_OF_MEMORY;

	while (start_block_num <= end_block_num) {
		int offset = fdp->pos % BLOCK_SIZE;
		size_t size_to_write = MIN(remain_bytes, (size_t)BLOCK_SIZE);

		if (size_to_write + offset > BLOCK_SIZE)
			size_to_write = BLOCK_SIZE - offset;

		res = read_block(fdp, start_block_num, block);
		if (res == TEE_ERROR_ITEM_NOT_FOUND)
			memset(block, 0, BLOCK_SIZE);
		else if (res != TEE_SUCCESS)
			goto exit;

		if (data_ptr)
			memcpy(block + offset, data_ptr, size_to_write);
		else
			memset(block + offset, 0, size_to_write);

		res = write_block(fdp, start_block_num, block, new_meta);
		if (res != TEE_SUCCESS)
			goto exit;

		if (data_ptr)
			data_ptr += size_to_write;
		remain_bytes -= size_to_write;
		start_block_num++;
		fdp->pos += size_to_write;
	}

	if (fdp->pos > (tee_fs_off_t)new_meta->info.length)
		new_meta->info.length = fdp->pos;

exit:
	free(block);
	if (res != TEE_SUCCESS)
		fdp->pos = orig_pos;
	return res;
}

static TEE_Result open_internal(const char *file, bool create,
				struct tee_file_handle **fh)
{
	TEE_Result res;
	size_t len;
	struct tee_fs_fd *fdp = NULL;

	if (!file)
		return TEE_ERROR_BAD_PARAMETERS;

	len = strlen(file) + 1;
	if (len > TEE_FS_NAME_MAX)
		return TEE_ERROR_BAD_PARAMETERS;

	fdp = calloc(1, sizeof(struct tee_fs_fd));
	if (!fdp)
		return TEE_ERROR_OUT_OF_MEMORY;
	fdp->fd = -1;

	mutex_lock(&ree_fs_mutex);

	if (create)
		res = create_meta(fdp, file);
	else
		res = read_meta(fdp, file);

	if (res == TEE_SUCCESS) {
		*fh = (struct tee_file_handle *)fdp;
	} else {
		if (fdp->fd != -1)
			tee_fs_rpc_close(OPTEE_MSG_RPC_CMD_FS, fdp->fd);
		if (create)
			tee_fs_rpc_remove(OPTEE_MSG_RPC_CMD_FS, file);
		free(fdp);
	}

	mutex_unlock(&ree_fs_mutex);
	return res;
}

static TEE_Result ree_fs_open(const char *file, struct tee_file_handle **fh)
{
	return open_internal(file, false, fh);
}

static TEE_Result ree_fs_create(const char *file, struct tee_file_handle **fh)
{
	return open_internal(file, true, fh);
}

static void ree_fs_close(struct tee_file_handle **fh)
{
	struct tee_fs_fd *fdp = (struct tee_fs_fd *)*fh;

	if (fdp) {
		tee_fs_rpc_close(OPTEE_MSG_RPC_CMD_FS, fdp->fd);
		free(fdp);
		*fh = NULL;
	}
}

static TEE_Result ree_fs_seek(struct tee_file_handle *fh, int32_t offset,
			      TEE_Whence whence, int32_t *new_offs)
{
	TEE_Result res;
	tee_fs_off_t new_pos;
	size_t filelen;
	struct tee_fs_fd *fdp = (struct tee_fs_fd *)fh;

	mutex_lock(&ree_fs_mutex);

	DMSG("offset=%d, whence=%d", (int)offset, whence);

	filelen = fdp->meta.info.length;

	switch (whence) {
	case TEE_DATA_SEEK_SET:
		new_pos = offset;
		break;

	case TEE_DATA_SEEK_CUR:
		new_pos = fdp->pos + offset;
		break;

	case TEE_DATA_SEEK_END:
		new_pos = filelen + offset;
		break;

	default:
		res = TEE_ERROR_BAD_PARAMETERS;
		goto exit;
	}

	if (new_pos < 0)
		new_pos = 0;

	if (new_pos > TEE_DATA_MAX_POSITION) {
		EMSG("Position is beyond TEE_DATA_MAX_POSITION");
		res = TEE_ERROR_BAD_PARAMETERS;
		goto exit;
	}

	fdp->pos = new_pos;
	if (new_offs)
		*new_offs = new_pos;
	res = TEE_SUCCESS;
exit:
	mutex_unlock(&ree_fs_mutex);
	return res;
}

/*
 * To ensure atomic truncate operation, we can:
 *
 *  - update file length to new length
 *  - commit new meta
 *
 * To ensure atomic extend operation, we can:
 *
 *  - update file length to new length
 *  - allocate and fill zero data to new blocks
 *  - commit new meta
 *
 * Any failure before committing new meta is considered as
 * update failed, and the file content will not be updated
 */
static TEE_Result ree_fs_ftruncate_internal(struct tee_fs_fd *fdp,
					    tee_fs_off_t new_file_len)
{
	TEE_Result res;
	size_t old_file_len = fdp->meta.info.length;
	struct tee_fs_file_meta new_meta;

	if (new_file_len > MAX_FILE_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	new_meta = fdp->meta;
	new_meta.info.length = new_file_len;

	if ((size_t)new_file_len > old_file_len) {
		size_t ext_len = new_file_len - old_file_len;
		int orig_pos = fdp->pos;

		fdp->pos = old_file_len;
		res = out_of_place_write(fdp, NULL, ext_len, &new_meta);
		fdp->pos = orig_pos;
		if (res != TEE_SUCCESS)
			return res;
	}

	return commit_meta_file(fdp, &new_meta);
}

static TEE_Result ree_fs_read(struct tee_file_handle *fh, void *buf,
			      size_t *len)
{
	TEE_Result res;
	int start_block_num;
	int end_block_num;
	size_t remain_bytes;
	uint8_t *data_ptr = buf;
	uint8_t *block = NULL;
	struct tee_fs_fd *fdp = (struct tee_fs_fd *)fh;

	mutex_lock(&ree_fs_mutex);

	remain_bytes = *len;
	if ((fdp->pos + remain_bytes) < remain_bytes ||
	    fdp->pos > (tee_fs_off_t)fdp->meta.info.length)
		remain_bytes = 0;
	else if (fdp->pos + (tee_fs_off_t)remain_bytes >
		(tee_fs_off_t)fdp->meta.info.length)
		remain_bytes = fdp->meta.info.length - fdp->pos;

	*len = remain_bytes;

	if (!remain_bytes) {
		res = TEE_SUCCESS;
		goto exit;
	}

	start_block_num = pos_to_block_num(fdp->pos);
	end_block_num = pos_to_block_num(fdp->pos + remain_bytes - 1);

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

		res = read_block(fdp, start_block_num, block);
		if (res != TEE_SUCCESS) {
			if (res == TEE_ERROR_MAC_INVALID)
				res = TEE_ERROR_CORRUPT_OBJECT;
			goto exit;
		}

		memcpy(data_ptr, block + offset, size_to_read);

		data_ptr += size_to_read;
		remain_bytes -= size_to_read;
		fdp->pos += size_to_read;

		start_block_num++;
	}
	res = TEE_SUCCESS;
exit:
	mutex_unlock(&ree_fs_mutex);
	free(block);
	return res;
}

/*
 * To ensure atomicity of write operation, we need to
 * do the following steps:
 * (The sequence of operations is very important)
 *
 *  - Create a new backup version of meta file as a copy
 *    of current meta file.
 *  - For each blocks to write:
 *    - Create new backup version for current block.
 *    - Write data to new backup version.
 *    - Update the new meta file accordingly.
 *  - Write the new meta file.
 *
 * (Any failure in above steps is considered as update failed,
 *  and the file content will not be updated)
 */
static TEE_Result ree_fs_write(struct tee_file_handle *fh, const void *buf,
			       size_t len)
{
	TEE_Result res;
	struct tee_fs_file_meta new_meta;
	struct tee_fs_fd *fdp = (struct tee_fs_fd *)fh;
	size_t file_size;

	if (!len)
		return TEE_SUCCESS;

	mutex_lock(&ree_fs_mutex);

	file_size = fdp->meta.info.length;

	if ((fdp->pos + len) > MAX_FILE_SIZE || (fdp->pos + len) < len) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto exit;
	}

	if (file_size < (size_t)fdp->pos) {
		res = ree_fs_ftruncate_internal(fdp, fdp->pos);
		if (res != TEE_SUCCESS)
			goto exit;
	}

	new_meta = fdp->meta;
	res = out_of_place_write(fdp, buf, len, &new_meta);
	if (res != TEE_SUCCESS)
		goto exit;

	res = commit_meta_file(fdp, &new_meta);
exit:
	mutex_unlock(&ree_fs_mutex);
	return res;
}

static TEE_Result ree_fs_rename(const char *old, const char *new,
				bool overwrite)
{
	TEE_Result res;

	mutex_lock(&ree_fs_mutex);
	res = tee_fs_rpc_rename(OPTEE_MSG_RPC_CMD_FS, old, new, overwrite);
	mutex_unlock(&ree_fs_mutex);

	return res;
}

static TEE_Result ree_fs_remove(const char *file)
{
	TEE_Result res;

	mutex_lock(&ree_fs_mutex);
	res = tee_fs_rpc_remove(OPTEE_MSG_RPC_CMD_FS, file);
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
	.seek = ree_fs_seek,
	.truncate = ree_fs_truncate,
	.rename = ree_fs_rename,
	.remove = ree_fs_remove,
	.opendir = ree_fs_opendir_rpc,
	.closedir = ree_fs_closedir_rpc,
	.readdir = ree_fs_readdir_rpc,
};
