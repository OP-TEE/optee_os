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
#include <kernel/handle.h>
#include <kernel/mutex.h>
#include <kernel/panic.h>
#include <kernel/thread.h>
#include <mm/core_memprot.h>
#include <optee_msg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string_ext.h>
#include <string.h>
#include <sys/queue.h>
#include <tee/tee_cryp_provider.h>
#include <tee/tee_fs_defs.h>
#include <tee/tee_fs.h>
#include <tee/tee_fs_key_manager.h>
#include <tee/tee_fs_rpc.h>
#include <trace.h>
#include <utee_defines.h>
#include <util.h>

#define BLOCK_FILE_SHIFT	12

#define BLOCK_FILE_SIZE		(1 << BLOCK_FILE_SHIFT)

#define MAX_NUM_CACHED_BLOCKS	1

#define NUM_BLOCKS_PER_FILE	1024

#define MAX_FILE_SIZE	(BLOCK_FILE_SIZE * NUM_BLOCKS_PER_FILE)

struct tee_file_handle;

struct tee_fs_file_info {
	size_t length;
	uint32_t backup_version_table[NUM_BLOCKS_PER_FILE / 32];
};

struct tee_fs_file_meta {
	struct tee_fs_file_info info;
	uint8_t encrypted_fek[TEE_FS_KM_FEK_SIZE];
	uint8_t backup_version;
};

TAILQ_HEAD(block_head, block);

struct block {
	TAILQ_ENTRY(block) list;
	int block_num;
	uint8_t *data;
	size_t data_size;
};

struct block_cache {
	struct block_head block_lru;
	uint8_t cached_block_num;
};

struct tee_fs_fd {
	struct tee_fs_file_meta meta;
	tee_fs_off_t pos;
	uint32_t flags;
	bool is_new_file;
	char *filename;
	struct block_cache block_cache;
};

static inline int pos_to_block_num(int position)
{
	return position >> BLOCK_FILE_SHIFT;
}

static inline int get_last_block_num(size_t size)
{
	return pos_to_block_num(size - 1);
}

static inline uint8_t get_backup_version_of_block(
		struct tee_fs_file_meta *meta,
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

static struct handle_db fs_handle_db = HANDLE_DB_INITIALIZER;

static struct mutex ree_fs_mutex = MUTEX_INITIALIZER;

/*
 * We split a TEE file into multiple blocks and store them
 * on REE filesystem. A TEE file is represented by a REE file
 * called meta and a number of REE files called blocks. Meta
 * file is used for storing file information, e.g. file size
 * and backup version of each block.
 *
 * REE files naming rule is as follows:
 *
 *   <tee_file_name>/meta.<backup_version>
 *   <tee_file_name>/block0.<backup_version>
 *   ...
 *   <tee_file_name>/block15.<backup_version>
 *
 * Backup_version is used to support atomic update operation.
 * Original file will not be updated, instead we create a new
 * version of the same file and update the new file instead.
 *
 * The backup_version of each block file is stored in meta
 * file, the meta file itself also has backup_version, the update is
 * successful after new version of meta has been written.
 */
#define REE_FS_NAME_MAX (TEE_FS_NAME_MAX + 20)


static int ree_fs_mkdir_rpc(const char *path, tee_fs_mode_t mode)
{
	return tee_fs_rpc_mkdir(OPTEE_MSG_RPC_CMD_FS, path, mode);
}

static TEE_Result ree_fs_opendir_rpc(const char *name, struct tee_fs_dir **d)

{
	struct tee_fs_dir *d2 = tee_fs_rpc_opendir(OPTEE_MSG_RPC_CMD_FS, name);

	if (!d2)
		return TEE_ERROR_ITEM_NOT_FOUND;

	*d = d2;
	return TEE_SUCCESS;
}

static void ree_fs_closedir_rpc(struct tee_fs_dir *d)
{
	tee_fs_rpc_closedir(OPTEE_MSG_RPC_CMD_FS, d);
}

static TEE_Result ree_fs_readdir_rpc(struct tee_fs_dir *d,
				     struct tee_fs_dirent **ent)
{
	struct tee_fs_dirent *e = tee_fs_rpc_readdir(OPTEE_MSG_RPC_CMD_FS, d);

	if (!e)
		return TEE_ERROR_ITEM_NOT_FOUND;

	*ent = e;
	return TEE_SUCCESS;
}

static int ree_fs_rmdir_rpc(const char *name)
{
	return tee_fs_rpc_rmdir(OPTEE_MSG_RPC_CMD_FS, name);
}

static int ree_fs_access_rpc(const char *name, int mode)
{
	return tee_fs_rpc_access(OPTEE_MSG_RPC_CMD_FS, name, mode);
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

static int __remove_block_file(struct tee_fs_fd *fdp, size_t block_num,
				bool toggle)
{
	TEE_Result res;
	char block_path[REE_FS_NAME_MAX];
	uint8_t version = get_backup_version_of_block(&fdp->meta, block_num);

	if (toggle)
		version = !version;

	get_block_filepath(fdp->filename, block_num, version, block_path);
	DMSG("%s", block_path);

	res = tee_fs_rpc_new_remove(OPTEE_MSG_RPC_CMD_FS, block_path);
	if (res == TEE_SUCCESS || res == TEE_ERROR_ITEM_NOT_FOUND)
		return 0; /* ignore it if file not found */
	return -1;
}

static int remove_block_file(struct tee_fs_fd *fdp, size_t block_num)
{
	DMSG("remove block%zd", block_num);
	return __remove_block_file(fdp, block_num, false);
}

static int remove_outdated_block(struct tee_fs_fd *fdp, size_t block_num)
{
	DMSG("remove outdated block%zd", block_num);
	return __remove_block_file(fdp, block_num, true);
}

/*
 * encrypted_fek: as input for META_FILE and BLOCK_FILE
 */
static TEE_Result encrypt_and_write_file(const char *file_name,
		enum tee_fs_file_type file_type,
		void *data_in, size_t data_in_size,
		uint8_t *encrypted_fek)
{
	TEE_Result res;
	TEE_Result res2;
	struct tee_fs_rpc_operation op;
	void *ciphertext;
	size_t header_size = tee_fs_get_header_size(file_type);
	size_t ciphertext_size = header_size + data_in_size;
	int fd;

	res = tee_fs_rpc_new_open(OPTEE_MSG_RPC_CMD_FS, file_name, &fd);
	if (res != TEE_SUCCESS) {
		if (res != TEE_ERROR_ITEM_NOT_FOUND)
			return res;
		res = tee_fs_rpc_new_create(OPTEE_MSG_RPC_CMD_FS, file_name,
					    &fd);
		if (res != TEE_SUCCESS)
			return res;
	}

	res = tee_fs_rpc_new_write_init(&op, OPTEE_MSG_RPC_CMD_FS, fd, 0,
					ciphertext_size, &ciphertext);
	if (res != TEE_SUCCESS)
		goto out;

	res = tee_fs_encrypt_file(file_type, data_in, data_in_size,
				  ciphertext, &ciphertext_size, encrypted_fek);
	if (res != TEE_SUCCESS)
		goto out;

	res = tee_fs_rpc_new_write_final(&op);
out:
	res2 = tee_fs_rpc_new_close(OPTEE_MSG_RPC_CMD_FS, fd);
	if (res == TEE_SUCCESS)
		return res2;
	return res;
}

/*
 * encrypted_fek: as output for META_FILE
 *                as input for BLOCK_FILE
 */
static TEE_Result read_and_decrypt_file(const char *file_name,
		enum tee_fs_file_type file_type,
		void *data_out, size_t *data_out_size,
		uint8_t *encrypted_fek)
{
	TEE_Result res;
	TEE_Result res2;
	struct tee_fs_rpc_operation op;
	size_t bytes;
	void *ciphertext;
	int fd;

	res = tee_fs_rpc_new_open(OPTEE_MSG_RPC_CMD_FS, file_name, &fd);
	if (res != TEE_SUCCESS)
		return res;

	bytes = *data_out_size + tee_fs_get_header_size(file_type);
	res = tee_fs_rpc_new_read_init(&op, OPTEE_MSG_RPC_CMD_FS, fd, 0,
				       bytes, &ciphertext);
	if (res != TEE_SUCCESS)
		goto out;

	res = tee_fs_rpc_new_read_final(&op, &bytes);
	if (res != TEE_SUCCESS)
		goto out;

	res = tee_fs_decrypt_file(file_type, ciphertext, bytes, data_out,
				  data_out_size, encrypted_fek);
	if (res != TEE_SUCCESS)
		res = TEE_ERROR_CORRUPT_OBJECT;
out:
	res2 = tee_fs_rpc_new_close(OPTEE_MSG_RPC_CMD_FS, fd);
	if (res == TEE_SUCCESS)
		return res2;
	return res;
}

static TEE_Result write_meta_file(const char *filename,
		struct tee_fs_file_meta *meta)
{
	char meta_path[REE_FS_NAME_MAX];

	get_meta_filepath(filename, meta->backup_version, meta_path);

	return encrypt_and_write_file(meta_path, META_FILE,
			(void *)&meta->info, sizeof(meta->info),
			meta->encrypted_fek);
}

static TEE_Result create_meta(struct tee_fs_fd *fdp)
{
	TEE_Result res;

	memset(fdp->meta.info.backup_version_table, 0xff,
		sizeof(fdp->meta.info.backup_version_table));
	fdp->meta.info.length = 0;

	res = tee_fs_generate_fek(fdp->meta.encrypted_fek, TEE_FS_KM_FEK_SIZE);
	if (res != TEE_SUCCESS)
		return res;

	fdp->meta.backup_version = 0;

	return write_meta_file(fdp->filename, &fdp->meta);
}

static TEE_Result commit_meta_file(struct tee_fs_fd *fdp,
				   struct tee_fs_file_meta *new_meta)
{
	TEE_Result res;
	uint8_t old_version;
	char meta_path[REE_FS_NAME_MAX];

	old_version = new_meta->backup_version;
	new_meta->backup_version = !new_meta->backup_version;

	res = write_meta_file(fdp->filename, new_meta);
	if (res != TEE_SUCCESS)
		return res;

	/*
	 * From now on the new meta is successfully committed,
	 * change tee_fs_fd accordingly
	 */
	fdp->meta = *new_meta;

	/*
	 * Remove outdated meta file, there is nothing we can
	 * do if we fail here, but that is OK because both
	 * new & old version of block files are kept. The context
	 * of the file is still consistent.
	 */
	get_meta_filepath(fdp->filename, old_version, meta_path);
	tee_fs_rpc_new_remove(OPTEE_MSG_RPC_CMD_FS, meta_path);

	return res;
}

static TEE_Result read_meta_file(const char *meta_path,
		struct tee_fs_file_meta *meta)
{
	size_t meta_info_size = sizeof(struct tee_fs_file_info);

	return read_and_decrypt_file(meta_path, META_FILE,
				     &meta->info, &meta_info_size,
				     meta->encrypted_fek);
}

static TEE_Result read_meta(struct tee_fs_fd *fdp)
{
	TEE_Result res;
	char meta_path[REE_FS_NAME_MAX];

	get_meta_filepath(fdp->filename, fdp->meta.backup_version, meta_path);
	res = read_meta_file(meta_path, &fdp->meta);
	if (res != TEE_SUCCESS) {
		TEE_Result res2;

		fdp->meta.backup_version = !fdp->meta.backup_version;
		get_meta_filepath(fdp->filename, fdp->meta.backup_version,
				  meta_path);
		res2 = read_meta_file(meta_path, &fdp->meta);
		if (res2 != TEE_ERROR_ITEM_NOT_FOUND)
			return res2;
	}

	return res;
}

static bool is_block_file_exist(struct tee_fs_file_meta *meta,
					size_t block_num)
{
	size_t file_size = meta->info.length;

	if (file_size == 0)
		return false;

	return (block_num <= (size_t)get_last_block_num(file_size));
}

static TEE_Result read_block_from_storage(struct tee_fs_fd *fdp,
					  struct block *b)
{
	TEE_Result res = TEE_SUCCESS;
	uint8_t *plaintext = b->data;
	char block_path[REE_FS_NAME_MAX];
	size_t block_file_size = BLOCK_FILE_SIZE;
	uint8_t version = get_backup_version_of_block(&fdp->meta, b->block_num);

	if (!is_block_file_exist(&fdp->meta, b->block_num))
		goto exit;

	get_block_filepath(fdp->filename, b->block_num, version,
			block_path);

	res = read_and_decrypt_file(block_path, BLOCK_FILE,
			plaintext, &block_file_size,
			fdp->meta.encrypted_fek);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to read and decrypt file");
		goto exit;
	}
	b->data_size = block_file_size;
	DMSG("Successfully read and decrypt block%d from storage, size=%zd",
		b->block_num, b->data_size);
exit:
	return res;
}

static int flush_block_to_storage(struct tee_fs_fd *fdp, struct block *b,
					 struct tee_fs_file_meta *new_meta)
{
	TEE_Result res;
	size_t block_num = b->block_num;
	char block_path[REE_FS_NAME_MAX];
	uint8_t new_version =
		!get_backup_version_of_block(&fdp->meta, block_num);

	get_block_filepath(fdp->filename, block_num, new_version, block_path);

	res = encrypt_and_write_file(block_path, BLOCK_FILE, b->data,
				     b->data_size, new_meta->encrypted_fek);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to encrypt and write block file");
		goto fail;
	}

	DMSG("Successfully encrypt and write block%d to storage, size=%zd",
		b->block_num, b->data_size);
	toggle_backup_version_of_block(new_meta, block_num);

	return 0;
fail:
	return -1;
}

static struct block *alloc_block(void)
{
	struct block *c;

	c = malloc(sizeof(struct block));
	if (!c)
		return NULL;

	c->data = malloc(BLOCK_FILE_SIZE);
	if (!c->data) {
		EMSG("unable to alloc memory for block data");
		goto exit;
	}

	c->block_num = -1;
	c->data_size = 0;

	return c;

exit:
	free(c);
	return NULL;
}

#ifdef CFG_FS_BLOCK_CACHE
static void free_block(struct block *b)
{
	if (b) {
		free(b->data);
		free(b);
	}
}

static inline bool is_block_data_invalid(struct block *b)
{
	return (b->data_size == 0);
}

static void get_block_from_cache(struct block_cache *cache,
			int block_num, struct block **out_block)
{
	struct block *b, *found = NULL;

	DMSG("Try to find block%d in cache", block_num);
	TAILQ_FOREACH(b, &cache->block_lru, list) {
		if (b->block_num == block_num) {
			DMSG("Found in cache");
			found = b;
			break;
		}
	}

	if (found) {
		TAILQ_REMOVE(&cache->block_lru, found, list);
		TAILQ_INSERT_HEAD(&cache->block_lru, found, list);
		*out_block = found;
		return;
	}

	DMSG("Not found, reuse oldest block on LRU list");
	b = TAILQ_LAST(&cache->block_lru, block_head);
	TAILQ_REMOVE(&cache->block_lru, b, list);
	TAILQ_INSERT_HEAD(&cache->block_lru, b, list);
	b->block_num = block_num;
	b->data_size = 0;
	*out_block = b;
}

static int init_block_cache(struct block_cache *cache)
{
	struct block *b;

	TAILQ_INIT(&cache->block_lru);
	cache->cached_block_num = 0;

	while (cache->cached_block_num < MAX_NUM_CACHED_BLOCKS) {

		b = alloc_block();
		if (!b) {
			EMSG("Failed to alloc block");
			goto fail;
		} else {
			TAILQ_INSERT_HEAD(&cache->block_lru, b, list);
			cache->cached_block_num++;
		}
	}
	return 0;

fail:
	TAILQ_FOREACH(b, &cache->block_lru, list)
		free_block(b);
	return -1;
}

static void destroy_block_cache(struct block_cache *cache)
{
	struct block *b, *next;

	TAILQ_FOREACH_SAFE(b, &cache->block_lru, list, next) {
		TAILQ_REMOVE(&cache->block_lru, b, list);
		free_block(b);
	}
}
#else
static int init_block_cache(struct block_cache *cache __unused)
{
	return 0;
}

static void destroy_block_cache(struct block_cache *cache __unused)
{
}
#endif

static void write_data_to_block(struct block *b, int offset,
				void *buf, size_t len)
{
	DMSG("Write %zd bytes to block%d", len, b->block_num);
	memcpy(b->data + offset, buf, len);
	if (offset + len > b->data_size) {
		b->data_size = offset + len;
		DMSG("Extend block%d size to %zd bytes",
				b->block_num, b->data_size);
	}
}

static void read_data_from_block(struct block *b, int offset,
				void *buf, size_t len)
{
	DMSG("Read %zd bytes from block%d", len, b->block_num);
	if (offset + len > b->data_size)
		panic("Exceeding block size");
	memcpy(buf, b->data + offset, len);
}

#ifdef CFG_FS_BLOCK_CACHE
static struct block *read_block_with_cache(struct tee_fs_fd *fdp, int block_num)
{
	struct block *b;

	get_block_from_cache(&fdp->block_cache, block_num, &b);
	if (is_block_data_invalid(b))
		if (read_block_from_storage(fdp, b)) {
			EMSG("Unable to read block%d from storage",
					block_num);
			return NULL;
		}

	return b;
}
#else

static struct block *read_block_no_cache(struct tee_fs_fd *fdp, int block_num)
{
	static struct block *b;
	TEE_Result res;

	if (!b)
		b = alloc_block();
	b->block_num = block_num;

	res = read_block_from_storage(fdp, b);
	if (res != TEE_SUCCESS)
		EMSG("Unable to read block%d from storage",
				block_num);

	return res != TEE_SUCCESS ? NULL : b;
}
#endif

static struct block_operations block_ops = {
#ifdef CFG_FS_BLOCK_CACHE
	.read = read_block_with_cache,
#else
	.read = read_block_no_cache,
#endif
	.write = flush_block_to_storage,
};

static TEE_Result out_of_place_write(struct tee_fs_fd *fdp, const void *buf,
		size_t len, struct tee_fs_file_meta *new_meta)
{
	int start_block_num = pos_to_block_num(fdp->pos);
	int end_block_num = pos_to_block_num(fdp->pos + len - 1);
	size_t remain_bytes = len;
	uint8_t *data_ptr = (uint8_t *)buf;
	int orig_pos = fdp->pos;

	while (start_block_num <= end_block_num) {
		int offset = fdp->pos % BLOCK_FILE_SIZE;
		struct block *b;
		size_t size_to_write = (remain_bytes > BLOCK_FILE_SIZE) ?
			BLOCK_FILE_SIZE : remain_bytes;

		if (size_to_write + offset > BLOCK_FILE_SIZE)
			size_to_write = BLOCK_FILE_SIZE - offset;

		b = block_ops.read(fdp, start_block_num);
		if (!b)
			goto failed;

		DMSG("Write data, offset: %d, size_to_write: %zd",
			offset, size_to_write);
		write_data_to_block(b, offset, data_ptr, size_to_write);

		if (block_ops.write(fdp, b, new_meta)) {
			EMSG("Unable to wrtie block%d to storage",
					b->block_num);
			goto failed;
		}

		data_ptr += size_to_write;
		remain_bytes -= size_to_write;
		start_block_num++;
		fdp->pos += size_to_write;
	}

	if (fdp->pos > (tee_fs_off_t)new_meta->info.length)
		new_meta->info.length = fdp->pos;

	return TEE_SUCCESS;
failed:
	fdp->pos = orig_pos;
	return TEE_ERROR_GENERIC;
}

static TEE_Result create_hard_link(const char *old_dir, const char *new_dir,
				   const char *filename)
{
	char old_path[REE_FS_NAME_MAX];
	char new_path[REE_FS_NAME_MAX];

	snprintf(old_path, REE_FS_NAME_MAX, "%s/%s",
			old_dir, filename);
	snprintf(new_path, REE_FS_NAME_MAX, "%s/%s",
			new_dir, filename);

	DMSG("%s -> %s", old_path, new_path);
	if (tee_fs_rpc_link(OPTEE_MSG_RPC_CMD_FS, old_path, new_path))
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

static TEE_Result unlink_tee_file(const char *file)
{
	TEE_Result res;
	size_t len = strlen(file) + 1;
	struct tee_fs_dirent *dirent;
	struct tee_fs_dir *dir;

	DMSG("file=%s", file);

	if (len > TEE_FS_NAME_MAX)
		return TEE_ERROR_GENERIC;

	res = ree_fs_opendir_rpc(file, &dir);
	if (res != TEE_SUCCESS)
		return res;

	res = ree_fs_readdir_rpc(dir, &dirent);
	while (res == TEE_SUCCESS) {
		char path[REE_FS_NAME_MAX];

		snprintf(path, REE_FS_NAME_MAX, "%s/%s",
			file, dirent->d_name);

		DMSG("unlink %s", path);
		res = tee_fs_rpc_new_remove(OPTEE_MSG_RPC_CMD_FS, path);
		if (res != TEE_SUCCESS) {
			ree_fs_closedir_rpc(dir);
			return res;
		}
		res = ree_fs_readdir_rpc(dir, &dirent);
	}

	ree_fs_closedir_rpc(dir);

	return ree_fs_rmdir_rpc(file);
}

static TEE_Result open_internal(const char *file, bool create, bool overwrite,
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

	mutex_lock(&ree_fs_mutex);

	/* init internal status */
	if (init_block_cache(&fdp->block_cache)) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_free_fd;
	}

	fdp->filename = strdup(file);
	if (!fdp->filename) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_destroy_block_cache;
	}

	res = read_meta(fdp);
	if (res == TEE_SUCCESS) {
		if (overwrite) {
			res = TEE_ERROR_ACCESS_CONFLICT;
			goto exit_free_filename;
		}
	} else if (res == TEE_ERROR_ITEM_NOT_FOUND) {
		if (!create)
			goto exit_free_filename;
		res = create_meta(fdp);
		if (res != TEE_SUCCESS)
			goto exit_free_filename;
	} else {
		goto exit_free_filename;
	}

	*fh = (struct tee_file_handle *)fdp;
	goto exit;

exit_free_filename:
	free(fdp->filename);
exit_destroy_block_cache:
	destroy_block_cache(&fdp->block_cache);
exit_free_fd:
	free(fdp);
exit:
	mutex_unlock(&ree_fs_mutex);
	return res;
}

static TEE_Result ree_fs_open(const char *file, struct tee_file_handle **fh)
{
	return open_internal(file, false, false, fh);
}

static TEE_Result ree_fs_create(const char *file, bool overwrite,
				struct tee_file_handle **fh)
{
	return open_internal(file, true, overwrite, fh);
}

static void ree_fs_close(struct tee_file_handle **fh)
{
	struct tee_fs_fd *fdp = (struct tee_fs_fd *)*fh;

	if (fdp) {
		destroy_block_cache(&fdp->block_cache);
		free(fdp->filename);
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
 */
static TEE_Result ree_fs_ftruncate_internal(struct tee_fs_fd *fdp,
					    tee_fs_off_t new_file_len)
{
	TEE_Result res;
	size_t old_file_len = fdp->meta.info.length;
	struct tee_fs_file_meta new_meta;

	if ((size_t)new_file_len == old_file_len) {
		DMSG("Ignore due to file length does not changed");
		return TEE_SUCCESS;
	}

	if (new_file_len > MAX_FILE_SIZE) {
		EMSG("Over maximum file size(%d)", MAX_FILE_SIZE);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	new_meta = fdp->meta;
	new_meta.info.length = new_file_len;

	if ((size_t)new_file_len < old_file_len) {
		int old_block_num = get_last_block_num(old_file_len);
		int new_block_num = get_last_block_num(new_file_len);

		DMSG("Truncate file length to %zu", (size_t)new_file_len);

		res = commit_meta_file(fdp, &new_meta);
		if (res != TEE_SUCCESS)
			return res;

		/* now we are safe to free unused blocks */
		while (old_block_num > new_block_num) {
			if (remove_block_file(fdp, old_block_num)) {
				IMSG("Warning: Failed to free block: %d",
						old_block_num);
			}

			old_block_num--;
		}

	} else {
		size_t ext_len = new_file_len - old_file_len;
		int orig_pos = fdp->pos;
		uint8_t *buf;

		buf = calloc(1, BLOCK_FILE_SIZE);
		if (!buf) {
			EMSG("Failed to allocate buffer, size=%d",
					BLOCK_FILE_SIZE);
			return TEE_ERROR_OUT_OF_MEMORY;
		}

		DMSG("Extend file length to %zu", (size_t)new_file_len);

		fdp->pos = old_file_len;

		res = TEE_SUCCESS;
		while (ext_len > 0) {
			size_t data_len = (ext_len > BLOCK_FILE_SIZE) ?
					BLOCK_FILE_SIZE : ext_len;

			DMSG("fill len=%zu", data_len);
			res = out_of_place_write(fdp, buf, data_len, &new_meta);
			if (res != TEE_SUCCESS) {
				EMSG("Failed to fill data");
				break;
			}

			ext_len -= data_len;
		}

		free(buf);
		fdp->pos = orig_pos;

		if (res == TEE_SUCCESS) {
			res = commit_meta_file(fdp, &new_meta);
			if (res != TEE_SUCCESS)
				EMSG("Failed to commit meta file");
		}
	}

	return res;
}

static TEE_Result ree_fs_read(struct tee_file_handle *fh, void *buf,
			      size_t *len)
{
	TEE_Result res;
	int start_block_num;
	int end_block_num;
	size_t remain_bytes;
	uint8_t *data_ptr = buf;
	struct tee_fs_fd *fdp = (struct tee_fs_fd *)fh;

	mutex_lock(&ree_fs_mutex);

	remain_bytes = *len;
	if ((fdp->pos + remain_bytes) < remain_bytes ||
	    fdp->pos > (tee_fs_off_t)fdp->meta.info.length)
		remain_bytes = 0;
	else if (fdp->pos + remain_bytes > fdp->meta.info.length)
		remain_bytes = fdp->meta.info.length - fdp->pos;

	*len = remain_bytes;

	if (!remain_bytes) {
		res = TEE_SUCCESS;
		goto exit;
	}

	DMSG("%s, data len=%zu", fdp->filename, remain_bytes);

	start_block_num = pos_to_block_num(fdp->pos);
	end_block_num = pos_to_block_num(fdp->pos + remain_bytes - 1);
	DMSG("start_block_num:%d, end_block_num:%d",
		start_block_num, end_block_num);

	while (start_block_num <= end_block_num) {
		struct block *b;
		int offset = fdp->pos % BLOCK_FILE_SIZE;
		size_t size_to_read = remain_bytes > BLOCK_FILE_SIZE ?
			BLOCK_FILE_SIZE : remain_bytes;

		if (size_to_read + offset > BLOCK_FILE_SIZE)
			size_to_read = BLOCK_FILE_SIZE - offset;

		DMSG("block_num:%d, offset:%d, size_to_read: %zd",
			start_block_num, offset, size_to_read);

		b = block_ops.read(fdp, start_block_num);
		if (!b) {
			res = TEE_ERROR_CORRUPT_OBJECT;
			goto exit;
		}

		read_data_from_block(b, offset, data_ptr, size_to_read);
		data_ptr += size_to_read;
		remain_bytes -= size_to_read;
		fdp->pos += size_to_read;

		start_block_num++;
	}
	res = TEE_SUCCESS;
exit:
	mutex_unlock(&ree_fs_mutex);
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
 *
 * After previous step the update is considered complete, but
 * we should do the following clean-up step(s):
 *
 *  - Delete old meta file.
 *  - Remove old block files.
 *
 * (Any failure in above steps is considered as a successfully
 *  update)
 */
static TEE_Result ree_fs_write(struct tee_file_handle *fh, const void *buf,
			       size_t len)
{
	TEE_Result res;
	struct tee_fs_file_meta new_meta;
	struct tee_fs_fd *fdp = (struct tee_fs_fd *)fh;
	size_t file_size;
	tee_fs_off_t orig_pos;
	int start_block_num;
	int end_block_num;


	if (!len)
		return TEE_SUCCESS;

	mutex_lock(&ree_fs_mutex);

	file_size = fdp->meta.info.length;
	orig_pos = fdp->pos;

	if ((fdp->pos + len) > MAX_FILE_SIZE || (fdp->pos + len) < len) {
		EMSG("Over maximum file size(%d)", MAX_FILE_SIZE);
		res = TEE_ERROR_BAD_PARAMETERS;
		goto exit;
	}

	DMSG("%s, data len=%zu", fdp->filename, len);
	if (file_size < (size_t)fdp->pos) {
		DMSG("File hole detected, try to extend file size");
		res = ree_fs_ftruncate_internal(fdp, fdp->pos);
		if (res != TEE_SUCCESS)
			goto exit;
	}

	new_meta = fdp->meta;
	res = out_of_place_write(fdp, buf, len, &new_meta);
	if (res != TEE_SUCCESS)
		goto exit;

	res = commit_meta_file(fdp, &new_meta);
	if (res != TEE_SUCCESS)
		goto exit;

	/* we are safe to free old blocks */
	start_block_num = pos_to_block_num(orig_pos);
	end_block_num = pos_to_block_num(fdp->pos - 1);
	while (start_block_num <= end_block_num) {
		if (remove_outdated_block(fdp, start_block_num))
			IMSG("Warning: Failed to free old block: %d",
				start_block_num);

		start_block_num++;
	}
exit:
	mutex_unlock(&ree_fs_mutex);
	return res;
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
static TEE_Result ree_fs_rename_internal(const char *old, const char *new)
{
	TEE_Result res;
	size_t old_len;
	size_t new_len;
	size_t meta_count = 0;
	struct tee_fs_dir *old_dir;
	struct tee_fs_dirent *dirent;
	char *meta_filename = NULL;

	DMSG("old=%s, new=%s", old, new);

	old_len = strlen(old) + 1;
	new_len = strlen(new) + 1;

	if (old_len > TEE_FS_NAME_MAX || new_len > TEE_FS_NAME_MAX)
		return TEE_ERROR_BAD_PARAMETERS;

	if (ree_fs_mkdir_rpc(new, TEE_FS_S_IRUSR | TEE_FS_S_IWUSR))
		return TEE_ERROR_GENERIC;

	res = ree_fs_opendir_rpc(old, &old_dir);
	if (res != TEE_SUCCESS)
		return res;

	res = ree_fs_readdir_rpc(old_dir, &dirent);
	while (res == TEE_SUCCESS) {
		if (!strncmp(dirent->d_name, "meta.", 5)) {
			meta_filename = strdup(dirent->d_name);
			meta_count++;
		} else {
			res = create_hard_link(old, new, dirent->d_name);
			if (res != TEE_SUCCESS)
				goto exit_close_old_dir;
		}

		res = ree_fs_readdir_rpc(old_dir, &dirent);
	}

	/* finally, link the meta file, rename operation completed */
	if (!meta_filename)
		panic("no meta file");

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
	 * can completely remove ree_fs_rename(). We can simply
	 * rename TEE file using REE rename() system call, which is also
	 * atomic.
	 */
	if (meta_count > 1)
		EMSG("Warning: more than one meta file in your TEE file\n"
		     "This will cause memory leakage.");

	res = create_hard_link(old, new, meta_filename);
	if (res != TEE_SUCCESS)
		goto exit_close_old_dir;

	/* we are safe now, remove old TEE file */
	unlink_tee_file(old);

exit_close_old_dir:
	ree_fs_closedir_rpc(old_dir);
	free(meta_filename);
	return res;
}

static TEE_Result ree_fs_rename(const char *old, const char *new)
{
	TEE_Result res;

	mutex_lock(&ree_fs_mutex);
	res = ree_fs_rename_internal(old, new);
	mutex_unlock(&ree_fs_mutex);

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
static TEE_Result ree_fs_remove(const char *file)
{
	TEE_Result res;
	char trash_file[TEE_FS_NAME_MAX + 6];

	snprintf(trash_file, TEE_FS_NAME_MAX + 6, "%s.trash", file);

	mutex_lock(&ree_fs_mutex);

	res = ree_fs_rename_internal(file, trash_file);
	if (res == TEE_SUCCESS)
		unlink_tee_file(trash_file);

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

static int ree_open_wrapper(TEE_Result *errno, const char *file, int flags, ...)
{
	TEE_Result res;
	struct tee_file_handle *tfh = NULL;
	int fd;

	if (flags & TEE_FS_O_CREATE)
		res = ree_fs_create(file, !!(flags & TEE_FS_O_EXCL), &tfh);
	else
		res = ree_fs_open(file, &tfh);

	*errno = res;
	if (res != TEE_SUCCESS)
		return -1;

	mutex_lock(&ree_fs_mutex);
	fd = handle_get(&fs_handle_db, tfh);
	mutex_unlock(&ree_fs_mutex);

	if (fd == -1)
		panic(); /* Temporary solution */

	return fd;
}

static int ree_close_wrapper(int fd)
{
	struct tee_file_handle *tfh;

	mutex_lock(&ree_fs_mutex);
	tfh = handle_put(&fs_handle_db, fd);
	mutex_unlock(&ree_fs_mutex);

	if (tfh) {
		ree_fs_close(&tfh);
		return 0;
	}
	return -1;
}

static int ree_read_wrapper(TEE_Result *errno, int fd, void *buf, size_t len)
{
	TEE_Result res;
	struct tee_file_handle *tfh;
	size_t l;

	mutex_lock(&ree_fs_mutex);
	tfh = handle_lookup(&fs_handle_db, fd);
	mutex_unlock(&ree_fs_mutex);

	if (!tfh) {
		*errno = TEE_ERROR_BAD_PARAMETERS;
		return -1;
	}

	l = len;
	res = ree_fs_read(tfh, buf, &l);
	*errno = res;

	if (res != TEE_SUCCESS)
		return -1;
	return l;
}

static int ree_write_wrapper(TEE_Result *errno, int fd, const void *buf,
			     size_t len)
{
	TEE_Result res;
	struct tee_file_handle *tfh;

	mutex_lock(&ree_fs_mutex);
	tfh = handle_lookup(&fs_handle_db, fd);
	mutex_unlock(&ree_fs_mutex);

	if (!tfh) {
		*errno = TEE_ERROR_BAD_PARAMETERS;
		return -1;
	}

	res = ree_fs_write(tfh, buf, len);
	*errno = res;

	if (res != TEE_SUCCESS)
		return -1;
	return len;
}

static tee_fs_off_t ree_lseek_wrapper(TEE_Result *errno, int fd,
				      tee_fs_off_t offset, int whence)
{
	TEE_Result res;
	struct tee_file_handle *tfh;
	int32_t new_offs;

	mutex_lock(&ree_fs_mutex);
	tfh = handle_lookup(&fs_handle_db, fd);
	mutex_unlock(&ree_fs_mutex);

	if (!tfh) {
		*errno = TEE_ERROR_BAD_PARAMETERS;
		return -1;
	}

	switch (whence) {
	case TEE_FS_SEEK_SET:
		res = ree_fs_seek(tfh, offset, TEE_DATA_SEEK_SET, &new_offs);
		break;
	case TEE_FS_SEEK_CUR:
		res = ree_fs_seek(tfh, offset, TEE_DATA_SEEK_CUR, &new_offs);
		break;
	case TEE_FS_SEEK_END:
		res = ree_fs_seek(tfh, offset, TEE_DATA_SEEK_END, &new_offs);
		break;
	default:
		res = TEE_ERROR_BAD_PARAMETERS;
	}

	*errno = res;
	if (res != TEE_SUCCESS)
		return -1;
	return new_offs;
}

static int ree_rename_wrapper(const char *old, const char *new)
{
	if (ree_fs_rename(old, new) != TEE_SUCCESS)
		return -1;
	return 0;
}

static int ree_unlink_wrapper(const char *file)
{
	if (ree_fs_remove(file) != TEE_SUCCESS)
		return -1;
	return 0;
}

static int ree_ftruncate_wrapper(TEE_Result *errno, int fd,
				  tee_fs_off_t length)
{
	TEE_Result res;
	struct tee_file_handle *tfh;

	mutex_lock(&ree_fs_mutex);
	tfh = handle_lookup(&fs_handle_db, fd);
	mutex_unlock(&ree_fs_mutex);

	if (!tfh) {
		*errno = TEE_ERROR_BAD_PARAMETERS;
		return -1;
	}

	res = ree_fs_truncate(tfh, length);
	*errno = res;

	if (res != TEE_SUCCESS)
		return -1;
	return 0;
}

static struct tee_fs_dir *ree_opendir_wrapper(const char *name)
{
	struct tee_fs_dir *d;

	if (ree_fs_opendir_rpc(name, &d) != TEE_SUCCESS)
		return NULL;
	return d;
}

static int ree_closedir_wrapper(struct tee_fs_dir *d)
{
	ree_fs_closedir_rpc(d);
	return 0;
}

static struct tee_fs_dirent *ree_readdir_wrapper(struct tee_fs_dir *d)
{
	struct tee_fs_dirent *e;

	if (ree_fs_readdir_rpc(d, &e) != TEE_SUCCESS)
		return NULL;
	return e;
}

const struct tee_file_operations ree_fs_ops = {
	.open = ree_open_wrapper,
	.close = ree_close_wrapper,
	.read = ree_read_wrapper,
	.write = ree_write_wrapper,
	.lseek = ree_lseek_wrapper,
	.ftruncate = ree_ftruncate_wrapper,
	.rename = ree_rename_wrapper,
	.unlink = ree_unlink_wrapper,
	.mkdir = ree_fs_mkdir_rpc,
	.opendir = ree_opendir_wrapper,
	.closedir = ree_closedir_wrapper,
	.readdir = ree_readdir_wrapper,
	.rmdir = ree_fs_rmdir_rpc,
	.access = ree_fs_access_rpc
};
