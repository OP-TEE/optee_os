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
#include <tee/tee_fs_defs.h>
#include <tee/tee_cryp_provider.h>
#include <kernel/tee_common_unpg.h>
#include <kernel/handle.h>
#include <kernel/mutex.h>
#include <trace.h>

#include "tee_fs_private.h"
#include "ree_fs_intf.h"

static struct handle_db fs_handle_db = HANDLE_DB_INITIALIZER;

static inline void get_tmp_file_header_path(const char *filepath, char *out)
{
	snprintf(out, REE_FS_NAME_MAX, "%s/%s%s",
			filepath, TMP_PREFIX, FILE_HEADER_NAME);
}

static inline void get_file_header_path(const char *filepath, char *out)
{
	snprintf(out, REE_FS_NAME_MAX, "%s/%s",
			filepath, FILE_HEADER_NAME);
}

static inline void get_data_block_path(const char *filepath,
		uint32_t block_num, int backup_version, char *path)
{
	snprintf(path, REE_FS_NAME_MAX, "%s/%s%u.%d",
		filepath, DATA_BLOCK_NAME, block_num, backup_version);
}

static struct tee_file_info *construct_file_info_object(const char *filename)
{
	struct tee_file_info *file_info = NULL;
	struct fh_meta_data *meta;
	uint32_t filename_len = strlen(filename) + 1;
	TEE_Result tee_res;

	file_info = malloc(sizeof(struct tee_file_info));
	if (!file_info) {
		EMSG("Failed to allocate memory");
		goto exit;
	}

	/* Initial meta data */
	meta = &file_info->meta_data;
	memset(meta->data_block_backup_version, 0xff,
		sizeof(meta->data_block_backup_version));
	meta->file_size = 0;

	/* Initial FEK */
	tee_res = key_manager_ops.generate_fek(file_info->encrypted_fek,
			TEE_FS_KM_FEK_SIZE);
	if (tee_res != TEE_SUCCESS) {
		EMSG("Failed to generate new FEK");
		goto exit;
	}

	/* Save filename to file_info */
	file_info->filename = malloc(filename_len);
	if (!file_info->filename) {
		EMSG("Failed to allocate memory");
		goto exit;
	}
	memcpy(file_info->filename, filename, filename_len);

	return file_info;

exit:
	if (file_info)
		free(file_info->filename);

	free(file_info);

	return NULL;
}

static void release_file_info_object(struct tee_file_info *info)
{
	if (info)
		free(info->filename);

	free(info);
}

static int __remove_block_file(struct tee_file_info *info, uint32_t block_num,
				bool toggle)
{
	char block_path[REE_FS_NAME_MAX];
	uint8_t version =
		get_backup_version_of_block(&info->meta_data, block_num);

	if (toggle)
		version = !version;

	get_data_block_path(info->filename, block_num, version, block_path);
	DMSG("%s", block_path);

	/* ignore it if file not found */
	if (ree_file_ops.access(block_path, TEE_FS_F_OK))
		return 0;

	return ree_file_ops.unlink(block_path);
}

static int remove_block_file(struct tee_file_info *info, uint32_t block_num)
{
	DMSG("remove block%u", block_num);
	return __remove_block_file(info, block_num, false);
}

static int remove_outdated_block(struct tee_file_info *info, uint32_t block_num)
{
	DMSG("remove outdated block%u", block_num);
	return __remove_block_file(info, block_num, true);
}

static void prepare_file_header_aad(struct fh_aad *aad,
		struct tee_file_info *info)
{
	memset(aad, 0x0, sizeof(struct fh_aad));

	memcpy(aad->encrypted_fek, info->encrypted_fek,
			sizeof(info->encrypted_fek));

	memcpy(aad->filename, info->filename, strlen(info->filename) + 1);
}

#ifdef CFG_ENC_FS
static TEE_Result encrypt_and_write_file(char *ree_path,
		enum tee_file_data_type data_type,
		struct tee_file_info *file_info,
		uint8_t *aad, uint32_t aad_len,
		uint8_t *in, uint32_t in_size)
{
	TEE_Result tee_res = TEE_SUCCESS;
	uint32_t cipher_header_size = 0;
	uint8_t *cipher = NULL;
	size_t cipher_size = 0;

	cipher_header_size = key_manager_ops.
			get_cipher_header_size(data_type);

	cipher_size = cipher_header_size + in_size;

	cipher = malloc(cipher_size);
	if (!cipher) {
		EMSG("Failed to allocate cipher buffer, size=%zu",
				cipher_size);
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	tee_res = key_manager_ops.do_encryption(data_type,
			file_info->encrypted_fek,
			aad, aad_len,
			in, in_size,
			cipher, &cipher_size);

	if (tee_res != TEE_SUCCESS) {
		EMSG("Failed to do encryption, res=%x", tee_res);
		goto exit;
	}

	tee_res = write_ree_file(ree_path, cipher, cipher_size);
	if (tee_res != TEE_SUCCESS)
		EMSG("Failed to write REE file, file=%s", ree_path);

exit:
	free(cipher);

	return tee_res;
}

static TEE_Result read_and_decrypt_file(char *ree_path,
		enum tee_file_data_type data_type,
		struct tee_file_info *file_info,
		uint8_t *aad, uint32_t aad_len,
		uint8_t *out, size_t *out_size)
{
	TEE_Result tee_res;
	uint8_t *ree_file_buffer = NULL;
	uint32_t ree_file_size = 0;
	uint32_t fek_size = sizeof(file_info->encrypted_fek);

	tee_res = read_ree_file(ree_path, &ree_file_buffer, &ree_file_size);
	if (tee_res != TEE_SUCCESS) {
		EMSG("Failed to read REE file, file=%s", ree_path);
		goto exit;
	}

	if (data_type == FILE_HEADER) {
		tee_res = key_manager_ops.get_encrypted_fek(ree_file_buffer,
				ree_file_size, file_info->encrypted_fek,
				&fek_size);

		if (tee_res != TEE_SUCCESS) {
			EMSG("Failed to read encrypted FEK from file, res=0x%x",
					tee_res);
			goto exit;
		}

		prepare_file_header_aad((struct fh_aad *)aad, file_info);
	}

	tee_res = key_manager_ops.do_decryption(data_type,
			file_info->encrypted_fek,
			aad, aad_len,
			ree_file_buffer, ree_file_size,
			out, out_size);

	if (tee_res != TEE_SUCCESS)
		EMSG("Failed to decrypt file, res=0x%x", tee_res);

exit:
	if (ree_file_buffer)
		free(ree_file_buffer);

	return tee_res;
}

#else

static TEE_Result encrypt_and_write_file(char *ree_path,
		enum tee_file_data_type data_type __unused,
		struct tee_file_info *file_info __unused,
		uint8_t *aad __unused, uint32_t aad_len __unused,
		uint8_t *in, uint32_t in_size)
{
	TEE_Result tee_res = TEE_SUCCESS;

	tee_res = write_ree_file(ree_path, in, in_size);
	if (tee_res != TEE_SUCCESS)
		EMSG("Failed to write REE file, file=%s", ree_path);

	return tee_res;
}

static TEE_Result read_and_decrypt_file(char *ree_path,
		enum tee_file_data_type data_type __unused,
		struct tee_file_info *file_info __unused,
		uint8_t *aad __unused, uint32_t aad_len __unused,
		uint8_t *out, size_t *out_size)
{
	TEE_Result tee_res;
	uint8_t *ree_file_buffer = NULL;
	uint32_t ree_file_size = 0;

	tee_res = read_ree_file(ree_path, &ree_file_buffer, &ree_file_size);
	if (tee_res != TEE_SUCCESS) {
		EMSG("Failed to read REE file, file=%s", ree_path);
		goto exit;
	}

	if (*out_size < ree_file_size) {
		tee_res = TEE_ERROR_SHORT_BUFFER;
		EMSG("Short buffer size(%zd), file size=%u\n", *out_size,
				ree_file_size);
		goto exit;
	}

	memcpy(out, ree_file_buffer, ree_file_size);
	*out = ree_file_size;

exit:
	if (ree_file_buffer)
		free(ree_file_buffer);

	return tee_res;
}
#endif

static TEE_Result commit_file_header(struct tee_file_info *file_info)
{
	TEE_Result tee_res = TEE_SUCCESS;
	char tmp_ree_path[REE_FS_NAME_MAX];
	char ree_path[REE_FS_NAME_MAX];
	struct fh_aad aad;
	uint32_t meta_data_size = sizeof(struct fh_meta_data);
	int res;

	/* write meta data to a tmp file */
	get_tmp_file_header_path(file_info->filename, tmp_ree_path);

	prepare_file_header_aad(&aad, file_info);

	tee_res = encrypt_and_write_file(tmp_ree_path,
			FILE_HEADER, file_info,
			(uint8_t *)&aad, sizeof(aad),
			(uint8_t *)&file_info->meta_data,
			meta_data_size);

	if (tee_res != TEE_SUCCESS)
		goto exit;

	/* do atomic write by renaming */
	get_file_header_path(file_info->filename, ree_path);
	res = ree_file_ops.rename(tmp_ree_path, ree_path);
	if (res < 0) {
		EMSG("Failed to rename file");
		EMSG("old=%s", tmp_ree_path);
		EMSG("new=%s", ree_path);
		tee_res = TEE_ERROR_CORRUPT_OBJECT;
	}

exit:
	return tee_res;
}

static TEE_Result read_file_header(struct tee_file_info *file_info)
{
	struct fh_aad aad;
	char ree_path[REE_FS_NAME_MAX];
	size_t meta_data_size = sizeof(struct fh_meta_data);

	get_file_header_path(file_info->filename, ree_path);

	return read_and_decrypt_file(ree_path,
			FILE_HEADER, file_info,
			(uint8_t *)&aad, sizeof(aad),
			(uint8_t *)&file_info->meta_data,
			&meta_data_size);
}

static TEE_Result change_file_info_filename(struct tee_file_info *info,
		const char *filename)
{
	uint32_t filename_len;
	TEE_Result tee_res = TEE_SUCCESS;

	if (!info || !filename)
		return TEE_ERROR_BAD_PARAMETERS;

	if (info->filename)
		free(info->filename);

	filename_len = strlen(filename) + 1;

	info->filename = malloc(filename_len);
	if (!info->filename) {
		EMSG("Failed to allocate memory");
		tee_res = TEE_ERROR_OUT_OF_MEMORY;
		goto exit;
	}
	memcpy(info->filename, filename, filename_len);

exit:
	return tee_res;
}

static TEE_Result copy_file_header(const char *old_file, const char *new_file)
{
	TEE_Result tee_res = TEE_SUCCESS;
	struct tee_file_info *file_info = NULL;

	file_info = construct_file_info_object(old_file);
	if (!file_info) {
		EMSG("Failed to construct old tee_file_info object");
		tee_res = TEE_ERROR_OUT_OF_MEMORY;
		goto exit;
	}

	tee_res = read_file_header(file_info);
	if (tee_res != TEE_SUCCESS) {
		EMSG("Failed to read file header from old file, res=0x%x",
				tee_res);
		goto exit;
	}

	tee_res = change_file_info_filename(file_info, new_file);
	if (tee_res != TEE_SUCCESS) {
		EMSG("Failed to change filename, res=0x%x",
				tee_res);
		goto exit;
	}

	tee_res = commit_file_header(file_info);
	if (tee_res != TEE_SUCCESS) {
		EMSG("Failed to update file header, res=0x%x",
				tee_res);
		goto exit;
	}

exit:
	if (file_info)
		release_file_info_object(file_info);

	return tee_res;
}


static bool is_block_file_exist(struct fh_meta_data *meta,
					uint32_t block_num)
{
	uint32_t file_size = meta->file_size;

	if (file_size == 0)
		return false;

	return (block_num <= (uint32_t)get_last_block_num(file_size));
}

static TEE_Result read_block_from_storage(struct tee_file_info *info,
		struct block *b)
{
	TEE_Result tee_res = TEE_SUCCESS;
	struct block_aad aad = {.block_num = b->block_num};
	char block_path[REE_FS_NAME_MAX];
	size_t block_file_size = BLOCK_FILE_SIZE;
	uint8_t version = get_backup_version_of_block(&info->meta_data,
			b->block_num);

	if (!is_block_file_exist(&info->meta_data, b->block_num))
		goto exit;

	get_data_block_path(info->filename, b->block_num, version,
			block_path);

	tee_res = read_and_decrypt_file(block_path,
			DATA_BLOCK, info,
			(uint8_t *)&aad, sizeof(struct block_aad),
			b->data, &block_file_size);

	if (tee_res != TEE_SUCCESS) {
		EMSG("Failed to read and decrypt file");
		goto exit;
	}

	b->data_size = block_file_size;
	DMSG("Successfully read and decrypt block%d, size=%u",
		b->block_num, b->data_size);

exit:
	return tee_res;
}

static TEE_Result flush_block_to_storage(struct tee_fs_fd *fdp,
		struct block *b)
{
	TEE_Result tee_res = TEE_SUCCESS;
	struct tee_file_info *info = fdp->file_info;
	struct block_aad aad = {.block_num = b->block_num};
	char ree_path[REE_FS_NAME_MAX];
	uint8_t new_version =
		!get_backup_version_of_block(&info->meta_data, b->block_num);

	get_data_block_path(info->filename, b->block_num, new_version,
			ree_path);

	toggle_backup_version_of_block(&info->meta_data, b->block_num);

	tee_res = encrypt_and_write_file(ree_path,
			DATA_BLOCK, info,
			(uint8_t *)&aad, sizeof(struct block_aad),
			b->data, b->data_size);

	if (tee_res != TEE_SUCCESS) {
		EMSG("Failed to encrypt and write block file");
		goto fail;
	}

	DMSG("Successfully encrypt and write block%d to storage, size=%u",
		b->block_num, b->data_size);

fail:

	return tee_res;
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
		DMSG("Extend block%d size to %u bytes",
				b->block_num, b->data_size);
	}
}

static void read_data_from_block(struct block *b, int offset,
				void *buf, size_t len)
{
	size_t bytes_to_read = len;

	DMSG("Read %zd bytes from block%d", len, b->block_num);
	if (offset + len > b->data_size) {
		bytes_to_read = b->data_size - offset;
		DMSG("Exceed block size, update len to %zd bytes",
			bytes_to_read);
	}
	memcpy(buf, b->data + offset, bytes_to_read);
}

#ifdef CFG_FS_BLOCK_CACHE
static struct block *read_block_with_cache(struct tee_fs_fd *fdp, int block_num)
{
	struct block *b;

	get_block_from_cache(&fdp->block_cache, block_num, &b);
	if (is_block_data_invalid(b)) {
		TEE_Result tee_res;

		tee_res = read_block_from_storage(fdp->file_info, b);
		if (tee_res != TEE_SUCCESS) {
			EMSG("Unable to read block%d from storage",
					block_num);
			return NULL;
		}
	}

	return b;
}
#else

static struct mutex block_mutex = MUTEX_INITIALIZER;
static struct block *read_block_no_cache(struct tee_fs_fd *fdp, int block_num)
{
	static struct block *b;
	TEE_Result tee_res;

	mutex_lock(&block_mutex);
	if (!b)
		b = alloc_block();
	b->block_num = block_num;

	tee_res = read_block_from_storage(fdp->file_info, b);
	if (tee_res != TEE_SUCCESS) {
		EMSG("Unable to read block%d from storage, res=0x%x",
				block_num, tee_res);
	}
	mutex_unlock(&block_mutex);

	if (tee_res == TEE_SUCCESS)
		return b;
	else
		return NULL;
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

static int out_of_place_write(struct tee_fs_fd *fdp, const void *buf,
		size_t len, struct fh_meta_data *meta)
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

		if (block_ops.write(fdp, b) != TEE_SUCCESS) {
			EMSG("Unable to wrtie block%d to storage",
					b->block_num);
			goto failed;
		}

		data_ptr += size_to_write;
		remain_bytes -= size_to_write;
		start_block_num++;
		fdp->pos += size_to_write;
	}

	if (fdp->pos > (tee_fs_off_t)meta->file_size)
		meta->file_size = fdp->pos;

	return 0;
failed:
	fdp->pos = orig_pos;
	return -1;
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

	DMSG("%s -> %s", old_path, new_path);
	return ree_file_ops.link(old_path, new_path);
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

	dir = ree_file_ops.opendir(file);
	if (!dir)
		goto exit;

	dirent = ree_file_ops.readdir(dir);
	while (dirent) {
		char path[REE_FS_NAME_MAX];

		snprintf(path, REE_FS_NAME_MAX, "%s/%s",
			file, dirent->d_name);

		DMSG("unlink %s", path);
		res = ree_file_ops.unlink(path);
		if (res) {
			ree_file_ops.closedir(dir);
			goto exit;
		}

		dirent = ree_file_ops.readdir(dir);
	}

	res = ree_file_ops.closedir(dir);
	if (res)
		goto exit;

	res = ree_file_ops.rmdir(file);
exit:
	return res;
}

static inline bool is_tee_file_exist(const char *file)
{
	return !ree_file_ops.access(file, TEE_FS_F_OK);
}

static TEE_Result create_tee_file(struct tee_file_info *info)
{
	int res;

	DMSG("Creating TEE file=%s", info->filename);

	/* create TEE file directory */
	res = ree_file_ops.mkdir(info->filename,
			TEE_FS_S_IRUSR | TEE_FS_S_IWUSR);
	if (res) {
		EMSG("Failed to create TEE file directory, filename=%s",
				info->filename);
		return TEE_ERROR_CORRUPT_OBJECT;
	}

	/* create a new file header in TEE file directory */
	return commit_file_header(info);
}

static TEE_Result open_tee_file(struct tee_file_info *info)
{
	DMSG("Opening TEE file=%s", info->filename);

	return read_file_header(info);
}

static struct tee_fs_fd *tee_fs_fd_lookup(int fd)
{
	return handle_lookup(&fs_handle_db, fd);
}

static int tee_fs_open(TEE_Result *errno, const char *file, int flags, ...)
{
	int res = -1;
	size_t len = strlen(file) + 1;
	struct tee_file_info *file_info = NULL;
	struct tee_fs_fd *fdp = NULL;
	bool file_exist;
	TEE_Result tee_res = TEE_SUCCESS;

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

	file_info = construct_file_info_object(file);
	if (!file_info) {
		EMSG("Failed to construct new tee_file_info object");
		*errno = TEE_ERROR_OUT_OF_MEMORY;
		goto exit;
	}

	file_exist = is_tee_file_exist(file);
	if (flags & TEE_FS_O_CREATE) {
		if ((flags & TEE_FS_O_EXCL) && file_exist) {
			EMSG("tee file already exists");
			*errno = TEE_ERROR_ACCESS_CONFLICT;
			goto exit_free_file_info;
		}

		if (!file_exist)
			tee_res = create_tee_file(file_info);
		else
			tee_res = open_tee_file(file_info);

	} else {
		if (!file_exist) {
			EMSG("tee file not exists");
			*errno = TEE_ERROR_ITEM_NOT_FOUND;
			goto exit_free_file_info;
		}

		tee_res = open_tee_file(file_info);
	}

	if (tee_res != TEE_SUCCESS) {
		EMSG("Failed to open TEE file, res=0x%x", tee_res);
		*errno = TEE_ERROR_CORRUPT_OBJECT;
		goto exit_free_file_info;
	}

	DMSG("file=%s, length=%u", file, file_info->meta_data.file_size);
	fdp = (struct tee_fs_fd *)malloc(sizeof(struct tee_fs_fd));
	if (!fdp) {
		*errno = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_free_file_info;
	}

	/* init internal status */
	fdp->flags = flags;
	fdp->file_info = file_info;
	fdp->pos = 0;
	if (init_block_cache(&fdp->block_cache)) {
		*errno = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_free_fdp;
	}

	/* return fd */
	res = handle_get(&fs_handle_db, fdp);
	if (res < 0) {
		*errno = TEE_ERROR_GENERIC;
		goto exit_destroy_block_cache;
	}

	fdp->fd = res;

	if ((flags & TEE_FS_O_TRUNC) &&
		(flags & TEE_FS_O_WRONLY || flags & TEE_FS_O_RDWR)) {
		res = tee_file_ops.ftruncate(errno, fdp->fd, 0);
		if (res < 0) {
			EMSG("Unable to truncate file");
			*errno = TEE_ERROR_CORRUPT_OBJECT;
			goto exit_release_handle;
		}
	}

	goto exit;

exit_release_handle:
	handle_put(&fs_handle_db, fdp->fd);
exit_destroy_block_cache:
	destroy_block_cache(&fdp->block_cache);
exit_free_fdp:
	free(fdp);
exit_free_file_info:
	release_file_info_object(file_info);
exit:
	if (*errno == TEE_SUCCESS)
		return fdp->fd;

	return -1;
}

static int tee_fs_close(int fd)
{
	struct tee_fs_fd *fdp = tee_fs_fd_lookup(fd);

	if (!fdp)
		return -1;

	handle_put(&fs_handle_db, fdp->fd);

	destroy_block_cache(&fdp->block_cache);
	release_file_info_object(fdp->file_info);
	free(fdp);

	return 0;
}

static tee_fs_off_t tee_fs_lseek(TEE_Result *errno, int fd,
				tee_fs_off_t offset, int whence)
{
	tee_fs_off_t res = -1;
	struct tee_fs_fd *fdp = tee_fs_fd_lookup(fd);
	tee_fs_off_t new_pos;
	uint32_t filelen;

	assert(errno != NULL);
	*errno = TEE_SUCCESS;

	if (!fdp) {
		*errno = TEE_ERROR_BAD_PARAMETERS;
		goto exit;
	}

	DMSG("offset=%d, whence=%d", (int)offset, whence);

	filelen = fdp->file_info->meta_data.file_size;

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
 */
static int tee_fs_ftruncate(TEE_Result *errno, int fd,
				tee_fs_off_t new_file_len)
{
	int res = 0;
	struct tee_fs_fd *fdp = tee_fs_fd_lookup(fd);
	struct fh_meta_data *meta = &fdp->file_info->meta_data;
	size_t old_file_len = meta->file_size;
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


	meta->file_size = new_file_len;

	if ((size_t)new_file_len < old_file_len) {
		int old_block_num = get_last_block_num(old_file_len);
		int new_block_num = get_last_block_num(new_file_len);

		DMSG("Truncate file length to %zu", (size_t)new_file_len);

		*errno = commit_file_header(fdp->file_info);
		if (*errno != TEE_SUCCESS) {
			EMSG("Failed to update file header");
			res = -1;
			goto free;
		}

		/* now we are safe to free unused blocks */
		while (old_block_num > new_block_num) {
			if (remove_block_file(fdp->file_info, old_block_num)) {
				IMSG("Warning: Failed to free block: %d",
						old_block_num);
			}

			old_block_num--;
		}

	} else {
		size_t ext_len = new_file_len - old_file_len;
		int orig_pos = fdp->pos;

		buf = malloc(BLOCK_FILE_SIZE);
		if (!buf) {
			*errno = TEE_ERROR_OUT_OF_MEMORY;
			EMSG("Failed to allocate buffer, size=%d",
					BLOCK_FILE_SIZE);
			res = -1;
			goto free;
		}

		memset(buf, 0x0, BLOCK_FILE_SIZE);

		DMSG("Extend file length to %zu", (size_t)new_file_len);

		fdp->pos = old_file_len;

		while (ext_len > 0) {
			size_t data_len = (ext_len > BLOCK_FILE_SIZE) ?
					BLOCK_FILE_SIZE : ext_len;

			DMSG("fill len=%zu", data_len);
			res = out_of_place_write(fdp, (void *)buf,
					data_len, meta);
			if (res < 0) {
				*errno = TEE_ERROR_CORRUPT_OBJECT;
				EMSG("Failed to fill data");
				break;
			}

			ext_len -= data_len;
		}

		fdp->pos = orig_pos;

		if (res == 0) {
			*errno = commit_file_header(fdp->file_info);
			if (*errno != TEE_SUCCESS) {
				res = -1;
				EMSG("Failed to update file header");
			}
		}
	}

free:
	free(buf);

exit:
	return res;
}

static int tee_fs_read(TEE_Result *errno, int fd,
		       void *buf, size_t len)
{
	int res = -1;
	struct tee_fs_fd *fdp = tee_fs_fd_lookup(fd);
	int start_block_num;
	int end_block_num;
	size_t remain_bytes = len;
	uint8_t *data_ptr = buf;
	uint32_t file_size = fdp->file_info->meta_data.file_size;

	assert(errno != NULL);
	*errno = TEE_SUCCESS;

	if (!fdp) {
		*errno = TEE_ERROR_BAD_PARAMETERS;
		goto exit;
	}

	if (fdp->pos + len > file_size) {
		len = file_size - fdp->pos;
		DMSG("reached EOF, update read length to %zu", len);
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

	DMSG("%s, data len=%zu", fdp->file_info->filename, len);

	start_block_num = pos_to_block_num(fdp->pos);
	end_block_num = pos_to_block_num(fdp->pos + len - 1);
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
			*errno = TEE_ERROR_CORRUPT_OBJECT;
			goto exit;
		}

		read_data_from_block(b, offset, data_ptr, size_to_read);
		data_ptr += size_to_read;
		remain_bytes -= size_to_read;
		fdp->pos += size_to_read;

		start_block_num++;
	}
	res = 0;
exit:
	return (res < 0) ? res : (int)len;
}

/*
 * To ensure atomicity of write operation, we need to
 * do the following steps:
 * (The sequence of operations is very important)
 *
 *  - For each blocks to write:
 *    - Create new backup version for current block.
 *    - Write data to new backup version.
 *    - Update the new meta file accordingly.
 *  - Update meta data in file header.
 *
 * (Any failure in above steps is considered as update failed,
 *  and the file content will not be updated)
 *
 * After previous step the update is considered complete, but
 * we should do the following clean-up step(s):
 *
 *  - Remove old block files.
 *
 * (Any failure in above steps is considered as a successfully
 *  update)
 */
static int tee_fs_write(TEE_Result *errno, int fd,
			const void *buf, size_t len)
{
	int res = -1;
	struct tee_fs_fd *fdp = tee_fs_fd_lookup(fd);
	struct fh_meta_data *meta = &fdp->file_info->meta_data;
	size_t file_size = meta->file_size;
	int orig_pos = fdp->pos;

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

	DMSG("%s, data len=%zu", fdp->file_info->filename, len);
	if (file_size < (size_t)fdp->pos) {
		DMSG("File hole detected, try to extend file size");
		res = tee_file_ops.ftruncate(errno, fd, fdp->pos);
		if (res < 0)
			goto exit;
	}

	res = out_of_place_write(fdp, buf, len, meta);
	if (res < 0) {
		*errno = TEE_ERROR_CORRUPT_OBJECT;
	} else {
		int start_block_num;
		int end_block_num;

		*errno = commit_file_header(fdp->file_info);
		if (*errno != TEE_SUCCESS)
			res = -1;

		/* we are safe to free old blocks */
		start_block_num = pos_to_block_num(orig_pos);
		end_block_num = pos_to_block_num(fdp->pos - 1);
		while (start_block_num <= end_block_num) {
			int rc;

			rc = remove_outdated_block(fdp->file_info,
					start_block_num);
			if (rc)
				IMSG("Warning: Failed to free old block: %d",
					start_block_num);

			start_block_num++;
		}
	}
exit:
	return (res < 0) ? res : (int)len;
}

/*
 * To ensure atomicity of rename operation, we need to
 * do the following steps:
 *
 *  - Create a new folder that represents the renamed TEE file
 *  - For each REE block files, create a hard link under the just
 *    created folder (new TEE file)
 *  - Now we are ready to copy file header to the new folder
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
static int tee_fs_rename(const char *old, const char *new)
{
	int res = -1;
	TEE_Result tee_res;
	size_t old_len;
	size_t new_len;
	struct tee_fs_dir *old_dir = NULL;
	struct tee_fs_dirent *dirent;
	char file_header_name[TEE_FS_NAME_MAX] = FILE_HEADER_NAME;
	uint32_t name_len = strlen(file_header_name);


	if (!old || !new)
		return -1;

	DMSG("old=%s", old);
	DMSG("new=%s", new);

	old_len = strlen(old) + 1;
	new_len = strlen(new) + 1;

	if (old_len > TEE_FS_NAME_MAX || new_len >TEE_FS_NAME_MAX)
		goto exit;

	res = ree_file_ops.mkdir(new,
			TEE_FS_S_IRUSR | TEE_FS_S_IWUSR);
	if (res)
		goto exit;

	old_dir = ree_file_ops.opendir(old);
	if (!old_dir) {
		res = -1;
		goto exit;
	}

	dirent = ree_file_ops.readdir(old_dir);
	while (dirent) {
		if (strncmp(dirent->d_name, file_header_name, name_len) != 0) {
			res = create_hard_link(old, new, dirent->d_name);
			if (res) {
				EMSG("Failed to create hard link");
				goto exit;
			}
		}

		dirent = ree_file_ops.readdir(old_dir);
	}

	/*
	 * Creating a new file header for the new TEE file.
	 * If success, rename operation is completed
	 */
	tee_res = copy_file_header(old, new);
	if (tee_res != TEE_SUCCESS) {
		EMSG("Failed to create file header for new TEE file");
		res = -1;
		goto exit;
	}

	/* we are safe now, remove old TEE file */
	unlink_tee_file(old);

exit:
	ree_file_ops.closedir(old_dir);

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
static int tee_fs_unlink(const char *file)
{
	int res = -1;
	char trash_file[TEE_FS_NAME_MAX + 6];

	if (!file)
		return -1;

	snprintf(trash_file, TEE_FS_NAME_MAX + 6, "%s.trash",
		file);

	res = tee_file_ops.rename(file, trash_file);
	if (res < 0)
		return res;

	unlink_tee_file(trash_file);

	return res;
}

static int tee_fs_force_unlink(const char *file)
{
	if (!file)
		return -1;

	return unlink_tee_file(file);
}

static int tee_fs_mkdir(const char *path, tee_fs_mode_t mode)
{
	return ree_file_ops.mkdir(path, mode);
}

static tee_fs_dir *tee_fs_opendir(const char *name)
{
	return ree_file_ops.opendir(name);
}

static int tee_fs_closedir(tee_fs_dir *d)
{
	return ree_file_ops.closedir(d);
}

static struct tee_fs_dirent *tee_fs_readdir(tee_fs_dir *d)
{
	return ree_file_ops.readdir(d);
}

static int tee_fs_rmdir(const char *pathname)
{
	return ree_file_ops.rmdir(pathname);
}

static int tee_fs_access(const char *name, int mode)
{
	return ree_file_ops.access(name, mode);
}

struct tee_file_operations tee_file_ops = {
	.open = tee_fs_open,
	.close = tee_fs_close,
	.read = tee_fs_read,
	.write = tee_fs_write,
	.lseek = tee_fs_lseek,
	.ftruncate = tee_fs_ftruncate,
	.rename = tee_fs_rename,
	.unlink = tee_fs_unlink,
	.force_unlink = tee_fs_force_unlink,
	.mkdir = tee_fs_mkdir,
	.opendir = tee_fs_opendir,
	.closedir = tee_fs_closedir,
	.readdir = tee_fs_readdir,
	.rmdir = tee_fs_rmdir,
	.access = tee_fs_access
};


