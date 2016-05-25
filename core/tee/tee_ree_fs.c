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
#include <kernel/tee_common_unpg.h>
#include <kernel/thread.h>
#include <kernel/handle.h>
#include <kernel/mutex.h>
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
#include <tee/tee_fs_key_manager.h>
#include <trace.h>
#include <utee_defines.h>
#include <util.h>

/* TEE FS operation */
#define TEE_FS_OPEN       1
#define TEE_FS_CLOSE      2
#define TEE_FS_READ       3
#define TEE_FS_WRITE      4
#define TEE_FS_SEEK       5
#define TEE_FS_UNLINK     6
#define TEE_FS_RENAME     7
#define TEE_FS_TRUNC      8
#define TEE_FS_MKDIR      9
#define TEE_FS_OPENDIR   10
#define TEE_FS_CLOSEDIR  11
#define TEE_FS_READDIR   12
#define TEE_FS_RMDIR     13
#define TEE_FS_ACCESS    14
#define TEE_FS_LINK      15

#define BLOCK_FILE_SHIFT	12

#define BLOCK_FILE_SIZE		(1 << BLOCK_FILE_SHIFT)

#define MAX_NUM_CACHED_BLOCKS	1

#define NUM_BLOCKS_PER_FILE	1024

#define MAX_FILE_SIZE	(BLOCK_FILE_SIZE * NUM_BLOCKS_PER_FILE)

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
	struct tee_fs_file_meta *meta;
	int pos;
	uint32_t flags;
	int fd;
	bool is_new_file;
	char *filename;
	struct block_cache block_cache;
};

struct tee_fs_dir {
	int nw_dir;
	struct tee_fs_dirent d;
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

struct tee_fs_rpc {
	int op;
	int flags;
	int arg;
	int fd;
	uint32_t len;
	int res;
};

static int tee_fs_send_cmd(struct tee_fs_rpc *bf_cmd, void *data, uint32_t len,
			   uint32_t mode)
{
	TEE_Result ret;
	struct optee_msg_param params;
	paddr_t phpayload = 0;
	uint64_t cpayload = 0;
	struct tee_fs_rpc *bf;
	int res = -1;

	thread_rpc_alloc_payload(sizeof(struct tee_fs_rpc) + len,
				 &phpayload, &cpayload);
	if (!phpayload)
		return -1;

	if (!ALIGNMENT_IS_OK(phpayload, struct tee_fs_rpc))
		goto exit;

	bf = phys_to_virt(phpayload, MEM_AREA_NSEC_SHM);
	if (!bf)
		goto exit;

	memset(&params, 0, sizeof(params));
	params.attr = OPTEE_MSG_ATTR_TYPE_TMEM_INOUT;
	params.u.tmem.buf_ptr = phpayload;
	params.u.tmem.size = sizeof(struct tee_fs_rpc) + len;
	params.u.tmem.shm_ref = cpayload;

	/* fill in parameters */
	*bf = *bf_cmd;

	if (mode & TEE_FS_MODE_IN)
		memcpy((void *)(bf + 1), data, len);

	ret = thread_rpc_cmd(OPTEE_MSG_RPC_CMD_FS, 1, &params);
	/* update result */
	*bf_cmd = *bf;
	if (ret != TEE_SUCCESS)
		goto exit;

	if (mode & TEE_FS_MODE_OUT) {
		uint32_t olen = MIN(len, bf->len);

		memcpy(data, (void *)(bf + 1), olen);
	}

	res = 0;

exit:
	thread_rpc_free_payload(cpayload);
	return res;
}

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

static int ree_fs_open_ree(const char *file, int flags, ...)
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

static int ree_fs_read_ree(int fd, void *buf, size_t len)
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

static int ree_fs_write_ree(int fd,
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

static int ree_fs_ftruncate_ree(int fd, tee_fs_off_t length)
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

static int ree_fs_close_ree(int fd)
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

static tee_fs_off_t ree_fs_lseek_ree(int fd, tee_fs_off_t offset, int whence)
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

static int ree_fs_mkdir_ree(const char *path, tee_fs_mode_t mode)
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

static struct tee_fs_dir *ree_fs_opendir_ree(const char *name)
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

static int ree_fs_closedir_ree(struct tee_fs_dir *d)
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

static struct tee_fs_dirent *ree_fs_readdir_ree(struct tee_fs_dir *d)
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

static int ree_fs_rmdir_ree(const char *name)
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

static int ree_fs_link_ree(const char *old, const char *new)
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

static int ree_fs_unlink_ree(const char *file)
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

static int ree_fs_access_ree(const char *name, int mode)
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

	res = ree_fs_lseek_ree(fd, 0, TEE_FS_SEEK_END);
	if (res < 0)
		return res;

	file_len = res;

	res = ree_fs_lseek_ree(fd, 0, TEE_FS_SEEK_SET);
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

static int create_block_file(struct tee_fs_fd *fdp,
		struct tee_fs_file_meta *new_meta, int block_num)
{
	int fd;
	int res = -1;
	char block_path[REE_FS_NAME_MAX];
	uint8_t new_version =
		!get_backup_version_of_block(fdp->meta, block_num);

	get_block_filepath(fdp->filename, block_num, new_version,
			block_path);

	fd = ree_fs_open_ree(block_path, TEE_FS_O_CREATE | TEE_FS_O_RDWR);
	if (fd < 0)
		goto exit;

	res = ree_fs_ftruncate_ree(fd, 0);
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

static int __remove_block_file(struct tee_fs_fd *fdp, size_t block_num,
				bool toggle)
{
	char block_path[REE_FS_NAME_MAX];
	uint8_t version =
		get_backup_version_of_block(fdp->meta, block_num);

	if (toggle)
		version = !version;

	get_block_filepath(fdp->filename, block_num, version, block_path);
	DMSG("%s", block_path);

	/* ignore it if file not found */
	if (ree_fs_access_ree(block_path, TEE_FS_F_OK))
		return 0;

	return ree_fs_unlink_ree(block_path);
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

	bytes = ree_fs_write_ree(fd, ciphertext, ciphertext_size);
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

	bytes = ree_fs_read_ree(fd, ciphertext, file_size);
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

	fd = ree_fs_open_ree(meta_path, TEE_FS_O_CREATE |
			     TEE_FS_O_TRUNC | TEE_FS_O_WRONLY);
	if (fd < 0)
		return -1;

	res = encrypt_and_write_file(fd, META_FILE,
			(void *)&meta->info, sizeof(meta->info),
			meta->encrypted_fek);

	ree_fs_close_ree(fd);
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

	memset(&meta->info.backup_version_table, 0xff,
		sizeof(meta->info.backup_version_table));
	meta->info.length = 0;

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
	 * Remove outdated meta file, there is nothing we can
	 * do if we fail here, but that is OK because both
	 * new & old version of block files are kept. The context
	 * of the file is still consistent.
	 */
	get_meta_filepath(fdp->filename, old_version, meta_path);
	ree_fs_unlink_ree(meta_path);

	return res;
}

static int read_meta_file(const char *meta_path,
		struct tee_fs_file_meta *meta)
{
	int res, fd;
	size_t meta_info_size = sizeof(struct tee_fs_file_info);

	res = ree_fs_open_ree(meta_path, TEE_FS_O_RDWR);
	if (res < 0)
		return res;

	fd = res;

	res = read_and_decrypt_file(fd, META_FILE,
			(void *)&meta->info, &meta_info_size,
			meta->encrypted_fek);

	ree_fs_close_ree(fd);

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

static bool is_block_file_exist(struct tee_fs_file_meta *meta,
					size_t block_num)
{
	size_t file_size = meta->info.length;

	if (file_size == 0)
		return false;

	return (block_num <= (size_t)get_last_block_num(file_size));
}

#ifdef CFG_ENC_FS
static int read_block_from_storage(struct tee_fs_fd *fdp, struct block *b)
{
	int fd, res = 0;
	uint8_t *plaintext = b->data;
	char block_path[REE_FS_NAME_MAX];
	size_t block_file_size = BLOCK_FILE_SIZE;
	uint8_t version = get_backup_version_of_block(fdp->meta,
			b->block_num);

	if (!is_block_file_exist(fdp->meta, b->block_num))
		goto exit;

	get_block_filepath(fdp->filename, b->block_num, version,
			block_path);

	fd = ree_fs_open_ree(block_path, TEE_FS_O_RDONLY);
	if (fd < 0)
		return fd;

	res = read_and_decrypt_file(fd, BLOCK_FILE,
			plaintext, &block_file_size,
			fdp->meta->encrypted_fek);
	if (res < 0) {
		EMSG("Failed to read and decrypt file");
		goto fail;
	}
	b->data_size = block_file_size;
	DMSG("Successfully read and decrypt block%d from storage, size=%zd",
		b->block_num, b->data_size);
fail:
	ree_fs_close_ree(fd);
exit:
	return res;
}

static int flush_block_to_storage(struct tee_fs_fd *fdp, struct block *b,
		struct tee_fs_file_meta *new_meta)
{
	int fd = -1;
	int res;
	size_t block_num = b->block_num;

	fd = create_block_file(
			fdp, new_meta, block_num);
	if (fd < 0) {
		EMSG("Failed to create new version of block");
		res = -1;
		goto fail;
	}

	res = encrypt_and_write_file(fd, BLOCK_FILE,
			b->data, b->data_size,
			new_meta->encrypted_fek);
	if (res < 0) {
		EMSG("Failed to encrypt and write block file");
		goto fail;
	}
	DMSG("Successfully encrypt and write block%d to storage, size=%zd",
		b->block_num, b->data_size);

fail:
	if (fd > 0)
		ree_fs_close_ree(fd);

	return res;
}
#else
static int read_block_from_storage(struct tee_fs_fd *fdp, struct block *b)
{
	int fd, res = 0;
	char block_path[REE_FS_NAME_MAX];
	size_t block_file_size = BLOCK_FILE_SIZE;
	uint8_t version = get_backup_version_of_block(fdp->meta,
			b->block_num);

	if (!is_block_file_exist(fdp->meta, b->block_num))
		goto exit;

	get_block_filepath(fdp->filename, b->block_num, version,
			block_path);

	fd = ree_fs_open_ree(block_path, TEE_FS_O_RDONLY);
	if (fd < 0)
		return fd;


	res = ree_fs_read_ree(fd, b->data, block_file_size);
	if (res < 0) {
		EMSG("Failed to read block%d (%d)",
			b->block_num, res);
		goto fail;
	}

	b->data_size = res;
	DMSG("Successfully read block%d from storage, size=%d",
		b->block_num, b->data_size);
	res = 0;
fail:
	ree_fs_close_ree(fd);
exit:
	return res;
}

static int flush_block_to_storage(struct tee_fs_fd *fdp, struct block *b,
		struct tee_fs_file_meta *new_meta)
{
	int fd = -1;
	int res;
	size_t block_num = b->block_num;

	fd = create_block_file(
			fdp, new_meta, block_num);
	if (fd < 0) {
		EMSG("Failed to create new version of block");
		res = -1;
		goto fail;
	}

	res = ree_fs_write_ree(fd, b->data, b->data_size);
	if (res < 0) {
		EMSG("Failed to write block%d (%d)",
			b->block_num, res);
		goto fail;
	}
	DMSG("Successfully writen block%d to storage, size=%d",
		b->block_num, b->data_size);
	res = 0;
fail:
	if (fd > 0)
		ree_fs_close_ree(fd);

	return res;
}
#endif

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
	if (is_block_data_invalid(b))
		if (read_block_from_storage(fdp, b)) {
			EMSG("Unable to read block%d from storage",
					block_num);
			return NULL;
		}

	return b;
}
#else

static struct mutex block_mutex = MUTEX_INITIALIZER;
static struct block *read_block_no_cache(struct tee_fs_fd *fdp, int block_num)
{
	static struct block *b;
	int res;

	mutex_lock(&block_mutex);
	if (!b)
		b = alloc_block();
	b->block_num = block_num;

	res = read_block_from_storage(fdp, b);
	if (res)
		EMSG("Unable to read block%d from storage",
				block_num);
	mutex_unlock(&block_mutex);

	return res ? NULL : b;
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
	return ree_fs_link_ree(old_path, new_path);
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

	dir = ree_fs_opendir_ree(file);
	if (!dir)
		goto exit;

	dirent = ree_fs_readdir_ree(dir);
	while (dirent) {
		char path[REE_FS_NAME_MAX];

		snprintf(path, REE_FS_NAME_MAX, "%s/%s",
			file, dirent->d_name);

		DMSG("unlink %s", path);
		res = ree_fs_unlink_ree(path);
		if (res) {
			ree_fs_closedir_ree(dir);
			goto exit;
		}

		dirent = ree_fs_readdir_ree(dir);
	}

	res = ree_fs_closedir_ree(dir);
	if (res)
		goto exit;

	res = ree_fs_rmdir_ree(file);
exit:
	return res;
}

static bool tee_file_exists(const char *file)
{
	char meta_path[REE_FS_NAME_MAX];

	get_meta_filepath(file, 0, meta_path);
	if (ree_fs_access_ree(meta_path, TEE_FS_F_OK)) {
		get_meta_filepath(file, 1, meta_path);
		if (ree_fs_access_ree(meta_path, TEE_FS_F_OK))
			return false;
	}

	return true;
}

static struct tee_fs_file_meta *create_tee_file(const char *file)
{
	struct tee_fs_file_meta *meta = NULL;
	int res;

	DMSG("Creating TEE file=%s", file);

	/* create TEE file directory if not exist */
	if (ree_fs_access_ree(file, TEE_FS_F_OK)) {
		res = ree_fs_mkdir_ree(file,
				TEE_FS_S_IRUSR | TEE_FS_S_IWUSR);
		if (res) {
			EMSG("Failed to create TEE file directory, res=%d",
				res);
			goto exit;
		}
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

static int ree_fs_ftruncate_internal(TEE_Result *errno, struct tee_fs_fd *fdp,
				   tee_fs_off_t new_file_len);

static int ree_fs_open(TEE_Result *errno, const char *file, int flags, ...)
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

	file_exist = tee_file_exists(file);
	if (flags & TEE_FS_O_CREATE) {
		if ((flags & TEE_FS_O_EXCL) && file_exist) {
			DMSG("tee file already exists");
			*errno = TEE_ERROR_ACCESS_CONFLICT;
			goto exit;
		}

		if (!file_exist)
			meta = create_tee_file(file);
		else
			meta = open_tee_file(file);

	} else {
		if (!file_exist) {
			DMSG("tee file not exists");
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

	DMSG("file=%s, length=%zd", file, meta->info.length);
	fdp = (struct tee_fs_fd *)malloc(sizeof(struct tee_fs_fd));
	if (!fdp) {
		*errno = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_free_meta;
	}

	/* init internal status */
	fdp->flags = flags;
	fdp->meta = meta;
	fdp->pos = 0;
	if (init_block_cache(&fdp->block_cache)) {
		res = -1;
		goto exit_free_fd;
	}

	fdp->filename = malloc(len);
	if (!fdp->filename) {
		res = -1;
		*errno = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_destroy_block_cache;
	}
	memcpy(fdp->filename, file, len);

	if ((flags & TEE_FS_O_TRUNC) &&
		(flags & TEE_FS_O_WRONLY || flags & TEE_FS_O_RDWR)) {
		res = ree_fs_ftruncate_internal(errno, fdp, 0);
		if (res < 0) {
			EMSG("Unable to truncate file");
			goto exit_free_filename;
		}
	}

	/* return fd */
	res = handle_get(&fs_handle_db, fdp);
	if (res < 0)
		goto exit_free_filename;
	fdp->fd = res;
	goto exit;

exit_free_filename:
	free(fdp->filename);
exit_destroy_block_cache:
	destroy_block_cache(&fdp->block_cache);
exit_free_fd:
	free(fdp);
exit_free_meta:
	free(meta);
exit:
	return res;
}

static int ree_fs_close(int fd)
{
	int res = -1;
	struct tee_fs_fd *fdp = handle_lookup(&fs_handle_db, fd);

	if (!fdp)
		return -1;

	handle_put(&fs_handle_db, fdp->fd);

	destroy_block_cache(&fdp->block_cache);
	free(fdp->meta);
	free(fdp->filename);
	free(fdp);

	return res;
}

static tee_fs_off_t ree_fs_lseek(TEE_Result *errno, int fd,
				 tee_fs_off_t offset, int whence)
{
	tee_fs_off_t res = -1;
	tee_fs_off_t new_pos;
	size_t filelen;
	struct tee_fs_fd *fdp = handle_lookup(&fs_handle_db, fd);

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
 */
static int ree_fs_ftruncate_internal(TEE_Result *errno, struct tee_fs_fd *fdp,
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
			if (remove_block_file(fdp, old_block_num)) {
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

		res = 0;
		while (ext_len > 0) {
			size_t data_len = (ext_len > BLOCK_FILE_SIZE) ?
					BLOCK_FILE_SIZE : ext_len;

			DMSG("fill len=%zu", data_len);
			res = out_of_place_write(fdp, (void *)buf,
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

static int ree_fs_read(TEE_Result *errno, int fd, void *buf, size_t len)
{
	int res = -1;
	int start_block_num;
	int end_block_num;
	size_t remain_bytes = len;
	uint8_t *data_ptr = buf;
	struct tee_fs_fd *fdp = handle_lookup(&fs_handle_db, fd);

	assert(errno != NULL);
	*errno = TEE_SUCCESS;

	if (!fdp) {
		*errno = TEE_ERROR_BAD_PARAMETERS;
		goto exit;
	}

	if (fdp->pos + len > fdp->meta->info.length) {
		len = fdp->meta->info.length - fdp->pos;
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

	DMSG("%s, data len=%zu", fdp->filename, len);

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
static int ree_fs_write(TEE_Result *errno, int fd, const void *buf, size_t len)
{
	int res = -1;
	struct tee_fs_file_meta *new_meta = NULL;
	struct tee_fs_fd *fdp = handle_lookup(&fs_handle_db, fd);
	size_t file_size;
	int orig_pos;

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

	file_size = fdp->meta->info.length;
	orig_pos = fdp->pos;

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

	DMSG("%s, data len=%zu", fdp->filename, len);
	if (file_size < (size_t)fdp->pos) {
		DMSG("File hole detected, try to extend file size");
		res = ree_fs_ftruncate_internal(errno, fdp, fdp->pos);
		if (res < 0)
			goto exit;
	}

	new_meta = duplicate_meta(fdp);
	if (!new_meta) {
		*errno = TEE_ERROR_OUT_OF_MEMORY;
		goto exit;
	}

	res = out_of_place_write(fdp, buf, len, new_meta);
	if (res < 0) {
		*errno = TEE_ERROR_CORRUPT_OBJECT;
	} else {
		int r;
		int start_block_num;
		int end_block_num;

		r = commit_meta_file(fdp, new_meta);
		if (r < 0) {
			*errno = TEE_ERROR_CORRUPT_OBJECT;
			res = -1;
		}

		/* we are safe to free old blocks */
		start_block_num = pos_to_block_num(orig_pos);
		end_block_num = pos_to_block_num(fdp->pos - 1);
		while (start_block_num <= end_block_num) {
			if (remove_outdated_block(fdp, start_block_num))
				IMSG("Warning: Failed to free old block: %d",
					start_block_num);

			start_block_num++;
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
static int ree_fs_rename(const char *old, const char *new)
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

	if (old_len > TEE_FS_NAME_MAX || new_len > TEE_FS_NAME_MAX)
		goto exit;

	res = ree_fs_mkdir_ree(new,
			TEE_FS_S_IRUSR | TEE_FS_S_IWUSR);
	if (res)
		goto exit;

	old_dir = ree_fs_opendir_ree(old);
	if (!old_dir)
		goto exit;

	dirent = ree_fs_readdir_ree(old_dir);
	while (dirent) {
		if (!strncmp(dirent->d_name, "meta.", 5)) {
			meta_filename = strdup(dirent->d_name);
			meta_count++;
		} else {
			res = create_hard_link(old, new, dirent->d_name);
			if (res)
				goto exit_close_old_dir;
		}

		dirent = ree_fs_readdir_ree(old_dir);
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
	 * can completely remove ree_fs_rename(). We can simply
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
	ree_fs_closedir_ree(old_dir);
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
static int ree_fs_unlink(const char *file)
{
	int res = -1;
	char trash_file[TEE_FS_NAME_MAX + 6];

	if (!file)
		return -1;

	snprintf(trash_file, TEE_FS_NAME_MAX + 6, "%s.trash",
		file);

	res = ree_fs_rename(file, trash_file);
	if (res < 0)
		return res;

	unlink_tee_file(trash_file);

	return res;
}

static int ree_fs_ftruncate(TEE_Result *errno, int fd, tee_fs_off_t length)
{
	struct tee_fs_fd *fdp = handle_lookup(&fs_handle_db, fd);

	return ree_fs_ftruncate_internal(errno, fdp, length);
}

const struct tee_file_operations ree_fs_ops = {
	.open = ree_fs_open,
	.close = ree_fs_close,
	.read = ree_fs_read,
	.write = ree_fs_write,
	.lseek = ree_fs_lseek,
	.ftruncate = ree_fs_ftruncate,
	.rename = ree_fs_rename,
	.unlink = ree_fs_unlink,
	.mkdir = ree_fs_mkdir_ree,
	.opendir = ree_fs_opendir_ree,
	.closedir = ree_fs_closedir_ree,
	.readdir = ree_fs_readdir_ree,
	.rmdir = ree_fs_rmdir_ree,
	.access = ree_fs_access_ree
};
