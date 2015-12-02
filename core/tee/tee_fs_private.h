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

#ifndef TEE_FS_PRIV_H
#define TEE_FS_PRIV_H

#include <utee_defines.h>
#include <tee/tee_fs_key_manager.h>

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

#define FILE_BLOCK_SHIFT	12

#define FILE_BLOCK_SIZE		(1 << FILE_BLOCK_SHIFT)

#define NUM_BLOCKS_PER_FILE	1024

#define MAX_FILE_SIZE	(FILE_BLOCK_SIZE * NUM_BLOCKS_PER_FILE)

#define READ_ALL 0

#define COPY_BUF_SIZE	1024

struct tee_fs_file_info {
	size_t length;
	uint32_t backup_version_table[NUM_BLOCKS_PER_FILE / 32];
};

struct tee_fs_file_meta {
	struct tee_fs_file_info info;
	uint8_t encrypted_fek[TEE_FS_KM_FEK_SIZE];
	uint8_t backup_version;
};

struct tee_fs_fd {
	struct tee_fs_file_meta *meta;
	int pos;
	uint32_t flags;
	int fd;
	int nw_fd; /* Normal world */
	bool is_new_file;
	char *filename;
	void *private;
};
#define tee_fs_fd_priv(fdp) ((fdp)->private)

struct tee_fs_dir {
	int nw_dir;
	struct tee_fs_dirent d;
};

static inline int pos_to_block_num(int position)
{
	return position >> FILE_BLOCK_SHIFT;
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

struct tee_fs_fd *tee_fs_fd_lookup(int fd);

int tee_fs_common_open(TEE_Result *errno, const char *file, int flags, ...);

int tee_fs_common_close(struct tee_fs_fd *fdp);

tee_fs_off_t tee_fs_common_lseek(TEE_Result *errno, struct tee_fs_fd *fdp,
		tee_fs_off_t offset, int whence);

int tee_fs_common_ftruncate(TEE_Result *errno, struct tee_fs_fd *fdp,
		tee_fs_off_t length);

int tee_fs_common_read(TEE_Result *errno, struct tee_fs_fd *fdp,
		void *buf, size_t len);

int tee_fs_common_write(TEE_Result *errno, struct tee_fs_fd *fdp,
		const void *buf, size_t len);

int tee_fs_common_rename(const char *old, const char *new);

int tee_fs_common_unlink(const char *file);

int tee_fs_common_mkdir(const char *path, tee_fs_mode_t mode);

tee_fs_dir *tee_fs_common_opendir(const char *name);

int tee_fs_common_closedir(tee_fs_dir *d);

struct tee_fs_dirent *tee_fs_common_readdir(tee_fs_dir *d);

int tee_fs_common_rmdir(const char *name);

int tee_fs_common_access(const char *name, int mode);

#endif
