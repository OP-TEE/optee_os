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
#include <sys/queue.h>
#include <tee/tee_fs_key_manager.h>
#include <tee/tee_fs.h>

#define MAX_NUM_CACHED_BLOCKS	1


struct tee_file_info {
	struct fh_meta_data meta_data;
	uint8_t encrypted_fek[TEE_FS_KM_FEK_SIZE];
	char *filename;
};


TAILQ_HEAD(block_head, block);

struct block {
	TAILQ_ENTRY(block) list;
	int block_num;
	uint8_t *data;
	uint32_t data_size;
};

struct block_cache {
	struct block_head block_lru;
	uint8_t cached_block_num;
};

struct tee_fs_fd {
#ifndef CFG_RPMB_FS
	struct tee_file_info *file_info;
#endif
	int pos;
	uint32_t flags;
	int fd;
#ifdef CFG_RPMB_FS
	int nw_fd; /* Normal world */
	char *filename;
#endif
	bool is_new_file;
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
		struct fh_meta_data *meta,
		uint32_t block_num)
{
	uint32_t index = (block_num / 32);
	uint32_t block_mask = 1 << (block_num % 32);

	return !!(meta->data_block_backup_version[index] & block_mask);
}

static inline void toggle_backup_version_of_block(
		struct fh_meta_data *meta,
		size_t block_num)
{
	uint32_t index = (block_num / 32);
	uint32_t block_mask = 1 << (block_num % 32);

	meta->data_block_backup_version[index] ^= block_mask;
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
	TEE_Result (*write)(struct tee_fs_fd *fdp, struct block *b);
};

#endif
