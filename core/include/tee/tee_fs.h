/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
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

#ifndef TEE_FS_H
#define TEE_FS_H

#include <stddef.h>
#include <stdint.h>
#include <tee_api_types.h>

#define TEE_FS_NAME_MAX 350

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
 * file (see @backup_version_table in tee_fs_private.h), the
 * meta file itself also has backup_version, the update is
 * successful after new version of meta has been written.
 */
#define REE_FS_NAME_MAX (TEE_FS_NAME_MAX + 20)

typedef int64_t tee_fs_off_t;
typedef uint32_t tee_fs_mode_t;
typedef struct tee_fs_dir tee_fs_dir;

struct tee_fs_dirent {
	char *d_name;
};


/*
 * tee_fs implemets a POSIX like secure file system with GP extension
 */
struct tee_file_operations {
	int (*open)(TEE_Result *errno, const char *file, int flags, ...);
	int (*close)(int fd);
	int (*read)(TEE_Result *errno, int fd, void *buf, size_t len);
	int (*write)(TEE_Result *errno, int fd, const void *buf, size_t len);
	tee_fs_off_t (*lseek)(TEE_Result *errno,
			      int fd, tee_fs_off_t offset, int whence);
	int (*rename)(const char *old, const char *new);
	int (*unlink)(const char *file);
	int (*ftruncate)(TEE_Result *errno, int fd, tee_fs_off_t length);
	int (*mkdir)(const char *path, tee_fs_mode_t mode);
	tee_fs_dir *(*opendir)(const char *name);
	int (*closedir)(tee_fs_dir *d);
	struct tee_fs_dirent *(*readdir)(tee_fs_dir *d);
	int (*rmdir)(const char *pathname);
	int (*access)(const char *name, int mode);
};

struct tee_fs_rpc {
	int op;
	int flags;
	int arg;
	int fd;
	uint32_t len;
	int res;
};

extern struct tee_file_operations tee_file_ops;

int tee_fs_send_cmd(struct tee_fs_rpc *bf_cmd, void *data, uint32_t len,
		    uint32_t mode);

#endif
