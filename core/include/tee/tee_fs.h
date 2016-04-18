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

typedef int64_t tee_fs_off_t;
typedef uint32_t tee_fs_mode_t;

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
	struct tee_fs_dir *(*opendir)(const char *name);
	int (*closedir)(struct tee_fs_dir *d);
	struct tee_fs_dirent *(*readdir)(struct tee_fs_dir *d);
	int (*rmdir)(const char *pathname);
	int (*access)(const char *name, int mode);
};

#ifdef CFG_REE_FS
extern const struct tee_file_operations ree_fs_ops;
#endif
#ifdef CFG_RPMB_FS
extern const struct tee_file_operations rpmb_fs_ops;
#endif

#endif
