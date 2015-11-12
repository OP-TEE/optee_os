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

#include <tee/tee_fs.h>

#define REE_FS_NAME_MAX 380


TEE_Result read_ree_file(const char *ree_path,
		uint8_t **out, uint32_t *out_size);

TEE_Result write_ree_file(char *ree_path,
		uint8_t *in, uint32_t in_size);

struct ree_file_operations {
	int (*open)(const char *file, int flags, ...);
	int (*read)(int fd, void *buf, size_t len);
	int (*write)(int fd, const void *buf, size_t len);
	int (*ftruncate)(int fd, tee_fs_off_t length);
	int (*close)(int fd);
	int (*rename)(const char *old, const char *new);
	tee_fs_off_t (*lseek)(int fd, tee_fs_off_t offset, int whence);
	int (*link)(const char *old, const char *new);
	int (*unlink)(const char *file);
	int (*mkdir)(const char *path, tee_fs_mode_t mode);
	tee_fs_dir *(*opendir)(const char *name);
	int (*closedir)(tee_fs_dir *d);
	struct tee_fs_dirent *(*readdir)(tee_fs_dir *d);
	int (*rmdir)(const char *pathname);
	int (*access)(const char *name, int mode);
	int (*get_file_length)(int fd, uint32_t *length);
};

extern struct ree_file_operations ree_file_ops;
