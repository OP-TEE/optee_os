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

#define TEE_FS_NAME_MAX 150

typedef int tee_fs_off_t;
typedef uint32_t tee_fs_mode_t;
typedef struct tee_fs_dir tee_fs_dir;

struct tee_fs_dirent {
	char *d_name;
};

/*
 * tee_fs implemets a POSIX like secure file system
 */
int tee_fs_open(const char *file, int flags, ...);

int tee_fs_close(int fd);

int tee_fs_read(int fd, void *buf, size_t len);

int tee_fs_write(int fd, const void *buf, size_t len);

tee_fs_off_t tee_fs_lseek(int fd, tee_fs_off_t offset, int whence);

int tee_fs_rename(const char *old, const char *new);

int tee_fs_unlink(const char *file);

int tee_fs_ftruncate(int fd, tee_fs_off_t length);

int tee_fs_mkdir(const char *path, tee_fs_mode_t mode);

tee_fs_dir *tee_fs_opendir(const char *name);

int tee_fs_closedir(tee_fs_dir *d);

struct tee_fs_dirent *tee_fs_readdir(tee_fs_dir *d);

int tee_fs_rmdir(const char *pathname);

int tee_fs_access(const char *name, int mode);

struct tee_fs_rpc {
	int op;
	int flags;
	int arg;
	int fd;
	uint32_t len;
	int res;
};
int tee_fs_send_cmd(struct tee_fs_rpc *bf_cmd, void *data, uint32_t len,
		    uint32_t mode);

#endif
