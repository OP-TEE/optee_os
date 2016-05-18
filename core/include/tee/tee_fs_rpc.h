/*
 * Copyright (c) 2016, Linaro Limited
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

/*
 * Interface with tee-supplicant for POSIX-like file operations
 */

#ifndef TEE_FS_RPC_H
#define TEE_FS_RPC_H

#include <stdbool.h>
#include <stddef.h>
#include <tee_api_types.h>

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
#define TEE_FS_BEGIN     16 /* SQL FS: begin transaction */
#define TEE_FS_END       17 /* SQL FS: end transaction */

/* sql_fs_send_cmd 'mode' */
#define TEE_FS_MODE_NONE 0
#define TEE_FS_MODE_IN   1
#define TEE_FS_MODE_OUT  2

struct tee_fs_rpc {
	int op;
	int flags;
	int arg;
	int fd;
	uint32_t len;
	int res;
};

/*
 * Return values:
 *   < 0: error. The actual value is meaningless (see below).
 *  >= 0: success. The value may be a file descriptor, a number of bytes, or
 *        simply 0 depending on the function.
 *
 * The return value is the status set by the normal world (tee-supplicant) or
 * -1 in case of communication error. To facilitate debugging, tee-supplicant
 * uses -(errno) when an error code from libc is available. Therefore the
 * values are non-portable and specific values must not be tested in the code.
 */
int tee_fs_rpc_access(int id, const char *name, int mode);
int tee_fs_rpc_begin_transaction(int id);
int tee_fs_rpc_close(int id, int fd);
int tee_fs_rpc_end_transaction(int id, bool rollback);
int tee_fs_rpc_ftruncate(int id, int fd, tee_fs_off_t length);
int tee_fs_rpc_link(int id, const char *old, const char *nw);
tee_fs_off_t tee_fs_rpc_lseek(int id, int fd, tee_fs_off_t offset,
				  int whence);
int tee_fs_rpc_mkdir(int id, const char *path, tee_fs_mode_t mode);
int tee_fs_rpc_open(int id, const char *file, int flags);
struct tee_fs_dir *tee_fs_rpc_opendir(int id, const char *name);
int tee_fs_rpc_read(int id, int fd, void *buf, size_t len);
struct tee_fs_dirent *tee_fs_rpc_readdir(int id, struct tee_fs_dir *d);
int tee_fs_rpc_rename(int id, const char *old, const char *nw);
int tee_fs_rpc_write(int id, int fd, const void *buf, size_t len);
int tee_fs_rpc_closedir(int id, struct tee_fs_dir *d);
int tee_fs_rpc_rmdir(int id, const char *name);
int tee_fs_rpc_unlink(int id, const char *file);

#endif /* TEE_FS_RPC_H */
