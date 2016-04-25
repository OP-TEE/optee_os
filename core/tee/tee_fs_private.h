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

struct tee_fs_fd;

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
