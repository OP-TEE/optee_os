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

#include <stdlib.h>
#include <string.h>
#include <tee/tee_fs.h>
#include <tee/tee_fs_defs.h>
#include <mm/core_mmu.h>
#include "tee_api_defines.h"
#include <kernel/tee_common_unpg.h>
#include <trace.h>
#include <kernel/handle.h>

#include "tee_fs_private.h"

static int tee_fs_close(int fd)
{
	struct tee_fs_fd *fdp = tee_fs_fd_lookup(fd);

	return tee_fs_common_close(fdp);
}

static int tee_fs_read(TEE_Result *errno, int fd, void *buf, size_t len)
{
	struct tee_fs_fd *fdp = tee_fs_fd_lookup(fd);

	return tee_fs_common_read(errno, fdp, buf, len);
}

static int tee_fs_write(TEE_Result *errno, int fd, const void *buf, size_t len)
{
	struct tee_fs_fd *fdp = tee_fs_fd_lookup(fd);

	return tee_fs_common_write(errno, fdp, buf, len);
}

static tee_fs_off_t tee_fs_lseek(TEE_Result *errno,
				 int fd, tee_fs_off_t offset, int whence)
{
	struct tee_fs_fd *fdp = tee_fs_fd_lookup(fd);

	return tee_fs_common_lseek(errno, fdp, offset, whence);
}

static int tee_fs_ftruncate(TEE_Result *errno, int fd, tee_fs_off_t length)
{
	struct tee_fs_fd *fdp = tee_fs_fd_lookup(fd);

	return tee_fs_common_ftruncate(errno, fdp, length);
}

struct tee_file_operations tee_file_ops = {
	.open = tee_fs_common_open,
	.close = tee_fs_close,
	.read = tee_fs_read,
	.write = tee_fs_write,
	.lseek = tee_fs_lseek,
	.ftruncate = tee_fs_ftruncate,
	.rename = tee_fs_common_rename,
	.unlink = tee_fs_common_unlink,
	.mkdir = tee_fs_common_mkdir,
	.opendir = tee_fs_common_opendir,
	.closedir = tee_fs_common_closedir,
	.readdir = tee_fs_common_readdir,
	.rmdir = tee_fs_common_rmdir,
	.access = tee_fs_common_access
};
