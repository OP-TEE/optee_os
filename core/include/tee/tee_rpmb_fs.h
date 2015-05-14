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

#ifndef TEE_RPMB_FS_H
#define TEE_RPMB_FS_H

#include <stddef.h>
#include <stdint.h>
#include <tee_api_types.h>

#define TEE_RPMB_FS_FILENAME_LENGTH 48

struct tee_rpmb_fs_stat {
	uint32_t size;
	uint32_t reserved;
};

/**
 * tee_rpmb_fs_open: Opens a file descriptor to the file.
 * If the file does not exist and TEE_FS_O_CREATE flag is specified
 * the file will be created empty.
 *
 * Returns the file descriptor or
 * a value < 0 on failure.
 */
int tee_rpmb_fs_open(const char *file, int flags, ...);

/**
 * tee_rpmb_fs_close: Closes the file opened by tee_rpmb_fs_open.
 *
 * Returns a value < 0 on failure.
 */
int tee_rpmb_fs_close(int fd);

/**
 * tee_rpmb_fs_read: Read entire file
 * Reads data from file pointed to by fd.
 * buf should be allocated by the client and its size must >= file size.
 *
 * Returns number of bytes read from the file or
 * a value < 0 on failure.
 */
int tee_rpmb_fs_read(int fd, uint8_t *buf, size_t size);

/**
 * tee_rpmb_fs_write: Write data to file
 * Write data to an existing file or create a new file and Write data.
 * The file contents will be overwritten with the new data.
 * size bytes of data will be copied from buf.
 *
 * Return n bytes written on success or a value < 0 on failure.
 */
int tee_rpmb_fs_write(int fd, uint8_t *buf, size_t size);

/**
 * tee_rpmb_fs_rm: Remove a file.
 * Only files that belongs to the client can be removed.
 */
TEE_Result tee_rpmb_fs_rm(const char *filename);

TEE_Result tee_rpmb_fs_rename(const char *old, const char *new);

TEE_Result tee_rpmb_fs_stat(const char *filename,
			    struct tee_rpmb_fs_stat *stat);

#endif
