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
#include <tee/tee_fs.h>
#include <kernel/thread.h>

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

struct tee_fs_rpc_operation {
	uint32_t id;
	struct optee_msg_param params[THREAD_RPC_MAX_NUM_PARAMS];
	size_t num_params;
};

TEE_Result tee_fs_rpc_new_open(uint32_t id, const char *fname, int *fd);
TEE_Result tee_fs_rpc_new_create(uint32_t id, const char *fname, int *fd);
TEE_Result tee_fs_rpc_new_close(uint32_t id, int fd);

TEE_Result tee_fs_rpc_new_read_init(struct tee_fs_rpc_operation *op,
				    uint32_t id, int fd, tee_fs_off_t offset,
				    size_t data_len, void **out_data);
TEE_Result tee_fs_rpc_new_read_final(struct tee_fs_rpc_operation *op,
				     size_t *data_len);

TEE_Result tee_fs_rpc_new_write_init(struct tee_fs_rpc_operation *op,
				     uint32_t id, int fd, tee_fs_off_t offset,
				     size_t data_len, void **data);
TEE_Result tee_fs_rpc_new_write_final(struct tee_fs_rpc_operation *op);


TEE_Result tee_fs_rpc_new_truncate(uint32_t id, int fd, size_t len);
TEE_Result tee_fs_rpc_new_remove(uint32_t id, const char *fname);
TEE_Result tee_fs_rpc_new_rename(uint32_t id, const char *old_fname,
				 const char *new_fname, bool overwrite);

TEE_Result tee_fs_rpc_new_opendir(uint32_t id, const char *name,
				  struct tee_fs_dir **d);
TEE_Result tee_fs_rpc_new_closedir(uint32_t id, struct tee_fs_dir *d);
TEE_Result tee_fs_rpc_new_readdir(uint32_t id, struct tee_fs_dir *d,
				  struct tee_fs_dirent **ent);

TEE_Result tee_fs_rpc_new_begin_transaction(uint32_t id);
TEE_Result tee_fs_rpc_new_end_transaction(uint32_t id, bool rollback);

struct thread_specific_data;
#if defined(CFG_WITH_USER_TA) && \
	(defined(CFG_REE_FS) || defined(CFG_SQL_FS) || defined(CFG_RPMB_FS))
/* Frees the cache of allocated FS RPC memory */
void tee_fs_rpc_cache_clear(struct thread_specific_data *tsd);
#else
static inline void tee_fs_rpc_cache_clear(
			struct thread_specific_data *tsd __unused)
{
}
#endif

/*
 * Returns a pointer to the cached FS RPC memory. Each thread has a unique
 * cache. The pointer is guaranteed to point to a large enough area or to
 * be NULL.
 */
void *tee_fs_rpc_cache_alloc(size_t size, paddr_t *pa, uint64_t *cookie);

#endif /* TEE_FS_RPC_H */
