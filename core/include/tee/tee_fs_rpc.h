/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016, Linaro Limited
 */

/*
 * Interface with tee-supplicant for file operations
 */

#ifndef TEE_FS_RPC_H
#define TEE_FS_RPC_H

#include <stdbool.h>
#include <stddef.h>
#include <tee_api_types.h>
#include <tee/tee_fs.h>
#include <kernel/thread.h>

struct tee_fs_rpc_operation {
	uint32_t id;
	struct thread_param params[THREAD_RPC_MAX_NUM_PARAMS];
	size_t num_params;
};

struct tee_fs_dirfile_fileh;

TEE_Result tee_fs_rpc_open(uint32_t id, struct tee_pobj *po, int *fd);
TEE_Result tee_fs_rpc_open_dfh(uint32_t id,
			       const struct tee_fs_dirfile_fileh *dfh, int *fd);
TEE_Result tee_fs_rpc_create(uint32_t id, struct tee_pobj *po, int *fd);
TEE_Result tee_fs_rpc_create_dfh(uint32_t id,
				 const struct tee_fs_dirfile_fileh *dfh,
				 int *fd);
TEE_Result tee_fs_rpc_close(uint32_t id, int fd);

TEE_Result tee_fs_rpc_read_init(struct tee_fs_rpc_operation *op,
				uint32_t id, int fd, tee_fs_off_t offset,
				size_t data_len, void **out_data);
TEE_Result tee_fs_rpc_read_final(struct tee_fs_rpc_operation *op,
				 size_t *data_len);

TEE_Result tee_fs_rpc_write_init(struct tee_fs_rpc_operation *op,
				 uint32_t id, int fd, tee_fs_off_t offset,
				 size_t data_len, void **data);
TEE_Result tee_fs_rpc_write_final(struct tee_fs_rpc_operation *op);


TEE_Result tee_fs_rpc_truncate(uint32_t id, int fd, size_t len);
TEE_Result tee_fs_rpc_remove(uint32_t id, struct tee_pobj *po);
TEE_Result tee_fs_rpc_remove_dfh(uint32_t id,
				 const struct tee_fs_dirfile_fileh *dfh);
TEE_Result tee_fs_rpc_rename(uint32_t id, struct tee_pobj *old,
			     struct tee_pobj *new, bool overwrite);

TEE_Result tee_fs_rpc_opendir(uint32_t id, const TEE_UUID *uuid,
				  struct tee_fs_dir **d);
TEE_Result tee_fs_rpc_closedir(uint32_t id, struct tee_fs_dir *d);
TEE_Result tee_fs_rpc_readdir(uint32_t id, struct tee_fs_dir *d,
			      struct tee_fs_dirent **ent);

struct thread_specific_data;
#if defined(CFG_WITH_USER_TA) && (defined(CFG_REE_FS) || defined(CFG_RPMB_FS))
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
void *tee_fs_rpc_cache_alloc(size_t size, struct mobj **mobj);

#endif /* TEE_FS_RPC_H */
