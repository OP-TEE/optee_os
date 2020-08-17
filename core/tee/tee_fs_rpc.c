// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016, Linaro Limited
 */

#include <assert.h>
#include <kernel/tee_misc.h>
#include <kernel/thread.h>
#include <mm/core_memprot.h>
#include <optee_rpc_cmd.h>
#include <stdlib.h>
#include <string_ext.h>
#include <string.h>
#include <tee/tee_fs.h>
#include <tee/tee_fs_rpc.h>
#include <tee/tee_pobj.h>
#include <tee/tee_svc_storage.h>
#include <trace.h>
#include <util.h>

struct tee_fs_dir {
	int nw_dir;
	struct tee_fs_dirent d;
};

static TEE_Result operation_commit(struct tee_fs_rpc_operation *op)
{
	return thread_rpc_cmd(op->id, op->num_params, op->params);
}

static TEE_Result operation_open(uint32_t id, unsigned int cmd,
				 struct tee_pobj *po, int *fd)
{
	struct mobj *mobj;
	TEE_Result res;
	void *va;

	va = thread_rpc_shm_cache_alloc(THREAD_SHM_CACHE_USER_FS,
					THREAD_SHM_TYPE_APPLICATION,
					TEE_FS_NAME_MAX, &mobj);
	if (!va)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = tee_svc_storage_create_filename(va, TEE_FS_NAME_MAX,
					      po, po->temporary);
	if (res != TEE_SUCCESS)
		return res;

	struct tee_fs_rpc_operation op = {
		.id = id, .num_params = 3, .params = {
			[0] = THREAD_PARAM_VALUE(IN, cmd, 0, 0),
			[1] = THREAD_PARAM_MEMREF(IN, mobj, 0, TEE_FS_NAME_MAX),
			[2] = THREAD_PARAM_VALUE(OUT, 0, 0, 0),
	} };

	res = operation_commit(&op);
	if (res == TEE_SUCCESS)
		*fd = op.params[2].u.value.a;

	return res;
}

TEE_Result tee_fs_rpc_open(uint32_t id, struct tee_pobj *po, int *fd)
{
	return operation_open(id, OPTEE_RPC_FS_OPEN, po, fd);
}

TEE_Result tee_fs_rpc_create(uint32_t id, struct tee_pobj *po, int *fd)
{
	return operation_open(id, OPTEE_RPC_FS_CREATE, po, fd);
}

static TEE_Result operation_open_dfh(uint32_t id, unsigned int cmd,
				 const struct tee_fs_dirfile_fileh *dfh,
				 int *fd)
{
	struct mobj *mobj;
	TEE_Result res;
	void *va;

	va = thread_rpc_shm_cache_alloc(THREAD_SHM_CACHE_USER_FS,
					THREAD_SHM_TYPE_APPLICATION,
					TEE_FS_NAME_MAX, &mobj);
	if (!va)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = tee_svc_storage_create_filename_dfh(va, TEE_FS_NAME_MAX, dfh);
	if (res != TEE_SUCCESS)
		return res;

	struct tee_fs_rpc_operation op = {
		.id = id, .num_params = 3, .params = {
			[0] = THREAD_PARAM_VALUE(IN, cmd, 0, 0),
			[1] = THREAD_PARAM_MEMREF(IN, mobj, 0, TEE_FS_NAME_MAX),
			[2] = THREAD_PARAM_VALUE(OUT, 0, 0, 0),
	} };

	res = operation_commit(&op);
	if (res == TEE_SUCCESS)
		*fd = op.params[2].u.value.a;

	return res;
}



TEE_Result tee_fs_rpc_open_dfh(uint32_t id,
			       const struct tee_fs_dirfile_fileh *dfh, int *fd)
{
	return operation_open_dfh(id, OPTEE_RPC_FS_OPEN, dfh, fd);
}

TEE_Result tee_fs_rpc_create_dfh(uint32_t id,
				 const struct tee_fs_dirfile_fileh *dfh,
				 int *fd)
{
	return operation_open_dfh(id, OPTEE_RPC_FS_CREATE, dfh, fd);
}

TEE_Result tee_fs_rpc_close(uint32_t id, int fd)
{
	struct tee_fs_rpc_operation op = {
		.id = id, .num_params = 1, .params = {
			[0] = THREAD_PARAM_VALUE(IN, OPTEE_RPC_FS_CLOSE, fd, 0),
		},
	};

	return operation_commit(&op);
}

TEE_Result tee_fs_rpc_read_init(struct tee_fs_rpc_operation *op,
				uint32_t id, int fd, tee_fs_off_t offset,
				size_t data_len, void **out_data)
{
	struct mobj *mobj;
	uint8_t *va;

	if (offset < 0)
		return TEE_ERROR_BAD_PARAMETERS;

	va = thread_rpc_shm_cache_alloc(THREAD_SHM_CACHE_USER_FS,
					THREAD_SHM_TYPE_APPLICATION,
					data_len, &mobj);
	if (!va)
		return TEE_ERROR_OUT_OF_MEMORY;

	*op = (struct tee_fs_rpc_operation){
		.id = id, .num_params = 2, .params = {
			[0] = THREAD_PARAM_VALUE(IN, OPTEE_RPC_FS_READ, fd,
						 offset),
			[1] = THREAD_PARAM_MEMREF(OUT, mobj, 0, data_len),
		},
	};

	*out_data = va;

	return TEE_SUCCESS;
}

TEE_Result tee_fs_rpc_read_final(struct tee_fs_rpc_operation *op,
				 size_t *data_len)
{
	TEE_Result res = operation_commit(op);

	if (res == TEE_SUCCESS)
		*data_len = op->params[1].u.memref.size;
	return res;
}

TEE_Result tee_fs_rpc_write_init(struct tee_fs_rpc_operation *op,
				 uint32_t id, int fd, tee_fs_off_t offset,
				 size_t data_len, void **data)
{
	struct mobj *mobj;
	uint8_t *va;

	if (offset < 0)
		return TEE_ERROR_BAD_PARAMETERS;

	va = thread_rpc_shm_cache_alloc(THREAD_SHM_CACHE_USER_FS,
					THREAD_SHM_TYPE_APPLICATION,
					data_len, &mobj);
	if (!va)
		return TEE_ERROR_OUT_OF_MEMORY;

	*op = (struct tee_fs_rpc_operation){
		.id = id, .num_params = 2, .params = {
			[0] = THREAD_PARAM_VALUE(IN, OPTEE_RPC_FS_WRITE, fd,
						 offset),
			[1] = THREAD_PARAM_MEMREF(IN, mobj, 0, data_len),
		},
	};

	*data = va;

	return TEE_SUCCESS;
}

TEE_Result tee_fs_rpc_write_final(struct tee_fs_rpc_operation *op)
{
	return operation_commit(op);
}

TEE_Result tee_fs_rpc_truncate(uint32_t id, int fd, size_t len)
{
	struct tee_fs_rpc_operation op = {
		.id = id, .num_params = 1, .params = {
			[0] = THREAD_PARAM_VALUE(IN, OPTEE_RPC_FS_TRUNCATE, fd,
						 len),
		}
	};

	return operation_commit(&op);
}

TEE_Result tee_fs_rpc_remove(uint32_t id, struct tee_pobj *po)
{
	TEE_Result res;
	struct mobj *mobj;
	void *va;

	va = thread_rpc_shm_cache_alloc(THREAD_SHM_CACHE_USER_FS,
					THREAD_SHM_TYPE_APPLICATION,
					TEE_FS_NAME_MAX, &mobj);
	if (!va)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = tee_svc_storage_create_filename(va, TEE_FS_NAME_MAX,
					      po, po->temporary);
	if (res != TEE_SUCCESS)
		return res;

	struct tee_fs_rpc_operation op = {
		.id = id, .num_params = 2, .params = {
			[0] = THREAD_PARAM_VALUE(IN, OPTEE_RPC_FS_REMOVE, 0, 0),
			[1] = THREAD_PARAM_MEMREF(IN, mobj, 0, TEE_FS_NAME_MAX),
		},
	};

	return operation_commit(&op);
}

TEE_Result tee_fs_rpc_remove_dfh(uint32_t id,
				 const struct tee_fs_dirfile_fileh *dfh)
{
	TEE_Result res;
	struct mobj *mobj;
	void *va;

	va = thread_rpc_shm_cache_alloc(THREAD_SHM_CACHE_USER_FS,
					THREAD_SHM_TYPE_APPLICATION,
					TEE_FS_NAME_MAX, &mobj);
	if (!va)
		return TEE_ERROR_OUT_OF_MEMORY;


	res = tee_svc_storage_create_filename_dfh(va, TEE_FS_NAME_MAX, dfh);
	if (res != TEE_SUCCESS)
		return res;

	struct tee_fs_rpc_operation op = {
		.id = id, .num_params = 2, .params = {
			[0] = THREAD_PARAM_VALUE(IN, OPTEE_RPC_FS_REMOVE, 0, 0),
			[1] = THREAD_PARAM_MEMREF(IN, mobj, 0, TEE_FS_NAME_MAX),
		}
	};

	return operation_commit(&op);
}

TEE_Result tee_fs_rpc_rename(uint32_t id, struct tee_pobj *old,
			     struct tee_pobj *new, bool overwrite)
{
	TEE_Result res;
	struct mobj *mobj;
	char *va;
	bool temp;

	va = thread_rpc_shm_cache_alloc(THREAD_SHM_CACHE_USER_FS,
					THREAD_SHM_TYPE_APPLICATION,
					TEE_FS_NAME_MAX * 2, &mobj);
	if (!va)
		return TEE_ERROR_OUT_OF_MEMORY;


	if (new)
		temp = old->temporary;
	else
		temp = true;
	res = tee_svc_storage_create_filename(va, TEE_FS_NAME_MAX,
					      old, temp);
	if (res != TEE_SUCCESS)
		return res;

	if (new) {
		res = tee_svc_storage_create_filename(va + TEE_FS_NAME_MAX,
						      TEE_FS_NAME_MAX,
						      new, new->temporary);
	} else {
		res = tee_svc_storage_create_filename(va + TEE_FS_NAME_MAX,
						      TEE_FS_NAME_MAX,
						      old, false);
	}
	if (res != TEE_SUCCESS)
		return res;

	struct tee_fs_rpc_operation op = {
		.id = id, .num_params = 3, .params = {
			[0] = THREAD_PARAM_VALUE(IN, OPTEE_RPC_FS_RENAME,
						 overwrite, 0),
			[1] = THREAD_PARAM_MEMREF(IN, mobj, 0, TEE_FS_NAME_MAX),
			[2] = THREAD_PARAM_MEMREF(IN, mobj, TEE_FS_NAME_MAX,
						  TEE_FS_NAME_MAX),
		}
	};

	return operation_commit(&op);
}

TEE_Result tee_fs_rpc_opendir(uint32_t id, const TEE_UUID *uuid,
			      struct tee_fs_dir **d)
{
	TEE_Result res;
	struct mobj *mobj;
	void *va;
	struct tee_fs_dir *dir = calloc(1, sizeof(*dir));

	if (!dir)
		return TEE_ERROR_OUT_OF_MEMORY;

	va = thread_rpc_shm_cache_alloc(THREAD_SHM_CACHE_USER_FS,
					THREAD_SHM_TYPE_APPLICATION,
					TEE_FS_NAME_MAX, &mobj);
	if (!va) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto err_exit;
	}


	res = tee_svc_storage_create_dirname(va, TEE_FS_NAME_MAX, uuid);
	if (res != TEE_SUCCESS)
		goto err_exit;

	struct tee_fs_rpc_operation op = {
		.id = id, .num_params = 3, .params = {
			[0] = THREAD_PARAM_VALUE(IN, OPTEE_RPC_FS_OPENDIR,
						 0, 0),
			[1] = THREAD_PARAM_MEMREF(IN, mobj, 0, TEE_FS_NAME_MAX),
			[2] = THREAD_PARAM_VALUE(OUT, 0, 0, 0),
		}
	};

	res = operation_commit(&op);

	if (res != TEE_SUCCESS)
		goto err_exit;

	dir->nw_dir = op.params[2].u.value.a;
	*d = dir;

	return TEE_SUCCESS;
err_exit:
	free(dir);

	return res;
}

TEE_Result tee_fs_rpc_closedir(uint32_t id, struct tee_fs_dir *d)
{
	struct tee_fs_rpc_operation op = {
		.id = id, .num_params = 1, .params = {
			[0] = THREAD_PARAM_VALUE(IN, OPTEE_RPC_FS_CLOSEDIR,
						 d->nw_dir, 0),
		}
	};

	free(d);
	return operation_commit(&op);
}

TEE_Result tee_fs_rpc_readdir(uint32_t id, struct tee_fs_dir *d,
			      struct tee_fs_dirent **ent)
{
	TEE_Result res;
	struct mobj *mobj;
	void *va;
	const size_t max_name_len = TEE_FS_NAME_MAX + 1;

	if (!d)
		return TEE_ERROR_ITEM_NOT_FOUND;

	va = thread_rpc_shm_cache_alloc(THREAD_SHM_CACHE_USER_FS,
					THREAD_SHM_TYPE_APPLICATION,
					max_name_len, &mobj);
	if (!va)
		return TEE_ERROR_OUT_OF_MEMORY;

	struct tee_fs_rpc_operation op = {
		.id = id, .num_params = 2, .params = {
			[0] = THREAD_PARAM_VALUE(IN, OPTEE_RPC_FS_READDIR,
						 d->nw_dir, 0),
			[1] = THREAD_PARAM_MEMREF(OUT, mobj, 0, max_name_len),
		}
	};

	res = operation_commit(&op);
	if (res != TEE_SUCCESS)
		return res;

	d->d.oidlen = tee_hs2b(va, d->d.oid, strnlen(va, max_name_len),
			       sizeof(d->d.oid));
	if (!d->d.oidlen)
		return TEE_ERROR_OUT_OF_MEMORY;

	*ent = &d->d;
	return TEE_SUCCESS;
}
