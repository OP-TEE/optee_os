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

#include <assert.h>
#include <kernel/msg_param.h>
#include <kernel/tee_misc.h>
#include <kernel/thread.h>
#include <mm/core_memprot.h>
#include <optee_msg_supplicant.h>
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
	struct tee_fs_rpc_operation op = { .id = id, .num_params = 3 };
	struct mobj *mobj;
	TEE_Result res;
	void *va;
	uint64_t cookie;

	va = tee_fs_rpc_cache_alloc(TEE_FS_NAME_MAX, &mobj, &cookie);
	if (!va)
		return TEE_ERROR_OUT_OF_MEMORY;

	op.params[0].attr = OPTEE_MSG_ATTR_TYPE_VALUE_INPUT;
	op.params[0].u.value.a = cmd;

	if (!msg_param_init_memparam(op.params + 1, mobj, 0, TEE_FS_NAME_MAX,
				     cookie, MSG_PARAM_MEM_DIR_IN))
		return TEE_ERROR_BAD_STATE;

	res = tee_svc_storage_create_filename(va, TEE_FS_NAME_MAX,
					      po, po->temporary);
	if (res != TEE_SUCCESS)
		return res;

	op.params[2].attr = OPTEE_MSG_ATTR_TYPE_VALUE_OUTPUT;

	res = operation_commit(&op);
	if (res == TEE_SUCCESS)
		*fd = op.params[2].u.value.a;

	return res;
}

TEE_Result tee_fs_rpc_open(uint32_t id, struct tee_pobj *po, int *fd)
{
	return operation_open(id, OPTEE_MRF_OPEN, po, fd);
}

TEE_Result tee_fs_rpc_create(uint32_t id, struct tee_pobj *po, int *fd)
{
	return operation_open(id, OPTEE_MRF_CREATE, po, fd);
}

static TEE_Result operation_open_dfh(uint32_t id, unsigned int cmd,
				 const struct tee_fs_dirfile_fileh *dfh,
				 int *fd)
{
	struct tee_fs_rpc_operation op = { .id = id, .num_params = 3 };
	struct mobj *mobj;
	TEE_Result res;
	void *va;
	uint64_t cookie;

	va = tee_fs_rpc_cache_alloc(TEE_FS_NAME_MAX, &mobj, &cookie);
	if (!va)
		return TEE_ERROR_OUT_OF_MEMORY;

	op.params[0].attr = OPTEE_MSG_ATTR_TYPE_VALUE_INPUT;
	op.params[0].u.value.a = cmd;

	if (!msg_param_init_memparam(op.params + 1, mobj, 0, TEE_FS_NAME_MAX,
				     cookie, MSG_PARAM_MEM_DIR_IN))
		return TEE_ERROR_BAD_STATE;

	res = tee_svc_storage_create_filename_dfh(va, TEE_FS_NAME_MAX, dfh);
	if (res != TEE_SUCCESS)
		return res;

	op.params[2].attr = OPTEE_MSG_ATTR_TYPE_VALUE_OUTPUT;

	res = operation_commit(&op);
	if (res == TEE_SUCCESS)
		*fd = op.params[2].u.value.a;

	return res;
}



TEE_Result tee_fs_rpc_open_dfh(uint32_t id,
			       const struct tee_fs_dirfile_fileh *dfh, int *fd)
{
	return operation_open_dfh(id, OPTEE_MRF_OPEN, dfh, fd);
}

TEE_Result tee_fs_rpc_create_dfh(uint32_t id,
				 const struct tee_fs_dirfile_fileh *dfh,
				 int *fd)
{
	return operation_open_dfh(id, OPTEE_MRF_CREATE, dfh, fd);
}

TEE_Result tee_fs_rpc_close(uint32_t id, int fd)
{
	struct tee_fs_rpc_operation op = { .id = id, .num_params = 1 };

	op.params[0].attr = OPTEE_MSG_ATTR_TYPE_VALUE_INPUT;
	op.params[0].u.value.a = OPTEE_MRF_CLOSE;
	op.params[0].u.value.b = fd;

	return operation_commit(&op);
}

TEE_Result tee_fs_rpc_read_init(struct tee_fs_rpc_operation *op,
				uint32_t id, int fd, tee_fs_off_t offset,
				size_t data_len, void **out_data)
{
	struct mobj *mobj;
	uint8_t *va;
	uint64_t cookie;

	if (offset < 0)
		return TEE_ERROR_BAD_PARAMETERS;

	va = tee_fs_rpc_cache_alloc(data_len, &mobj, &cookie);
	if (!va)
		return TEE_ERROR_OUT_OF_MEMORY;

	memset(op, 0, sizeof(*op));
	op->id = id;
	op->num_params = 2;

	op->params[0].attr = OPTEE_MSG_ATTR_TYPE_VALUE_INPUT;
	op->params[0].u.value.a = OPTEE_MRF_READ;
	op->params[0].u.value.b = fd;
	op->params[0].u.value.c = offset;

	if (!msg_param_init_memparam(op->params + 1, mobj, 0, data_len, cookie,
				     MSG_PARAM_MEM_DIR_OUT))
		return TEE_ERROR_BAD_STATE;

	*out_data = va;

	return TEE_SUCCESS;
}

TEE_Result tee_fs_rpc_read_final(struct tee_fs_rpc_operation *op,
				 size_t *data_len)
{
	TEE_Result res = operation_commit(op);

	if (res == TEE_SUCCESS)
		*data_len = msg_param_get_buf_size(op->params + 1);
	return res;
}

TEE_Result tee_fs_rpc_write_init(struct tee_fs_rpc_operation *op,
				 uint32_t id, int fd, tee_fs_off_t offset,
				 size_t data_len, void **data)
{
	struct mobj *mobj;
	uint8_t *va;
	uint64_t cookie;

	if (offset < 0)
		return TEE_ERROR_BAD_PARAMETERS;

	va = tee_fs_rpc_cache_alloc(data_len, &mobj, &cookie);
	if (!va)
		return TEE_ERROR_OUT_OF_MEMORY;

	memset(op, 0, sizeof(*op));
	op->id = id;
	op->num_params = 2;

	op->params[0].attr = OPTEE_MSG_ATTR_TYPE_VALUE_INPUT;
	op->params[0].u.value.a = OPTEE_MRF_WRITE;
	op->params[0].u.value.b = fd;
	op->params[0].u.value.c = offset;

	if (!msg_param_init_memparam(op->params + 1, mobj, 0, data_len, cookie,
				     MSG_PARAM_MEM_DIR_IN))
		return TEE_ERROR_BAD_STATE;

	*data = va;

	return TEE_SUCCESS;
}

TEE_Result tee_fs_rpc_write_final(struct tee_fs_rpc_operation *op)
{
	return operation_commit(op);
}

TEE_Result tee_fs_rpc_truncate(uint32_t id, int fd, size_t len)
{
	struct tee_fs_rpc_operation op = { .id = id, .num_params = 1 };

	op.params[0].attr = OPTEE_MSG_ATTR_TYPE_VALUE_INPUT;
	op.params[0].u.value.a = OPTEE_MRF_TRUNCATE;
	op.params[0].u.value.b = fd;
	op.params[0].u.value.c = len;

	return operation_commit(&op);
}

TEE_Result tee_fs_rpc_remove(uint32_t id, struct tee_pobj *po)
{
	TEE_Result res;
	struct tee_fs_rpc_operation op = { .id = id, .num_params = 2 };
	struct mobj *mobj;
	void *va;
	uint64_t cookie;

	va = tee_fs_rpc_cache_alloc(TEE_FS_NAME_MAX, &mobj, &cookie);
	if (!va)
		return TEE_ERROR_OUT_OF_MEMORY;

	op.params[0].attr = OPTEE_MSG_ATTR_TYPE_VALUE_INPUT;
	op.params[0].u.value.a = OPTEE_MRF_REMOVE;

	if (!msg_param_init_memparam(op.params + 1, mobj, 0, TEE_FS_NAME_MAX,
				     cookie, MSG_PARAM_MEM_DIR_IN))
		return TEE_ERROR_BAD_STATE;

	res = tee_svc_storage_create_filename(va, TEE_FS_NAME_MAX,
					      po, po->temporary);
	if (res != TEE_SUCCESS)
		return res;

	return operation_commit(&op);
}

TEE_Result tee_fs_rpc_remove_dfh(uint32_t id,
				 const struct tee_fs_dirfile_fileh *dfh)
{
	TEE_Result res;
	struct tee_fs_rpc_operation op = { .id = id, .num_params = 2 };
	struct mobj *mobj;
	void *va;
	uint64_t cookie;

	va = tee_fs_rpc_cache_alloc(TEE_FS_NAME_MAX, &mobj, &cookie);
	if (!va)
		return TEE_ERROR_OUT_OF_MEMORY;

	op.params[0].attr = OPTEE_MSG_ATTR_TYPE_VALUE_INPUT;
	op.params[0].u.value.a = OPTEE_MRF_REMOVE;

	if (!msg_param_init_memparam(op.params + 1, mobj, 0, TEE_FS_NAME_MAX,
				     cookie, MSG_PARAM_MEM_DIR_IN))
		return TEE_ERROR_BAD_STATE;

	res = tee_svc_storage_create_filename_dfh(va, TEE_FS_NAME_MAX, dfh);
	if (res != TEE_SUCCESS)
		return res;

	return operation_commit(&op);
}

TEE_Result tee_fs_rpc_rename(uint32_t id, struct tee_pobj *old,
			     struct tee_pobj *new, bool overwrite)
{
	TEE_Result res;
	struct tee_fs_rpc_operation op = { .id = id, .num_params = 3 };
	struct mobj *mobj;
	char *va;
	uint64_t cookie;
	bool temp;

	va = tee_fs_rpc_cache_alloc(TEE_FS_NAME_MAX * 2, &mobj, &cookie);
	if (!va)
		return TEE_ERROR_OUT_OF_MEMORY;

	op.params[0].attr = OPTEE_MSG_ATTR_TYPE_VALUE_INPUT;
	op.params[0].u.value.a = OPTEE_MRF_RENAME;
	op.params[0].u.value.b = overwrite;

	if (!msg_param_init_memparam(op.params + 1, mobj, 0, TEE_FS_NAME_MAX,
				     cookie, MSG_PARAM_MEM_DIR_IN))
		return TEE_ERROR_BAD_STATE;

	if (new)
		temp = old->temporary;
	else
		temp = true;
	res = tee_svc_storage_create_filename(va, TEE_FS_NAME_MAX,
					      old, temp);
	if (res != TEE_SUCCESS)
		return res;

	if (!msg_param_init_memparam(op.params + 2, mobj, TEE_FS_NAME_MAX,
				     TEE_FS_NAME_MAX, cookie,
				     MSG_PARAM_MEM_DIR_IN))
		return TEE_ERROR_BAD_STATE;

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

	return operation_commit(&op);
}

TEE_Result tee_fs_rpc_opendir(uint32_t id, const TEE_UUID *uuid,
			      struct tee_fs_dir **d)
{
	TEE_Result res;
	struct tee_fs_rpc_operation op = { .id = id, .num_params = 3 };
	struct mobj *mobj;
	void *va;
	uint64_t cookie;
	struct tee_fs_dir *dir = calloc(1, sizeof(*dir));

	if (!dir)
		return TEE_ERROR_OUT_OF_MEMORY;

	va = tee_fs_rpc_cache_alloc(TEE_FS_NAME_MAX, &mobj, &cookie);
	if (!va) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto err_exit;
	}

	op.params[0].attr = OPTEE_MSG_ATTR_TYPE_VALUE_INPUT;
	op.params[0].u.value.a = OPTEE_MRF_OPENDIR;

	if (!msg_param_init_memparam(op.params + 1, mobj, 0, TEE_FS_NAME_MAX,
				     cookie, MSG_PARAM_MEM_DIR_IN))
		return TEE_ERROR_BAD_STATE;

	res = tee_svc_storage_create_dirname(va, TEE_FS_NAME_MAX, uuid);
	if (res != TEE_SUCCESS)
		return res;

	op.params[2].attr = OPTEE_MSG_ATTR_TYPE_VALUE_OUTPUT;

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
	struct tee_fs_rpc_operation op = { .id = id, .num_params = 1 };

	op.params[0].attr = OPTEE_MSG_ATTR_TYPE_VALUE_INPUT;
	op.params[0].u.value.a = OPTEE_MRF_CLOSEDIR;
	op.params[0].u.value.b = d->nw_dir;

	free(d);
	return operation_commit(&op);
}

TEE_Result tee_fs_rpc_readdir(uint32_t id, struct tee_fs_dir *d,
			      struct tee_fs_dirent **ent)
{
	TEE_Result res;
	struct tee_fs_rpc_operation op = { .id = id, .num_params = 2 };
	struct mobj *mobj;
	void *va;
	uint64_t cookie;
	const size_t max_name_len = TEE_FS_NAME_MAX + 1;

	if (!d)
		return TEE_ERROR_ITEM_NOT_FOUND;

	va = tee_fs_rpc_cache_alloc(max_name_len, &mobj, &cookie);
	if (!va)
		return TEE_ERROR_OUT_OF_MEMORY;

	op.params[0].attr = OPTEE_MSG_ATTR_TYPE_VALUE_INPUT;
	op.params[0].u.value.a = OPTEE_MRF_READDIR;
	op.params[0].u.value.b = d->nw_dir;

	if (!msg_param_init_memparam(op.params + 1, mobj, 0, max_name_len,
				     cookie, MSG_PARAM_MEM_DIR_OUT))
		return TEE_ERROR_BAD_STATE;

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
