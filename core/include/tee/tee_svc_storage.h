/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#ifndef TEE_SVC_STORAGE_H
#define TEE_SVC_STORAGE_H

#include <tee_api_types.h>
#include <kernel/tee_ta_manager.h>
#include <tee/tee_fs.h>

/*
 * Returns the appropriate tee_file_operations for the specified storage ID.
 * The value TEE_STORAGE_PRIVATE will select the REE FS if available, otherwise
 * RPMB.
 */
const struct tee_file_operations *tee_svc_storage_file_ops(uint32_t storage_id);

/*
 * Persistant Object Functions
 */
TEE_Result syscall_storage_obj_open(unsigned long storage_id, void *object_id,
			size_t object_id_len, unsigned long flags,
			uint32_t *obj);

TEE_Result syscall_storage_obj_create(unsigned long storage_id, void *object_id,
			size_t object_id_len, unsigned long flags,
			unsigned long attr, void *data, size_t len,
			uint32_t *obj);

TEE_Result syscall_storage_obj_del(unsigned long obj);

TEE_Result syscall_storage_obj_rename(unsigned long obj, void *object_id,
			size_t object_id_len);

/*
 * Persistent Object Enumeration Functions
 */
TEE_Result syscall_storage_alloc_enum(uint32_t *obj_enum);

TEE_Result syscall_storage_free_enum(unsigned long obj_enum);

TEE_Result syscall_storage_reset_enum(unsigned long obj_enum);

TEE_Result syscall_storage_start_enum(unsigned long obj_enum,
			unsigned long storage_id);

TEE_Result syscall_storage_next_enum(unsigned long obj_enum,
			TEE_ObjectInfo *info, void *obj_id, uint64_t *len);

/*
 * Data Stream Access Functions
 */
TEE_Result syscall_storage_obj_read(unsigned long obj, void *data, size_t len,
			uint64_t *count);

TEE_Result syscall_storage_obj_write(unsigned long obj, void *data,
			size_t len);

TEE_Result syscall_storage_obj_trunc(unsigned long obj, size_t len);

TEE_Result syscall_storage_obj_seek(unsigned long obj, int32_t offset,
				    unsigned long whence);

void tee_svc_storage_close_all_enum(struct user_ta_ctx *utc);

void tee_svc_storage_init(void);

struct tee_pobj;
TEE_Result tee_svc_storage_create_filename(void *buf, size_t blen,
					   struct tee_pobj *po, bool transient);
struct tee_fs_dirfile_fileh;
TEE_Result
tee_svc_storage_create_filename_dfh(void *buf, size_t blen,
				    const struct tee_fs_dirfile_fileh *dfh);

TEE_Result tee_svc_storage_create_dirname(void *buf, size_t blen,
					  const TEE_UUID *uuid);

#endif /* TEE_SVC_STORAGE_H */
