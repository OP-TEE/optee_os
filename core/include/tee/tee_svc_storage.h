/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2023, Linaro Limited
 */

#ifndef __TEE_TEE_SVC_STORAGE_H
#define __TEE_TEE_SVC_STORAGE_H

#include <kernel/tee_ta_manager.h>
#include <tee_api_types.h>
#include <tee/tee_fs.h>
#include <tee/tee_obj.h>

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
				     struct utee_object_info *info,
				     void *obj_id, uint64_t *len);

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
TEE_Result tee_svc_storage_write_usage(struct tee_obj *o, uint32_t usage);

void tee_svc_storage_init(void);

#endif /* __TEE_TEE_SVC_STORAGE_H */
