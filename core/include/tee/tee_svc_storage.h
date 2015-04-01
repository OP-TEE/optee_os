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

#ifndef TEE_SVC_STORAGE_H
#define TEE_SVC_STORAGE_H

#include <tee_api_types.h>
#include <kernel/tee_ta_manager.h>

/*
 * Persistant Object Functions
 */
TEE_Result tee_svc_storage_obj_open(uint32_t storage_id, void *object_id,
				    uint32_t object_id_len, uint32_t flags,
				    uint32_t *obj);

TEE_Result tee_svc_storage_obj_create(uint32_t storage_id, void *object_id,
				      uint32_t object_id_len, uint32_t flags,
				      uint32_t attr, void *data, uint32_t len,
				      uint32_t *obj);

TEE_Result tee_svc_storage_obj_del(uint32_t obj);

TEE_Result tee_svc_storage_obj_rename(uint32_t obj, void *object_id,
				      uint32_t object_id_len);

/*
 * Persistent Object Enumeration Functions
 */
TEE_Result tee_svc_storage_alloc_enum(uint32_t *obj_enum);

TEE_Result tee_svc_storage_free_enum(uint32_t obj_enum);

TEE_Result tee_svc_storage_reset_enum(uint32_t obj_enum);

TEE_Result tee_svc_storage_start_enum(uint32_t obj_enum, uint32_t storage_id);

TEE_Result tee_svc_storage_next_enum(uint32_t obj_enum, TEE_ObjectInfo *info,
				     void *obj_id, uint32_t *len);

/*
 * Data Stream Access Functions
 */
TEE_Result tee_svc_storage_obj_read(uint32_t obj, void *data, size_t len,
				    uint32_t *count);

TEE_Result tee_svc_storage_obj_write(uint32_t obj, void *data, size_t len);

TEE_Result tee_svc_storage_obj_trunc(uint32_t obj, size_t len);

TEE_Result tee_svc_storage_obj_seek(uint32_t obj, int32_t offset,
				    TEE_Whence whence);

void tee_svc_storage_close_all_enum(struct tee_ta_ctx *ctx);

void tee_svc_storage_init(void);

#endif /* TEE_SVC_STORAGE_H */
