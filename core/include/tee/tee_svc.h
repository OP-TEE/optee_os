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
#ifndef TEE_SVC_H
#define TEE_SVC_H

#include <stdint.h>
#include <kernel/tee_common_unpg.h>	/* tee_uaddr_t */
#include <tee_api_types.h>
#include <tee/abi.h>
#include <utee_types.h>

struct tee_ta_session;

void tee_svc_sys_return(uint32_t ret, uint32_t param_types, void *params);

void tee_svc_sys_log(const void *buf, size_t len);

void tee_svc_sys_panic(uint32_t code);

TEE_Result tee_svc_reserved(void);

TEE_Result tee_svc_not_supported(void);

uint32_t tee_svc_sys_dummy(uint32_t *a);
uint32_t tee_svc_sys_dummy_7args(uint32_t a1, uint32_t a2, uint32_t a3,
				 uint32_t a4, uint32_t a5, uint32_t a6,
				 uint32_t a7);

uint32_t tee_svc_sys_nocall(void);

TEE_Result tee_svc_sys_get_property(uint32_t prop, tee_uaddr_t buf,
				    size_t blen);

TEE_Result tee_svc_open_ta_session(const TEE_UUID *dest,
				   uint32_t cancel_req_to, uint32_t param_types,
				   struct abi_user32_param *usr_params,
				   TEE_TASessionHandle *sess,
				   uint32_t *ret_orig);

TEE_Result tee_svc_close_ta_session(TEE_TASessionHandle sess);

TEE_Result tee_svc_invoke_ta_command(TEE_TASessionHandle sess,
				     uint32_t cancel_req_to, uint32_t cmd_id,
				     uint32_t param_types,
				     struct abi_user32_param *usr_params,
				     uint32_t *ret_orig);

TEE_Result tee_svc_check_access_rights(uint32_t flags, const void *buf,
				       size_t len);

TEE_Result tee_svc_copy_from_user(struct tee_ta_session *sess, void *kaddr,
				  const void *uaddr, size_t len);
TEE_Result tee_svc_copy_to_user(struct tee_ta_session *sess, void *uaddr,
				const void *kaddr, size_t len);
TEE_Result tee_svc_copy_kaddr_to_user32(struct tee_ta_session *sess,
					uint32_t *uaddr, const void *kaddr);

TEE_Result tee_svc_get_cancellation_flag(bool *cancel);

TEE_Result tee_svc_unmask_cancellation(bool *old_mask);

TEE_Result tee_svc_mask_cancellation(bool *old_mask);

TEE_Result tee_svc_wait(uint32_t timeout);

TEE_Result tee_svc_get_time(enum utee_time_category cat, TEE_Time *time);
TEE_Result tee_svc_set_ta_time(const TEE_Time *time);

#ifdef CFG_CACHE_API
TEE_Result tee_svc_cache_operation(void *va, size_t len,
				   enum utee_cache_operation op);
#else
#define  tee_svc_cache_operation tee_svc_not_supported
#endif

void tee_svc_trace_syscall(int num);


#endif /* TEE_SVC_H */
