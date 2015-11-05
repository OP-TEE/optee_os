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
#include <kernel/tee_ta_manager_unpg.h>
#include <tee_api_types.h>
#include <utee_types.h>
#include <assert.h>

extern vaddr_t tee_svc_uref_base;

struct tee_ta_session;

void syscall_sys_return(unsigned long ret);

void syscall_log(const void *buf, size_t len);

void syscall_panic(unsigned long code);

TEE_Result syscall_reserved(void);

TEE_Result syscall_not_supported(void);

uint32_t syscall_dummy(uint32_t *a);
uint32_t syscall_dummy_7args(unsigned long a1, unsigned long a2,
			unsigned long a3, unsigned long a4, unsigned long a5,
			unsigned long a6, unsigned long a7);

uint32_t syscall_nocall(void);

TEE_Result syscall_get_property(unsigned long prop, void *buf, size_t blen);

TEE_Result syscall_open_ta_session(const TEE_UUID *dest,
			unsigned long cancel_req_to, struct utee_params *params,
			uint32_t *sess, uint32_t *ret_orig);

TEE_Result syscall_close_ta_session(unsigned long sess);

TEE_Result syscall_invoke_ta_command(unsigned long sess,
			unsigned long cancel_req_to, unsigned long cmd_id,
			struct utee_params *params, uint32_t *ret_orig);

TEE_Result syscall_check_access_rights(unsigned long flags, const void *buf,
				       size_t len);

TEE_Result tee_svc_copy_from_user(struct tee_ta_session *sess, void *kaddr,
				  const void *uaddr, size_t len);
TEE_Result tee_svc_copy_to_user(struct tee_ta_session *sess, void *uaddr,
				const void *kaddr, size_t len);

TEE_Result tee_svc_copy_kaddr_to_uref(struct tee_ta_session *sess,
			uint32_t *uref, void *kaddr);

static inline uint32_t tee_svc_kaddr_to_uref(void *kaddr)
{
	assert(((vaddr_t)kaddr - tee_svc_uref_base) < UINT32_MAX);
	return (vaddr_t)kaddr - tee_svc_uref_base;
}

static inline vaddr_t tee_svc_uref_to_vaddr(uint32_t uref)
{
	return tee_svc_uref_base + uref;
}

static inline void *tee_svc_uref_to_kaddr(uint32_t uref)
{
	return (void *)tee_svc_uref_to_vaddr(uref);
}

TEE_Result syscall_get_cancellation_flag(uint32_t *cancel);

TEE_Result syscall_unmask_cancellation(uint32_t *old_mask);

TEE_Result syscall_mask_cancellation(uint32_t *old_mask);

TEE_Result syscall_wait(unsigned long timeout);

TEE_Result syscall_get_time(unsigned long cat, TEE_Time *time);
TEE_Result syscall_set_ta_time(const TEE_Time *time);

#ifdef CFG_CACHE_API
TEE_Result syscall_cache_operation(void *va, size_t len, unsigned long op);
#else
#define  syscall_cache_operation syscall_not_supported
#endif

void tee_svc_trace_syscall(int num);


#endif /* TEE_SVC_H */
