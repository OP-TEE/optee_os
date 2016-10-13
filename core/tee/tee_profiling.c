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

#include <inttypes.h>
#include <kernel/tee_common_unpg.h>
#include <kernel/thread.h>
#include <kernel/user_ta.h>
#include <mm/core_memprot.h>
#include <mm/tee_mmu.h>
#include <optee_msg_supplicant.h>
#include <tee/tee_profiling.h>
#include <trace.h>
#include <utee_types.h>

/*
 * Send profile data to Normal World.
 * id [in/out]: (*id) should be set to 0 initially and passed unchanged to
 * subsequent calls
 */
TEE_Result syscall_gprof_send(void *buf, size_t len, uint32_t *id)
{
	struct optee_msg_param params[3];
	struct tee_ta_session *sess;
	struct user_ta_ctx *utc;
	TEE_Result res;
	uint64_t c = 0;
	paddr_t pa;
	char *va;

	res = tee_ta_get_current_session(&sess);
	if (res != TEE_SUCCESS)
		return res;

	utc = to_user_ta_ctx(sess->ctx);

	res = tee_mmu_check_access_rights(utc,
					  TEE_MEMORY_ACCESS_READ |
					  TEE_MEMORY_ACCESS_ANY_OWNER,
					  (tee_uaddr_t)buf, len);
	if (res != TEE_SUCCESS)
		return res;

	thread_rpc_alloc_payload(sizeof(utc->ctx.uuid) + len, &pa, &c);
	if (!pa)
		return TEE_ERROR_OUT_OF_MEMORY;

	va = phys_to_virt(pa, MEM_AREA_NSEC_SHM);
	if (!va)
		goto exit;

	memcpy(va, &utc->ctx.uuid, sizeof(utc->ctx.uuid));
	memcpy(va + sizeof(utc->ctx.uuid), buf, len);

	memset(params, 0, sizeof(params));
	params[0].attr = OPTEE_MSG_ATTR_TYPE_VALUE_INOUT;
	params[0].u.value.a = *id;

	params[1].attr = OPTEE_MSG_ATTR_TYPE_TMEM_INPUT;
	params[1].u.tmem.buf_ptr = pa;
	params[1].u.tmem.size = sizeof(utc->ctx.uuid);
	params[1].u.tmem.shm_ref = c;

	params[2].attr = OPTEE_MSG_ATTR_TYPE_TMEM_INPUT;
	params[2].u.tmem.buf_ptr = pa + sizeof(utc->ctx.uuid);
	params[2].u.tmem.size = len;
	params[2].u.tmem.shm_ref = c;

	res = thread_rpc_cmd(OPTEE_MSG_RPC_CMD_GPROF, 3, params);
	if (res != TEE_SUCCESS)
		goto exit;

	*id = (uint32_t)params[0].u.value.a;
exit:
	thread_rpc_free_payload(c);
	return res;
}
