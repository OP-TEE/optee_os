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
#include <kernel/syslog.h>
#include <kernel/thread.h>
#include <mm/core_memprot.h>
#include <stdbool.h>
#include <string.h>
#include <tee_api_types.h>
#include <trace.h>

static bool enabled;

void enable_syslog(void)
{
	if (enabled)
		return;
	IMSG("Redirecting traces and logs to normal world");
	enabled = true;
}

bool syslog(const char *str)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	size_t len = strlen(str) + 1;
	struct optee_msg_param params;
	paddr_t phpayload = 0;
	uint64_t cpayload = 0;
	void *bf;

	if (!enabled)
		return false;

	thread_rpc_alloc_payload(len, &phpayload, &cpayload);
	if (!phpayload)
		return false;

	bf = phys_to_virt(phpayload, MEM_AREA_NSEC_SHM);
	if (!bf)
		goto exit;

	memset(&params, 0, sizeof(params));
	params.attr = OPTEE_MSG_ATTR_TYPE_TMEM_INOUT;
	params.u.tmem.buf_ptr = phpayload;
	params.u.tmem.size = len;
	params.u.tmem.shm_ref = cpayload;

	memcpy(bf, str, len);

	ret = thread_rpc_cmd(OPTEE_MSG_RPC_CMD_LOG, 1, &params);

exit:
	thread_rpc_free_payload(cpayload);
	return (ret == TEE_SUCCESS);
}
