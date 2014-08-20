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

#include <stdlib.h>
#include <string.h>
#include <tee/tee_fs.h>
#include <tee/tee_fs_defs.h>
#include <kernel/tee_rpc.h>
#include <kernel/tee_rpc_types.h>
#include <mm/core_mmu.h>
#include "tee_api_defines.h"
#include <kernel/util.h>
#include <kernel/tee_ta_manager.h>
#include <kernel/thread.h>
#include <sm/teesmc.h>

int tee_fs_send_cmd(struct tee_fs_rpc *bf_cmd, void *data, uint32_t len,
		    uint32_t mode)
{
	struct tee_ta_session *sess = NULL;
	struct teesmc32_arg *arg;
	struct teesmc32_param *params;
	const size_t num_params = 1;
	paddr_t pharg = 0;
	paddr_t phpayload = 0;
	paddr_t cookie = 0;
	struct tee_fs_rpc *bf;
	int res = -1;

	tee_ta_get_current_session(&sess);
	tee_ta_set_current_session(NULL);

	pharg = thread_rpc_alloc_arg(TEESMC32_GET_ARG_SIZE(num_params));
	thread_st_rpc_alloc_payload(sizeof(struct tee_fs_rpc) + len,
					        &phpayload, &cookie);
	if (!pharg || !phpayload)
		goto exit;

	if (!TEE_ALIGNMENT_IS_OK(pharg, struct teesmc32_arg) ||
	    !TEE_ALIGNMENT_IS_OK(phpayload, struct tee_fs_rpc))
		goto exit;

	if (core_pa2va(pharg, (uint32_t *)&arg) ||
	    core_pa2va(phpayload, (uint32_t *)&bf))
		goto exit;

	arg->cmd = TEE_RPC_FS;
	arg->ret = TEE_ERROR_GENERIC;
	arg->num_params = num_params;
	params = TEESMC32_GET_PARAMS(arg);
	params[0].attr = TEESMC_ATTR_TYPE_MEMREF_INOUT |
			 (TEESMC_ATTR_CACHE_I_WRITE_THR |
			  TEESMC_ATTR_CACHE_O_WRITE_THR) <<
				TEESMC_ATTR_CACHE_SHIFT;

	params[0].u.memref.buf_ptr = phpayload;
	params[0].u.memref.size = sizeof(struct tee_fs_rpc) + len;

	/* fill in parameters */
	*bf = *bf_cmd;

	if (mode & TEE_FS_MODE_IN) {
		tee_ta_set_current_session(sess);
		memcpy((void *)(bf + 1), data, len);
		tee_ta_set_current_session(NULL);
	}

	thread_rpc_cmd(pharg);
	/* update result */
	*bf_cmd = *bf;
	if (arg->ret != TEE_SUCCESS)
		goto exit;

	if (mode & TEE_FS_MODE_OUT) {
		uint32_t olen = MIN(len, bf->len);

		tee_ta_set_current_session(sess);
		memcpy(data, (void *)(bf + 1), olen);
		tee_ta_set_current_session(NULL);
	}

	res = 0;

exit:
	thread_rpc_free_arg(pharg);
	thread_st_rpc_free_payload(cookie);
	tee_ta_set_current_session(sess);
	return res;
}
