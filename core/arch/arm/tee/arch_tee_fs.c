/*
 * Copyright (c) 2016, Linaro Limited
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
#include <mm/core_memprot.h>
#include "tee_api_defines.h"
#include <util.h>
#include <kernel/thread.h>
#include <optee_msg.h>

int tee_fs_send_cmd(struct tee_fs_rpc *bf_cmd, void *data, uint32_t len,
		    uint32_t mode)
{
	TEE_Result ret;
	struct optee_msg_param params;
	paddr_t phpayload = 0;
	uint64_t cpayload = 0;
	struct tee_fs_rpc *bf;
	int res = -1;

	thread_rpc_alloc_payload(sizeof(struct tee_fs_rpc) + len,
				 &phpayload, &cpayload);
	if (!phpayload)
		return -1;

	if (!ALIGNMENT_IS_OK(phpayload, struct tee_fs_rpc))
		goto exit;

	bf = phys_to_virt(phpayload, MEM_AREA_NSEC_SHM);
	if (!bf)
		goto exit;

	memset(&params, 0, sizeof(params));
	params.attr = OPTEE_MSG_ATTR_TYPE_TMEM_INOUT;
	params.u.tmem.buf_ptr = phpayload;
	params.u.tmem.size = sizeof(struct tee_fs_rpc) + len;
	params.u.tmem.shm_ref = cpayload;

	/* fill in parameters */
	*bf = *bf_cmd;

	if (mode & TEE_FS_MODE_IN) {
		memcpy((void *)(bf + 1), data, len);
	}

	ret = thread_rpc_cmd(OPTEE_MSG_RPC_CMD_FS, 1, &params);
	/* update result */
	*bf_cmd = *bf;
	if (ret != TEE_SUCCESS)
		goto exit;

	if (mode & TEE_FS_MODE_OUT) {
		uint32_t olen = MIN(len, bf->len);

		memcpy(data, (void *)(bf + 1), olen);
	}

	res = 0;

exit:
	thread_rpc_free_payload(cpayload);
	return res;
}
