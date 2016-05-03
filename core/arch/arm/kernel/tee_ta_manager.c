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
#include <tee_api_types.h>
#include <kernel/tee_ta_manager.h>
#include <mm/tee_mmu_types.h>
#include <mm/core_memprot.h>

/**
 * tee_ta_verify_param() - check that the 4 "params" match security
 */
TEE_Result tee_ta_verify_param(struct tee_ta_session *sess,
			       struct tee_ta_param *param)
{
	tee_paddr_t p;
	size_t l;
	int n;

	for (n = 0; n < TEE_NUM_PARAMS; n++) {
		switch (TEE_PARAM_TYPE_GET(param->types, n)) {
		case TEE_PARAM_TYPE_MEMREF_OUTPUT:
		case TEE_PARAM_TYPE_MEMREF_INOUT:
		case TEE_PARAM_TYPE_MEMREF_INPUT:

			if (param->param_attr[n] & TEE_MATTR_VIRTUAL) {
				p = virt_to_phys(
					param->params[n].memref.buffer);
				if (!p)
					return TEE_ERROR_SECURITY;
			} else {
				p = (tee_paddr_t)param->params[n].memref.buffer;
			}
			l = param->params[n].memref.size;

			if (core_pbuf_is(CORE_MEM_NSEC_SHM, p, l))
				break;
			if ((sess->ctx->flags & TA_FLAG_UNSAFE_NW_PARAMS) &&
				core_pbuf_is(CORE_MEM_MULTPURPOSE, p, l))
				break;
			if ((sess->clnt_id.login == TEE_LOGIN_TRUSTED_APP) &&
				core_pbuf_is(CORE_MEM_TA_RAM, p, l))
				break;

			return TEE_ERROR_SECURITY;
		default:
			break;
		}
	}
	return TEE_SUCCESS;
}
