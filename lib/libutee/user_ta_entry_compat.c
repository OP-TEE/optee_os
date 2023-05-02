// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2022, Linaro Limited.
 */
#include <compiler.h>
#include <tee_internal_api.h>

static void to_gp11_param(uint32_t pt, const TEE_Param params[TEE_NUM_PARAMS],
			  __GP11_TEE_Param gp11_params[TEE_NUM_PARAMS])
{
	size_t n = 0;

	for (n = 0; n < TEE_NUM_PARAMS; n++) {
		switch (TEE_PARAM_TYPE_GET(pt, n)) {
		case TEE_PARAM_TYPE_VALUE_INPUT:
		case TEE_PARAM_TYPE_VALUE_OUTPUT:
		case TEE_PARAM_TYPE_VALUE_INOUT:
			gp11_params[n].value.a = params[n].value.a;
			gp11_params[n].value.b = params[n].value.b;
			break;
		case TEE_PARAM_TYPE_MEMREF_INPUT:
		case TEE_PARAM_TYPE_MEMREF_OUTPUT:
		case TEE_PARAM_TYPE_MEMREF_INOUT:
			gp11_params[n].memref.buffer = params[n].memref.buffer;
			gp11_params[n].memref.size = params[n].memref.size;
			break;
		default:
			break;
		}
	}
}

static void from_gp11_param(uint32_t pt,
			    const __GP11_TEE_Param gp11_params[TEE_NUM_PARAMS],
			    TEE_Param params[TEE_NUM_PARAMS])
{
	size_t n = 0;

	for (n = 0; n < TEE_NUM_PARAMS; n++) {
		switch (TEE_PARAM_TYPE_GET(pt, n)) {
		case TEE_PARAM_TYPE_VALUE_INPUT:
		case TEE_PARAM_TYPE_VALUE_OUTPUT:
		case TEE_PARAM_TYPE_VALUE_INOUT:
			params[n].value.a = gp11_params[n].value.a;
			params[n].value.b = gp11_params[n].value.b;
			break;
		case TEE_PARAM_TYPE_MEMREF_INPUT:
		case TEE_PARAM_TYPE_MEMREF_OUTPUT:
		case TEE_PARAM_TYPE_MEMREF_INOUT:
			params[n].memref.buffer = gp11_params[n].memref.buffer;
			params[n].memref.size = gp11_params[n].memref.size;
			break;
		default:
			break;
		}
	}
}

/*
 * Legacy TAs will due to macros define __GP11_TA_OpenSessionEntryPoint()
 * instead so call that function instead.
 */

TEE_Result __ta_open_sess(uint32_t pt, TEE_Param params[TEE_NUM_PARAMS],
			  void **sess_ctx,
			  TEE_Result (*fp)(uint32_t,
					   __GP11_TEE_Param [TEE_NUM_PARAMS],
					   void **))
{
	__GP11_TEE_Param gp11_params[TEE_NUM_PARAMS] = { };
	TEE_Result res = TEE_SUCCESS;

	to_gp11_param(pt, params, gp11_params);
	res = fp(pt, gp11_params, sess_ctx);
	from_gp11_param(pt, gp11_params, params);

	return res;
}

/*
 * Legacy TAs will due to macros define __GP11_TA_InvokeCommandEntryPoint()
 * instead so call that function instead.
 */

TEE_Result __ta_invoke_cmd(void *sess_ctx, uint32_t cmd_id, uint32_t pt,
			   TEE_Param params[TEE_NUM_PARAMS],
			   TEE_Result (*fp)(void *, uint32_t, uint32_t,
					    __GP11_TEE_Param [TEE_NUM_PARAMS]))
{
	__GP11_TEE_Param gp11_params[TEE_NUM_PARAMS] = { };
	TEE_Result res = TEE_SUCCESS;

	to_gp11_param(pt, params, gp11_params);
	res = fp(sess_ctx, cmd_id, pt, gp11_params);
	from_gp11_param(pt, gp11_params, params);

	return res;
}
