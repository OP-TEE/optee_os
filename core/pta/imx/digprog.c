// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2021 NXP
 */
#include <imx.h>
#include <kernel/pseudo_ta.h>
#include <pta_imx_digprog.h>

#define DIGPROG_PTA_NAME "digprog.pta"

static TEE_Result invokeCommandEntryPoint(void *sess_ctx __unused,
					  uint32_t cmd_id __unused,
					  uint32_t param_types,
					  TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	params[0].value.a = imx_get_digprog();
	params[0].value.b = 0;

	return TEE_SUCCESS;
}

pseudo_ta_register(.uuid = PTA_DIGPROG_UUID, .name = DIGPROG_PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .invoke_command_entry_point = invokeCommandEntryPoint);
