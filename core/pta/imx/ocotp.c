// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2021 NXP
 */
#include <drivers/imx_ocotp.h>
#include <kernel/pseudo_ta.h>
#include <kernel/tee_common_otp.h>
#include <pta_imx_ocotp.h>

#define OCOTP_PTA_NAME "ocotp.pta"

static TEE_Result chip_uid(uint32_t param_types,
			   TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t val[IMX_UID_SIZE] = { };
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* On i.MX platforms, the chip UID is 64 bits long */
	if (params[0].memref.size != sizeof(uint64_t))
		return TEE_ERROR_BAD_PARAMETERS;

	if (tee_otp_get_die_id(val, IMX_UID_SIZE))
		return TEE_ERROR_GENERIC;

	memcpy(params[0].memref.buffer, val, IMX_UID_SIZE);

	return TEE_SUCCESS;
}

static TEE_Result read_fuse(uint32_t param_types,
			    TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	uint32_t val = 0;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_VALUE_OUTPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	params[1].value.a = 0;
	params[1].value.b = 0;

	ret = imx_ocotp_read(params[0].value.a, params[0].value.b, &val);
	if (!ret)
		params[1].value.a = val;

	return ret;
}

static TEE_Result invokeCommandEntryPoint(void *sess_ctx __unused,
					  uint32_t cmd_id, uint32_t param_types,
					  TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd_id) {
	case PTA_OCOTP_CMD_CHIP_UID:
		return chip_uid(param_types, params);
	case PTA_OCOTP_CMD_READ_FUSE:
		return read_fuse(param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}

pseudo_ta_register(.uuid = PTA_OCOTP_UUID, .name = OCOTP_PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .invoke_command_entry_point = invokeCommandEntryPoint);
