// SPDX-License-Identifier: BSD-2-Clause
/*
 * Texas Instruments System Control Interface Driver
 *
 * Copyright (C) 2023 Texas Instruments Incorporated - https://www.ti.com/
 *	Manorit Chawdhry <m-chawdhry@ti.com>
 */

#include <drivers/ti_sci.h>
#include <inttypes.h>
#include <k3/otp_keywriting_ta.h>
#include <kernel/pseudo_ta.h>

static TEE_Result write_otp_row(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result ret = TEE_SUCCESS;
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
				TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);

	/*
	 * Safely get the invocation parameters
	 */
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	ret = ti_sci_write_otp_row(params[0].value.a, params[1].value.a,
				   params[1].value.b);
	if (ret)
		return ret;

	DMSG("Written the value: 0x%08"PRIx32, params[1].value.a);

	return TEE_SUCCESS;
}

static TEE_Result read_otp_mmr(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result ret = TEE_SUCCESS;
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
				TEE_PARAM_TYPE_VALUE_OUTPUT,
				TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

	/*
	 * Safely get the invocation parameters
	 */
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	ret = ti_sci_read_otp_mmr(params[0].value.a, &params[1].value.a);
	if (ret)
		return ret;

	DMSG("Got the value: 0x%08"PRIx32, params[1].value.a);

	return TEE_SUCCESS;
}

static TEE_Result lock_otp_row(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result ret = TEE_SUCCESS;
	int hw_write_lock = 0;
	int hw_read_lock = 0;
	int soft_lock = 0;
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

	/*
	 * Safely get the invocation parameters
	 */
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	if (params[0].value.b & K3_OTP_KEYWRITING_SOFT_LOCK)
		soft_lock = 0x5A;
	if (params[0].value.b & K3_OTP_KEYWRITING_HW_READ_LOCK)
		hw_read_lock = 0x5A;
	if (params[0].value.b & K3_OTP_KEYWRITING_HW_WRITE_LOCK)
		hw_write_lock = 0x5A;

	DMSG("hw_write_lock: 0x%#x", hw_write_lock);
	DMSG("hw_read_lock: 0x%#x", hw_read_lock);
	DMSG("soft_lock: 0x%#x", soft_lock);

	ret = ti_sci_lock_otp_row(params[0].value.a, hw_write_lock,
				  hw_read_lock, soft_lock);

	if (ret)
		return ret;

	DMSG("Locked the row: 0x%08"PRIx32, params[1].value.a);

	return TEE_SUCCESS;
}

static TEE_Result invoke_command(void *session __unused,
				 uint32_t command, uint32_t param_types,
				 TEE_Param params[4])
{
	switch (command) {
	case TA_OTP_KEYWRITING_CMD_READ_MMR:
		return read_otp_mmr(param_types, params);
	case TA_OTP_KEYWRITING_CMD_WRITE_ROW:
		return write_otp_row(param_types, params);
	case TA_OTP_KEYWRITING_CMD_LOCK_ROW:
		return lock_otp_row(param_types, params);
	default:
		EMSG("Command ID 0x%"PRIx32" is not supported", command);
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

pseudo_ta_register(.uuid = PTA_K3_OTP_KEYWRITING_UUID,
		   .name = PTA_K3_OTP_KEYWRITING_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .invoke_command_entry_point = invoke_command);
