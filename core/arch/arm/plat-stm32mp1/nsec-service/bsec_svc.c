// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2016-2019, STMicroelectronics
 */

#include <drivers/stm32_bsec.h>
#include <tee_api_types.h>
#include <trace.h>

#include "bsec_svc.h"
#include "stm32mp1_smc.h"

uint32_t bsec_main(uint32_t cmd, uint32_t otp_id, uint32_t in_value,
		   uint32_t *out_value)
{
	TEE_Result result = TEE_ERROR_GENERIC;
	uint32_t tmp = 0;

	if (!stm32_bsec_nsec_can_access_otp(otp_id))
		return STM32_SIP_SVC_INVALID_PARAMS;

	switch (cmd) {
	case STM32_SIP_SVC_BSEC_READ_SHADOW:
		result = stm32_bsec_read_otp(out_value, otp_id);
		FMSG("read shadow @%" PRIx32 " = %" PRIx32, otp_id, *out_value);
		break;
	case STM32_SIP_SVC_BSEC_PROG_OTP:
		FMSG("program @%" PRIx32, otp_id);
		result = stm32_bsec_program_otp(in_value, otp_id);
		break;
	case STM32_SIP_SVC_BSEC_WRITE_SHADOW:
		FMSG("write shadow @%" PRIx32, otp_id);
		result = stm32_bsec_write_otp(in_value, otp_id);
		break;
	case STM32_SIP_SVC_BSEC_READ_OTP:
		result = stm32_bsec_read_otp(&tmp, otp_id);
		if (result != TEE_SUCCESS)
			break;

		result = stm32_bsec_shadow_register(otp_id);
		if (result != TEE_SUCCESS)
			break;

		result = stm32_bsec_read_otp(out_value, otp_id);
		if (result != TEE_SUCCESS)
			break;

		result = stm32_bsec_write_otp(tmp, otp_id);
		FMSG("read @%" PRIx32 " = %" PRIx32, otp_id, *out_value);
		break;
	default:
		EMSG("Invalid 0x%" PRIx32, cmd);
		result = TEE_ERROR_BAD_PARAMETERS;
		break;
	}

	switch (result) {
	case TEE_SUCCESS:
		return STM32_SIP_SVC_OK;
	case TEE_ERROR_BAD_PARAMETERS:
		return STM32_SIP_SVC_INVALID_PARAMS;
	default:
		return STM32_SIP_SVC_FAILED;
	}
}
