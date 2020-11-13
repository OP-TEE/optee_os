// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2016-2020, STMicroelectronics
 */

#include <drivers/stm32_bsec.h>
#include <kernel/thread.h>
#include <tee_api_types.h>
#include <trace.h>

#include "bsec_svc.h"
#include "stm32mp1_smc.h"

void bsec_main(struct thread_smc_args *args)
{
	TEE_Result result = TEE_ERROR_GENERIC;
	uint32_t cmd = args->a1;
	uint32_t otp_id = args->a2;
	uint32_t in_value = args->a3;
	uint32_t *out_value = &args->a1;
	uint32_t tmp = 0;

	if (!stm32_bsec_nsec_can_access_otp(otp_id)) {
		args->a0 = STM32_SIP_SVC_INVALID_PARAMS;
		return;
	}

	switch (cmd) {
	case STM32_SIP_SVC_BSEC_READ_SHADOW:
		FMSG("read shadow @%#"PRIx32, otp_id);
		result = stm32_bsec_read_otp(out_value, otp_id);
		break;
	case STM32_SIP_SVC_BSEC_PROG_OTP:
		FMSG("program @%#"PRIx32, otp_id);
		result = stm32_bsec_program_otp(in_value, otp_id);
		break;
	case STM32_SIP_SVC_BSEC_WRITE_SHADOW:
		FMSG("write shadow @%#"PRIx32, otp_id);
		result = stm32_bsec_write_otp(in_value, otp_id);
		break;
	case STM32_SIP_SVC_BSEC_READ_OTP:
		FMSG("read @%#"PRIx32, otp_id);
		result = stm32_bsec_read_otp(&tmp, otp_id);
		if (!result)
			result = stm32_bsec_shadow_register(otp_id);
		if (!result)
			result = stm32_bsec_read_otp(out_value, otp_id);
		if (!result)
			result = stm32_bsec_write_otp(tmp, otp_id);
		break;
	case STM32_SIP_SVC_BSEC_WRLOCK_OTP:
		FMSG("permanent write lock @%#"PRIx32, otp_id);
		result = stm32_bsec_permanent_lock_otp(otp_id);
		break;
	default:
		DMSG("Invalid command %#"PRIx32, cmd);
		result = TEE_ERROR_BAD_PARAMETERS;
		break;
	}

	if (!result)
		args->a0 = STM32_SIP_SVC_OK;
	else if (result == TEE_ERROR_BAD_PARAMETERS)
		args->a0 = STM32_SIP_SVC_INVALID_PARAMS;
	else
		args->a0 = STM32_SIP_SVC_FAILED;
}
