// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2017-2018, STMicroelectronics
 */

#include <arm.h>
#include <drivers/scmi-msg.h>
#include <sm/optee_smc.h>
#include <sm/sm.h>
#include <stm32_util.h>

#include "stm32mp1_smc.h"

static enum sm_handler_ret sip_service(struct sm_ctx *ctx)
{
	uint32_t func_id = ctx->nsec.r0;

	switch (OPTEE_SMC_FUNC_NUM(func_id)) {
	case STM32_SIP_SVC_FUNC_CALL_COUNT:
		ctx->nsec.r0 = STM32_SIP_SVC_FUNCTION_COUNT;
		break;
	case STM32_SIP_SVC_FUNC_VERSION:
		ctx->nsec.r0 = STM32_SIP_SVC_VERSION_MAJOR;
		ctx->nsec.r1 = STM32_SIP_SVC_VERSION_MINOR;
		break;
	case STM32_SIP_SVC_FUNC_UID:
		ctx->nsec.r0 = STM32_SIP_SVC_UID_0;
		ctx->nsec.r1 = STM32_SIP_SVC_UID_1;
		ctx->nsec.r2 = STM32_SIP_SVC_UID_2;
		ctx->nsec.r3 = STM32_SIP_SVC_UID_3;
		break;
	case STM32_SIP_SVC_FUNC_SCMI_AGENT0:
		scmi_smt_fastcall_smc_entry(0);
		ctx->nsec.r0 = STM32_SIP_SVC_OK;
		break;
	case STM32_SIP_SVC_FUNC_SCMI_AGENT1:
		scmi_smt_fastcall_smc_entry(1);
		ctx->nsec.r0 = STM32_SIP_SVC_OK;
		break;
	case STM32_SIP_SVC_FUNC_BSEC:
		ctx->nsec.r0 = STM32_SIP_SVC_UNKNOWN_FUNCTION;
		break;
	default:
		return SM_HANDLER_PENDING_SMC;
	}

	return SM_HANDLER_SMC_HANDLED;
}

enum sm_handler_ret sm_platform_handler(struct sm_ctx *ctx)
{
	if (!OPTEE_SMC_IS_FAST_CALL(ctx->nsec.r0))
		return SM_HANDLER_PENDING_SMC;

	switch (OPTEE_SMC_OWNER_NUM(ctx->nsec.r0)) {
	case OPTEE_SMC_OWNER_SIP:
		return sip_service(ctx);
	default:
		return SM_HANDLER_PENDING_SMC;
	}
}
