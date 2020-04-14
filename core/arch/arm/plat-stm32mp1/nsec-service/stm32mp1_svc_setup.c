// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2017-2018, STMicroelectronics
 */

#include <kernel/thread.h>
#include <drivers/scmi-msg.h>
#include <sm/optee_smc.h>
#include <sm/sm.h>

#include "stm32mp1_smc.h"

static enum sm_handler_ret sip_service(struct sm_ctx *ctx __unused,
				       struct thread_smc_args *args)
{
	switch (OPTEE_SMC_FUNC_NUM(args->a0)) {
	case STM32_SIP_SVC_FUNC_CALL_COUNT:
		args->a0 = STM32_SIP_SVC_FUNCTION_COUNT;
		break;
	case STM32_SIP_SVC_FUNC_VERSION:
		args->a0 = STM32_SIP_SVC_VERSION_MAJOR;
		args->a1 = STM32_SIP_SVC_VERSION_MINOR;
		break;
	case STM32_SIP_SVC_FUNC_UID:
		args->a0 = STM32_SIP_SVC_UID_0;
		args->a1 = STM32_SIP_SVC_UID_1;
		args->a2 = STM32_SIP_SVC_UID_2;
		args->a3 = STM32_SIP_SVC_UID_3;
		break;
	case STM32_SIP_SVC_FUNC_SCMI_AGENT0:
		scmi_smt_fastcall_smc_entry(0);
		break;
	case STM32_SIP_SVC_FUNC_SCMI_AGENT1:
		scmi_smt_fastcall_smc_entry(1);
		break;
	default:
		return SM_HANDLER_PENDING_SMC;
	}

	return SM_HANDLER_SMC_HANDLED;
}

enum sm_handler_ret sm_platform_handler(struct sm_ctx *ctx)
{
	struct thread_smc_args *args = (void *)&ctx->nsec.r0;

	if (!OPTEE_SMC_IS_FAST_CALL(args->a0))
		return SM_HANDLER_PENDING_SMC;

	switch (OPTEE_SMC_OWNER_NUM(args->a0)) {
	case OPTEE_SMC_OWNER_SIP:
		return sip_service(ctx, args);
	default:
		return SM_HANDLER_PENDING_SMC;
	}
}
