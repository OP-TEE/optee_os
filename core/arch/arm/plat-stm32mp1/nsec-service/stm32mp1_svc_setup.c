// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2017-2018, STMicroelectronics
 */

#include <arm.h>
#include <sm/optee_smc.h>
#include <sm/sm.h>
#include <string.h>
#include <stm32_util.h>

#include "bsec_svc.h"
#include "stm32mp1_smc.h"

#define SM_NSEC_CTX_OFFSET(_reg)	(offsetof(struct sm_nsec_ctx, _reg) - \
					 offsetof(struct sm_nsec_ctx, r0))
#define SMC_ARGS_OFFSET(_reg)		offsetof(struct smc_args, _reg)

static enum sm_handler_ret sip_service(struct sm_ctx *ctx __unused,
				       struct smc_args *args)
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
	case STM32_SIP_SVC_FUNC_BSEC:
		args->a0 = bsec_main(args->a1, args->a2, args->a3, &args->a1);
		break;
	default:
		return SM_HANDLER_PENDING_SMC;
	}

	return SM_HANDLER_SMC_HANDLED;
}

/* Override default sm_platform_handler() with paltform specific function */
enum sm_handler_ret sm_platform_handler(struct sm_ctx *ctx)
{
	struct smc_args *args = (void *)&ctx->nsec.r0;

	COMPILE_TIME_ASSERT(SM_NSEC_CTX_OFFSET(r0) == SMC_ARGS_OFFSET(a0) &&
			    SM_NSEC_CTX_OFFSET(r1) == SMC_ARGS_OFFSET(a1) &&
			    SM_NSEC_CTX_OFFSET(r2) == SMC_ARGS_OFFSET(a2) &&
			    SM_NSEC_CTX_OFFSET(r3) == SMC_ARGS_OFFSET(a3) &&
			    SM_NSEC_CTX_OFFSET(r4) == SMC_ARGS_OFFSET(a4) &&
			    SM_NSEC_CTX_OFFSET(r5) == SMC_ARGS_OFFSET(a5) &&
			    SM_NSEC_CTX_OFFSET(r6) == SMC_ARGS_OFFSET(a6) &&
			    SM_NSEC_CTX_OFFSET(r7) == SMC_ARGS_OFFSET(a7));

	if (!OPTEE_SMC_IS_FAST_CALL(args->a0))
		return SM_HANDLER_PENDING_SMC;

	switch (OPTEE_SMC_OWNER_NUM(args->a0)) {
	case OPTEE_SMC_OWNER_SIP:
		return sip_service(ctx, args);
	default:
		return SM_HANDLER_PENDING_SMC;
	}
}
