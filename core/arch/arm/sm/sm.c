// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016-2020, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */
#include <arm.h>
#include <compiler.h>
#include <config.h>
#include <drivers/wdt.h>
#include <kernel/misc.h>
#include <kernel/thread.h>
#include <platform_config.h>
#include <sm/optee_smc.h>
#include <sm/sm.h>
#include <sm/std_smc.h>
#include <string.h>
#include "sm_private.h"

enum sm_handler_ret __weak sm_platform_handler(struct sm_ctx *ctx __unused)
{
	return SM_HANDLER_PENDING_SMC;
}

static void smc_arch_handler(struct thread_smc_args *args)
{
	uint32_t smc_fid = args->a0;
	uint32_t feature_fid = args->a1;

	switch (smc_fid) {
	case ARM_SMCCC_VERSION:
		args->a0 = SMCCC_V_1_1;
		break;
	case ARM_SMCCC_ARCH_FEATURES:
		switch (feature_fid) {
		case ARM_SMCCC_VERSION:
		case ARM_SMCCC_ARCH_SOC_ID:
			args->a0 = ARM_SMCCC_RET_SUCCESS;
			break;
		default:
			args->a0 = ARM_SMCCC_RET_NOT_SUPPORTED;
			break;
		}
		break;
	case ARM_SMCCC_ARCH_SOC_ID:
		args->a0 = ARM_SMCCC_RET_NOT_SUPPORTED;
		break;
	case ARM_SMCCC_ARCH_WORKAROUND_1:
	case ARM_SMCCC_ARCH_WORKAROUND_2:
		args->a0 = ARM_SMCCC_RET_NOT_REQUIRED;
		break;
	default:
		args->a0 = OPTEE_SMC_RETURN_UNKNOWN_FUNCTION;
		break;
	}
}

uint32_t sm_from_nsec(struct sm_ctx *ctx)
{
	uint32_t *nsec_r0 = (uint32_t *)(&ctx->nsec.r0);
	struct thread_smc_args *args = (struct thread_smc_args *)nsec_r0;

	/*
	 * Check that struct sm_ctx has the different parts properly
	 * aligned since the stack pointer will be updated to point at
	 * different parts of this struct.
	 */
	COMPILE_TIME_ASSERT(!(offsetof(struct sm_ctx, sec.r0) % 8));
	COMPILE_TIME_ASSERT(!(offsetof(struct sm_ctx, nsec.r0) % 8));
	COMPILE_TIME_ASSERT(!(sizeof(struct sm_ctx) % 8));

	if (wdt_sm_handler(args) == SM_HANDLER_SMC_HANDLED)
		return SM_EXIT_TO_NON_SECURE;

	if (IS_ENABLED(CFG_SM_PLATFORM_HANDLER) &&
	    sm_platform_handler(ctx) == SM_HANDLER_SMC_HANDLED)
		return SM_EXIT_TO_NON_SECURE;

	switch (OPTEE_SMC_OWNER_NUM(args->a0)) {
	case OPTEE_SMC_OWNER_STANDARD:
		if (IS_ENABLED(CFG_PSCI_ARM32)) {
			smc_std_handler(args, &ctx->nsec);
			return SM_EXIT_TO_NON_SECURE;
		}
		break;
	case OPTEE_SMC_OWNER_ARCH:
		smc_arch_handler(args);
		return SM_EXIT_TO_NON_SECURE;
	default:
		break;
	}

	sm_save_unbanked_regs(&ctx->nsec.ub_regs);
	sm_restore_unbanked_regs(&ctx->sec.ub_regs);

	memcpy(&ctx->sec.r0, args, sizeof(*args));

	if (IS_ENABLED(CFG_CORE_WORKAROUND_ARM_NMFI)) {
		/* Make sure FIQ is masked when jumping to SMC entry. */
		ctx->sec.mon_spsr |= CPSR_F;
	}

	if (OPTEE_SMC_IS_FAST_CALL(ctx->sec.r0))
		ctx->sec.mon_lr = (uint32_t)vector_fast_smc_entry;
	else
		ctx->sec.mon_lr = (uint32_t)vector_std_smc_entry;

	return SM_EXIT_TO_SECURE;
}
