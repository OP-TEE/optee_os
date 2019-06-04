// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */
#include <arm.h>
#include <compiler.h>
#include <kernel/misc.h>
#include <platform_config.h>
#include <sm/optee_smc.h>
#include <sm/sm.h>
#include <sm/std_smc.h>
#include <string.h>
#include "sm_private.h"

/*
 * Return false/0 if secure monitor shall retrun to non-secure and
 * true/1 if secure monitor shall enter OP-TEE core to proceed
 * invocation.
 */
bool sm_from_nsec(struct sm_ctx *ctx)
{
	uint32_t *nsec_r0 = (uint32_t *)(&ctx->nsec.r0);

	/*
	 * Check that struct sm_ctx has the different parts properly
	 * aligned since the stack pointer will be updated to point at
	 * different parts of this struct.
	 */
	COMPILE_TIME_ASSERT(!(offsetof(struct sm_ctx, sec.r0) % 8));
	COMPILE_TIME_ASSERT(!(offsetof(struct sm_ctx, nsec.r0) % 8));
	COMPILE_TIME_ASSERT(!(sizeof(struct sm_ctx) % 8));

#ifdef CFG_SM_PLATFORM_HANDLER
	if (sm_platform_handler(ctx) == SM_HANDLER_SMC_HANDLED)
		return false;
#endif

#ifdef CFG_PSCI_ARM32
	if (OPTEE_SMC_OWNER_NUM(*nsec_r0) == OPTEE_SMC_OWNER_STANDARD) {
		smc_std_handler((struct thread_smc_args *)nsec_r0, &ctx->nsec);
		return false;	/* Return to non secure state */
	}
#endif

	sm_save_unbanked_regs(&ctx->nsec.ub_regs);
	sm_restore_unbanked_regs(&ctx->sec.ub_regs);

	memcpy(&ctx->sec.r0, nsec_r0, sizeof(uint32_t) * 8);
	if (OPTEE_SMC_IS_FAST_CALL(ctx->sec.r0))
		ctx->sec.mon_lr = (uint32_t)&thread_vector_table.fast_smc_entry;
	else
		ctx->sec.mon_lr = (uint32_t)&thread_vector_table.std_smc_entry;
	return true;	/* return into secure state */
}
