// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
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

bool sm_from_nsec(struct sm_ctx *ctx)
{
	uint32_t *nsec_r0 = (uint32_t *)(&ctx->nsec.r0);

	if (!sm_platform_handler(ctx))
		return false;

#ifdef CFG_PSCI_ARM32
	if (OPTEE_SMC_OWNER_NUM(*nsec_r0) == OPTEE_SMC_OWNER_STANDARD) {
		smc_std_handler((struct thread_smc_args *)nsec_r0, &ctx->nsec);
		return false;	/* Return to non secure state */
	}
#endif

	sm_save_modes_regs(&ctx->nsec.mode_regs);
	sm_restore_modes_regs(&ctx->sec.mode_regs);

	memcpy(&ctx->sec.r0, nsec_r0, sizeof(uint32_t) * 8);
	if (OPTEE_SMC_IS_FAST_CALL(ctx->sec.r0))
		ctx->sec.mon_lr = (uint32_t)&thread_vector_table.fast_smc_entry;
	else
		ctx->sec.mon_lr = (uint32_t)&thread_vector_table.std_smc_entry;
	return true;	/* return into secure state */
}
