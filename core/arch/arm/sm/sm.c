/*
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
#include <compiler.h>
#include <platform_config.h>

#include <sm/sm.h>
#include <sm/optee_smc.h>
#include <sm/teesmc_opteed_macros.h>
#include <sm/teesmc_opteed.h>

#include <arm.h>

#include <kernel/misc.h>

#include "sm_private.h"

static struct sm_nsec_ctx sm_nsec_ctx[CFG_TEE_CORE_NB_CORE];
static struct sm_sec_ctx sm_sec_ctx[CFG_TEE_CORE_NB_CORE];

/*
 * Has to match layout of thread_vector_table. Some of the entries are
 * never used.
 *
 * We're using this layout to be able to used the same vector when this
 * secure monitor is used and when the secure monitor in ARM Trusted
 * Firmware is used.
 */
static struct {
	uint32_t std_smc_entry;
	uint32_t fast_smc_entry;
	uint32_t cpu_on_entry;
	uint32_t cpu_off_entry;
	uint32_t cpu_resume_entry;
	uint32_t cpu_suspend_entry;
	uint32_t fiq_entry;
	uint32_t system_off_entry;
	uint32_t system_reset_entry;
} *sm_entry_vector;

struct sm_nsec_ctx *sm_get_nsec_ctx(void)
{
	return &sm_nsec_ctx[get_core_pos()];
}

struct sm_sec_ctx *sm_get_sec_ctx(void)
{
	return &sm_sec_ctx[get_core_pos()];
}

void sm_set_sec_smc_entry(const struct sm_reg_r0_to_r3 *regs)
{
	struct sm_sec_ctx *sec_ctx = sm_get_sec_ctx();

	if (OPTEE_SMC_IS_FAST_CALL(regs->r0))
		sec_ctx->mon_lr = (uint32_t)&sm_entry_vector->fast_smc_entry;
	else
		sec_ctx->mon_lr = (uint32_t)&sm_entry_vector->std_smc_entry;
}

void sm_set_nsec_ret_vals(struct sm_reg_r0_to_r3 *regs, uint32_t r4)
{
	if (regs->r0 == TEESMC_OPTEED_RETURN_FIQ_DONE) {
		/* On FIQ exit we're restoring r0-r3 from nsec context */
		struct sm_nsec_ctx *nsec_ctx = sm_get_nsec_ctx();

		regs->r0 = nsec_ctx->r0;
		regs->r1 = nsec_ctx->r1;
		regs->r2 = nsec_ctx->r2;
		regs->r3 = nsec_ctx->r3;
	} else {
		/* On all other exits we're shifting r1-r4 into r0-r3 */
		regs->r0 = regs->r1;
		regs->r1 = regs->r2;
		regs->r2 = regs->r3;
		regs->r3 = r4;
	}
}

void sm_set_sec_fiq_entry(void)
{
	struct sm_sec_ctx *sec_ctx = sm_get_sec_ctx();

	sec_ctx->mon_lr = (uint32_t)&sm_entry_vector->fiq_entry;
}

void sm_set_entry_vector(void *entry_vector)
{
	sm_entry_vector = entry_vector;
}
