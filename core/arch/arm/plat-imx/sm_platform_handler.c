/*
 * Copyright 2017 NXP
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <io.h>
#include <kernel/cache_helpers.h>
#include <kernel/tz_ssvce_pl310.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <sm/sm.h>
#include <sm/optee_smc.h>

#include "smc_sip.h"

#ifdef CFG_PL310
static void handle_sip_pl310(struct thread_smc_args *smc_args)
{
	smc_args->a0 = OPTEE_SMC_RETURN_OK;
	DMSG("SIP L2C310 val=%x addr=%x\n", smc_args->a1,
	     smc_args->a2);
	/*
	 * Disable L2 is only needed in low power case,
	 * the psci asm code will take care of disable.
	 * So we just flush data here.
	 */
	if (smc_args->a1 == 0 && smc_args->a2 == PL310_CTRL) {
		dcache_op_all(DCACHE_OP_CLEAN);
		arm_cl2_cleanbyway(pl310_base());
		return;
	}
	switch (smc_args->a2) {
	case PL310_CTRL:
	case PL310_PREFETCH_CTRL:
	case PL310_AUX_CTRL:
		write32(smc_args->a1, pl310_base() + smc_args->a2);
		break;
	default:
		smc_args->a0 = OPTEE_SMC_RETURN_EBADCMD;
		break;
	}
}
#endif

static bool imx_sip_handler (struct thread_smc_args *smc_args) {

	uint16_t sip_func = OPTEE_SMC_FUNC_NUM(smc_args->a0);

	switch (sip_func) {
#ifdef CFG_PL310
	case SIP_IMX_L2C310:
		handle_sip_pl310(smc_args);
		break;
#endif
	default:
		smc_args->a0 = OPTEE_SMC_RETURN_EBADCMD;
		break;
	} /* end of switch */

	return false;
}

/**
 * sm_platform_handler
 */
bool sm_platform_handler(struct sm_ctx *ctx)
{
	uint32_t *nsec_r0 = (uint32_t *)(&ctx->nsec.r0);
	uint16_t smc_owner = OPTEE_SMC_OWNER_NUM(*nsec_r0);

	switch (smc_owner) {
	case OPTEE_SMC_OWNER_SIP:
		return imx_sip_handler((struct thread_smc_args *)nsec_r0);
	default:
		return true;
	}
}
