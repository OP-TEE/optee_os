// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 */

#include <kernel/thread.h>
#include <sm/optee_smc.h>
#include <sm/sm.h>
#include <trace.h>
#include "imx_pl310.h"

#define IMX_SIP_PL310_ENABLE			1
#define IMX_SIP_PL310_DISABLE			2
#define IMX_SIP_PL310_ENABLE_WRITEBACK		3
#define IMX_SIP_PL310_DISABLE_WRITEBACK		4
#define IMX_SIP_PL310_ENABLE_WFLZ		5

static enum sm_handler_ret imx_sip_handler(struct thread_smc_args *smc_args)
{
	uint16_t sip_func = OPTEE_SMC_FUNC_NUM(smc_args->a0);

	switch (sip_func) {
#ifdef CFG_PL310_SIP_PROTOCOL
	case IMX_SIP_PL310_ENABLE:
		smc_args->a0 = pl310_enable();
		break;
	case IMX_SIP_PL310_DISABLE:
		smc_args->a0 = pl310_disable();
		break;
	case IMX_SIP_PL310_ENABLE_WRITEBACK:
		smc_args->a0 = pl310_enable_writeback();
		break;
	case IMX_SIP_PL310_DISABLE_WRITEBACK:
		smc_args->a0 = pl310_disable_writeback();
		break;
	case IMX_SIP_PL310_ENABLE_WFLZ:
		smc_args->a0 = pl310_enable_wflz();
		break;
#endif
	default:
		EMSG("Invalid SIP function code: 0x%x", sip_func);
		smc_args->a0 = OPTEE_SMC_RETURN_EBADCMD;
		break;
	}

	return SM_HANDLER_SMC_HANDLED;
}

enum sm_handler_ret sm_platform_handler(struct sm_ctx *ctx)
{
	uint32_t *nsec_r0 = (uint32_t *)(&ctx->nsec.r0);
	uint16_t smc_owner = OPTEE_SMC_OWNER_NUM(*nsec_r0);

	switch (smc_owner) {
	case OPTEE_SMC_OWNER_SIP:
		return imx_sip_handler((struct thread_smc_args *)nsec_r0);
	default:
		return SM_HANDLER_PENDING_SMC;
	}
}
