// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021, Microchip
 */

#include <drivers/pm/sam/atmel_pm.h>
#include <console.h>
#include <io.h>
#include <kernel/tee_misc.h>
#include <mm/core_memprot.h>
#include <sam_sfr.h>
#include <sm/optee_smc.h>
#include <sm/sm.h>
#include <smc_ids.h>

static enum sm_handler_ret sam_sip_handler(struct thread_smc_args *args)
{
	switch (OPTEE_SMC_FUNC_NUM(args->a0)) {
	case SAMA5_SMC_SIP_SFR_SET_USB_SUSPEND:
		atmel_sfr_set_usb_suspend(args->a1);
		args->a0 = SAMA5_SMC_SIP_RETURN_SUCCESS;
		break;
	case SAMA5_SMC_SIP_SET_SUSPEND_MODE:
		return at91_pm_set_suspend_mode(args);
	case SAMA5_SMC_SIP_GET_SUSPEND_MODE:
		return at91_pm_get_suspend_mode(args);
	default:
		return SM_HANDLER_PENDING_SMC;
	}

	return SM_HANDLER_SMC_HANDLED;
}

enum sm_handler_ret sm_platform_handler(struct sm_ctx *ctx)
{
	uint32_t *nsec_r0 = (uint32_t *)(&ctx->nsec.r0);
	uint16_t smc_owner = OPTEE_SMC_OWNER_NUM(*nsec_r0);

	switch (smc_owner) {
	case OPTEE_SMC_OWNER_SIP:
		return sam_sip_handler((struct thread_smc_args *)nsec_r0);
	default:
		return SM_HANDLER_PENDING_SMC;
	}
}

