// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2017 Texas Instruments Incorporated - http://www.ti.com/
 *	Andrew Davis <afd@ti.com>
 */

#include <arm32.h>
#include <io.h>
#include <kernel/cache_helpers.h>
#include <kernel/thread.h>
#include <kernel/tz_ssvce_def.h>
#include <kernel/tz_ssvce_pl310.h>
#include <platform_config.h>
#include <sm/optee_smc.h>
#include <sm/pm.h>
#include <sm/sm.h>
#include <mm/core_memprot.h>
#include <trace.h>

#include "api_monitor_index_a9.h"

uint32_t suspend_regs[16];

static enum sm_handler_ret ti_sip_handler(struct thread_smc_args *smc_args)
{
	uint16_t sip_func = OPTEE_SMC_FUNC_NUM(smc_args->a0);

	switch (sip_func) {
	case SECURE_SVC_PM_LATE_SUSPEND:
		sm_pm_cpu_do_suspend(suspend_regs);
		cache_op_inner(DCACHE_AREA_CLEAN, suspend_regs,
			       sizeof(suspend_regs));
		cache_op_outer(DCACHE_AREA_CLEAN, virt_to_phys(suspend_regs),
			       sizeof(suspend_regs));
		smc_args->a0 = OPTEE_SMC_RETURN_OK;
		break;
	case API_MONITOR_L2CACHE_SETDEBUG_INDEX:
		io_write32(pl310_base() + PL310_DEBUG_CTRL, smc_args->a1);
		smc_args->a0 = OPTEE_SMC_RETURN_OK;
		break;
	case API_MONITOR_L2CACHE_CLEANINVBYPA_INDEX:
		arm_cl2_cleaninvbypa(pl310_base(), smc_args->a1,
				     smc_args->a1 + smc_args->a2);
		smc_args->a0 = OPTEE_SMC_RETURN_OK;
		break;
	case API_MONITOR_L2CACHE_SETCONTROL_INDEX:
		io_write32(pl310_base() + PL310_CTRL, smc_args->a1);
		smc_args->a0 = OPTEE_SMC_RETURN_OK;
		break;
	case API_MONITOR_L2CACHE_SETAUXILIARYCONTROL_INDEX:
		io_write32(pl310_base() + PL310_AUX_CTRL, smc_args->a1);
		smc_args->a0 = OPTEE_SMC_RETURN_OK;
		break;
	case API_MONITOR_L2CACHE_SETLATENCY_INDEX:
		io_write32(pl310_base() + PL310_TAG_RAM_CTRL, smc_args->a1);
		io_write32(pl310_base() + PL310_DATA_RAM_CTRL, smc_args->a2);
		smc_args->a0 = OPTEE_SMC_RETURN_OK;
		break;
	case API_MONITOR_L2CACHE_SETPREFETCHCONTROL_INDEX:
		io_write32(pl310_base() + PL310_PREFETCH_CTRL, smc_args->a1);
		smc_args->a0 = OPTEE_SMC_RETURN_OK;
		break;
	default:
		EMSG("Invalid SIP function code: 0x%04"PRIx16, sip_func);
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
		return ti_sip_handler((struct thread_smc_args *)nsec_r0);
	default:
		return SM_HANDLER_PENDING_SMC;
	}
}
