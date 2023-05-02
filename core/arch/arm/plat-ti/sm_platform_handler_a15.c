// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2017 Texas Instruments Incorporated - http://www.ti.com/
 *	Andrew Davis <afd@ti.com>
 */

#include <arm32.h>
#include <io.h>
#include <kernel/thread.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <sm/optee_smc.h>
#include <sm/sm.h>
#include <trace.h>

#include "api_monitor_index_a15.h"

#define WUGEN_MPU_AMBA_IF_MODE 0x80c

register_phys_mem_pgdir(MEM_AREA_IO_SEC, WUGEN_MPU_BASE, WUGEN_MPU_SIZE);

static vaddr_t wugen_mpu_base(void)
{
	static void *va;

	if (cpu_mmu_enabled()) {
		if (!va)
			va = phys_to_virt(WUGEN_MPU_BASE, MEM_AREA_IO_SEC,
					  WUGEN_MPU_SIZE);
		return (vaddr_t)va;
	}

	return WUGEN_MPU_BASE;
}

static void write_wugen_mpu_amba_if_mode(uint32_t val)
{
	io_write32(wugen_mpu_base() + WUGEN_MPU_AMBA_IF_MODE, val);
}

static enum sm_handler_ret ti_sip_handler(struct thread_smc_args *smc_args)
{
	uint16_t sip_func = OPTEE_SMC_FUNC_NUM(smc_args->a0);

	switch (sip_func) {
	case API_MONITOR_ACTLR_SETREGISTER_INDEX:
		write_actlr(smc_args->a1);
		isb();
		smc_args->a0 = OPTEE_SMC_RETURN_OK;
		break;
	case API_MONITOR_TIMER_SETCNTFRQ_INDEX:
		write_cntfrq(smc_args->a1);
		isb();
		smc_args->a0 = OPTEE_SMC_RETURN_OK;
		break;
	case API_MONITOR_WUGEN_MPU_SETAMBAIF_INDEX:
		write_wugen_mpu_amba_if_mode(smc_args->a1);
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
