// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017, Texas Instruments
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
 * SUBSTITUTE GOODS OR SERVICES// LOSS OF USE, DATA, OR PROFITS// OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <arm32.h>
#include <io.h>
#include <kernel/cache_helpers.h>
#include <kernel/tz_ssvce_def.h>
#include <kernel/tz_ssvce_pl310.h>
#include <platform_config.h>
#include <sm/pm.h>
#include <sm/sm.h>
#include <mm/core_memprot.h>
#include "api_monitor_index_a9.h"

uint32_t suspend_regs[16];

bool sm_platform_handler(struct sm_ctx *ctx)
{
	if (ctx->nsec.r12 == 0x200)
		return true;

	switch (ctx->nsec.r12) {
	case 0x0:
		switch (ctx->nsec.r0) {
		case SECURE_SVC_PM_LATE_SUSPEND:
			sm_pm_cpu_do_suspend(suspend_regs);
			cache_op_inner(DCACHE_AREA_CLEAN,
				       suspend_regs,
				       sizeof(suspend_regs));
			cache_op_outer(DCACHE_AREA_CLEAN,
				       virt_to_phys(suspend_regs),
				       sizeof(suspend_regs));
			ctx->nsec.r0 = API_HAL_RET_VALUE_OK;
			break;
		default:
			ctx->nsec.r0 = API_HAL_RET_VALUE_SERVICE_UNKNWON;
			break;
		}
		break;
	case API_MONITOR_L2CACHE_SETDEBUG_INDEX:
		io_write32(pl310_base() + PL310_DEBUG_CTRL, ctx->nsec.r0);
		ctx->nsec.r0 = API_HAL_RET_VALUE_OK;
		break;
	case API_MONITOR_L2CACHE_CLEANINVBYPA_INDEX:
		arm_cl2_cleaninvbypa(pl310_base(), ctx->nsec.r0,
				     ctx->nsec.r0 + ctx->nsec.r1);
		ctx->nsec.r0 = API_HAL_RET_VALUE_OK;
		break;
	case API_MONITOR_L2CACHE_SETCONTROL_INDEX:
		io_write32(pl310_base() + PL310_CTRL, ctx->nsec.r0);
		ctx->nsec.r0 = API_HAL_RET_VALUE_OK;
		break;
	case API_MONITOR_L2CACHE_SETAUXILIARYCONTROL_INDEX:
		io_write32(pl310_base() + PL310_AUX_CTRL, ctx->nsec.r0);
		ctx->nsec.r0 = API_HAL_RET_VALUE_OK;
		break;
	case API_MONITOR_L2CACHE_SETLATENCY_INDEX:
		io_write32(pl310_base() + PL310_TAG_RAM_CTRL, ctx->nsec.r0);
		io_write32(pl310_base() + PL310_DATA_RAM_CTRL, ctx->nsec.r1);
		ctx->nsec.r0 = API_HAL_RET_VALUE_OK;
		break;
	case API_MONITOR_L2CACHE_SETPREFETCHCONTROL_INDEX:
		io_write32(pl310_base() + PL310_PREFETCH_CTRL, ctx->nsec.r0);
		ctx->nsec.r0 = API_HAL_RET_VALUE_OK;
		break;
	default:
		ctx->nsec.r0 = API_HAL_RET_VALUE_SERVICE_UNKNWON;
		break;
	}

	return false;
}
