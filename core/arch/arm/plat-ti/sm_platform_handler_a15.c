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
#include <sm/sm.h>
#include "api_monitor_index_a15.h"

enum sm_handler_ret sm_platform_handler(struct sm_ctx *ctx)
{
	if (ctx->nsec.r12 == 0x200)
		return SM_HANDLER_PENDING_SMC;

	switch (ctx->nsec.r12) {
	case API_MONITOR_ACTLR_SETREGISTER_INDEX:
		write_actlr(ctx->nsec.r0);
		isb();
		ctx->nsec.r0 = API_HAL_RET_VALUE_OK;
		break;
	case API_MONITOR_TIMER_SETCNTFRQ_INDEX:
		write_cntfrq(ctx->nsec.r0);
		isb();
		ctx->nsec.r0 = API_HAL_RET_VALUE_OK;
		break;
	default:
		ctx->nsec.r0 = API_HAL_RET_VALUE_SERVICE_UNKNWON;
		break;
	}

	return SM_HANDLER_SMC_HANDLED;
}
