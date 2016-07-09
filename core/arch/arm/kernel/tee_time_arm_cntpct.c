/*
 * Copyright (c) 2014, 2015 Linaro Limited
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

#include <kernel/misc.h>
#include <kernel/tee_time.h>
#include <trace.h>
#include <kernel/time_source.h>
#include <mm/core_mmu.h>
#include <utee_defines.h>

#include <stdint.h>
#include <mpa.h>
#include <arm.h>

static TEE_Result arm_cntpct_get_sys_time(TEE_Time *time)
{
	uint64_t cntpct = read_cntpct();
	uint32_t cntfrq = read_cntfrq();

	time->seconds = cntpct / cntfrq;
	time->millis = (cntpct % cntfrq) / (cntfrq / TEE_TIME_MILLIS_BASE);

	return TEE_SUCCESS;
}

static const struct time_source arm_cntpct_time_source = {
	.name = "arm cntpct",
	.protection_level = 1000,
	.get_sys_time = arm_cntpct_get_sys_time,
};

REGISTER_TIME_SOURCE(arm_cntpct_time_source)
