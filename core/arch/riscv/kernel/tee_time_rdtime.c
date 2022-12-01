// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022-2023 NXP
 */

#include <kernel/clint.h>
#include <kernel/tee_time.h>
#include <kernel/time.h>
#include <kernel/time_source.h>
#include <utee_defines.h>

static TEE_Result riscv_get_sys_time(TEE_Time *time)
{
	uint64_t tm = read_time();
	uint64_t rate = CFG_RISCV_MTIME_RATE;

	time->seconds = tm / rate;
	time->millis = (tm % rate) / (rate / TEE_TIME_MILLIS_BASE);

	return TEE_SUCCESS;
}

static const struct time_source riscv_time_source_rdtime = {
	.name = "risc-v rdtime",
	.protection_level = 1000,
	.get_sys_time = riscv_get_sys_time,
};

REGISTER_TIME_SOURCE(riscv_time_source_rdtime)
