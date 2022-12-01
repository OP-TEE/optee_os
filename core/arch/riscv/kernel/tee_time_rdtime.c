// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022 NXP
 */

#include <kernel/clint.h>
#include <kernel/tee_time.h>
#include <kernel/time_source.h>
#include <riscv.h>
#include <utee_defines.h>

static TEE_Result riscv_get_sys_time(TEE_Time *time)
{
	uint64_t _time;

	_time = read_time();

	time->seconds = _time / RISCV_MTIME_RATE ;
	time->millis = (_time % RISCV_MTIME_RATE ) / (RISCV_MTIME_RATE  / TEE_TIME_MILLIS_BASE);

	return TEE_SUCCESS;
}

static const struct time_source riscv_time_source_rdtime = {
	.name = "risc-v rdtime",
	.protection_level = 1000,
	.get_sys_time = riscv_get_sys_time,
};

REGISTER_TIME_SOURCE(riscv_time_source_rdtime)
