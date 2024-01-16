// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022-2023 NXP
 */

#include <kernel/clint.h>
#include <kernel/tee_time.h>
#include <kernel/time_source.h>
#include <riscv.h>
#include <utee_defines.h>

__noprof uint64_t read_time(void)
{
	uint64_t time = 0;
	uint32_t hi __maybe_unused = 0;
	uint32_t lo __maybe_unused = 0;

#ifdef CFG_RISCV_M_MODE
	time = clint_get_mtime();
#endif /*CFG_RISCV_M_MODE*/

#ifdef CFG_RISCV_S_MODE
#ifdef RV32
	do {
		hi = read_csr(timeh);
		lo = read_csr(time);
	} while (hi != read_csr(timeh));

	time = SHIFT_U64(hi, 32) | lo;
#else /*RV64*/
	time = rdtime();
#endif /*RV32*/
#endif /*CFG_RISCV_S_MODE*/

	return time;
}

static TEE_Result riscv_get_sys_time(TEE_Time *time)
{
	uint64_t tm = read_time();
	uint64_t rate = read_cntfrq();

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
