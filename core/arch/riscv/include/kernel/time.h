/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2022-2023 NXP
 */

#ifndef __KERNEL_TIME_H
#define __KERNEL_TIME_H

#include <kernel/clint.h>
#include <riscv.h>

static inline __noprof uint64_t read_time(void)
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

	time =  SHIFT_U64(hi, 32) | lo;
#else /*RV64*/
	time = rdtime();
#endif /*RV32*/
#endif /*CFG_RISCV_S_MODE*/

	return time;
}

#endif /* __KERNEL_TIME_H */
