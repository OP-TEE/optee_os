/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2023 Andes Technology Corporation
 */
#ifndef RISCV_USER_SYSREG_H
#define RISCV_USER_SYSREG_H

#include <stdint.h>

#define read_csr(csr)							\
	({								\
		register unsigned long v;				\
		asm volatile ("csrr %0, " #csr : "=r"(v) : : "memory");	\
		v;							\
	})

static inline __noprof uint64_t read_time(void)
{
	uint64_t time = 0;
	uint32_t hi __maybe_unused = 0;
	uint32_t lo __maybe_unused = 0;

#ifdef RV32
	do {
		hi = read_csr(timeh);
		lo = read_csr(time);
	} while (hi != read_csr(timeh));

	time = SHIFT_U64(hi, 32) | lo;
#else /*RV64*/
	time = read_csr(time);
#endif /*RV32*/

	return time;
}

/* These barriers need to enforce ordering on both devices and memory. */
static inline __noprof void mb(void)
{
	asm volatile ("fence" : : : "memory");
}

static inline __noprof uint64_t barrier_read_counter_timer(void)
{
	mb();	/* Get timer value after pending operations have completed */
	return read_time();
}

static inline __noprof uint32_t read_cntfrq(void)
{
	return CFG_RISCV_MTIME_RATE;
}

#endif /* RISCV_USER_SYSREG_H */
