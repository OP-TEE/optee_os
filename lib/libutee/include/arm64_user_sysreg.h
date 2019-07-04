/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2019, Linaro Limited
 */
#ifndef ARM64_USER_SYSREG_H
#define ARM64_USER_SYSREG_H

#include <compiler.h>
#include <stdint.h>

/*
 * Templates for register read/write functions based on mrs/msr
 */

#define DEFINE_REG_READ_FUNC_(reg, type, asmreg)	\
static inline __noprof type read_##reg(void)		\
{							\
	type val;					\
							\
	asm volatile("mrs %0, " #asmreg : "=r" (val));	\
	return val;					\
}

#define DEFINE_REG_WRITE_FUNC_(reg, type, asmreg)		\
static inline __noprof void write_##reg(type val)		\
{								\
	asm volatile("msr " #asmreg ", %0" : : "r" (val));	\
}

/* ARM Generic timer functions */
DEFINE_REG_READ_FUNC_(cntfrq, uint32_t, cntfrq_el0)
DEFINE_REG_READ_FUNC_(cntpct, uint64_t, cntpct_el0)

#endif /*ARM64_USER_SYSREG_H*/
