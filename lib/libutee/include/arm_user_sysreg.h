/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2019, Linaro Limited
 */
#ifndef ARM_USER_SYSREG_H
#define ARM_USER_SYSREG_H

#include <util.h>

#ifdef ARM32
#include <arm32_user_sysreg.h>
#endif

#ifdef ARM64
#include <arm64_user_sysreg.h>
#endif

#ifndef __ASSEMBLER__
static inline __noprof void isb(void)
{
	asm volatile ("isb");
}

static inline __noprof uint64_t barrier_read_counter_timer(void)
{
	isb();
#ifdef CFG_CORE_SEL2_SPMC
	return read_cntvct();
#else
	return read_cntpct();
#endif
}
#endif

#endif /*ARM_USER_SYSREG_H*/
