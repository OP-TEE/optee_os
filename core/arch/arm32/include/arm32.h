/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
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

#ifndef ARM32_H
#define ARM32_H

#ifndef ASM
#include <stdint.h>
#endif

#define CPSR_MODE_MASK	0x1f
#define CPSR_MODE_USR	0x10
#define CPSR_MODE_FIQ	0x11
#define CPSR_MODE_IRQ	0x12
#define CPSR_MODE_SVC	0x13
#define CPSR_MODE_MON	0x16
#define CPSR_MODE_ABT	0x17
#define CPSR_MODE_UND	0x1b
#define CPSR_MODE_SYS	0x1f

#define CPSR_T		(1 << 5)
#define CPSR_F		(1 << 6)
#define CPSR_I		(1 << 7)
#define CPSR_A		(1 << 8)

#define MPIDR_CPU_MASK		0xff
#define MPIDR_CLUSTER_MASK	(0xff << 8)

#define SCR_NS		(1 << 0)
#define SCR_IRQ		(1 << 1)
#define SCR_FIQ		(1 << 2)
#define SCR_EA		(1 << 3)
#define SCR_FW		(1 << 4)
#define SCR_AW		(1 << 5)
#define SCR_NET		(1 << 6)
#define SCR_SCD		(1 << 7)
#define SCR_HCE		(1 << 8)
#define SCR_SIF		(1 << 9)

#define SCTLR_M		(1 << 0)
#define SCTLR_A		(1 << 1)
#define SCTLR_C		(1 << 2)
#define SCTLR_CP15BEN	(1 << 5)
#define SCTLR_SW	(1 << 10)
#define SCTLR_Z		(1 << 11)
#define SCTLR_I		(1 << 12)
#define SCTLR_V		(1 << 13)
#define SCTLR_RR	(1 << 14)
#define SCTLR_HA	(1 << 17)
#define SCTLR_WXN	(1 << 19)
#define SCTLR_UWXN	(1 << 20)
#define SCTLR_FI	(1 << 21)
#define SCTLR_VE	(1 << 24)
#define SCTLR_EE	(1 << 25)
#define SCTLR_NMFI	(1 << 26)
#define SCTLR_TRE	(1 << 28)
#define SCTLR_AFE	(1 << 29)
#define SCTLR_TE	(1 << 30)

#ifndef ASM
static inline uint32_t read_mpidr(void)
{
	uint32_t mpidr;

	asm ("mrc	p15, 0, %[mpidr], c0, c0, 5"
			: [mpidr] "=r" (mpidr)
	);

	return mpidr;
}

static inline uint32_t read_sctlr(void)
{
	uint32_t sctlr;

	asm ("mrc	p15, 0, %[sctlr], c1, c0, 0"
			: [sctlr] "=r" (sctlr)
	);

	return sctlr;
}

static inline void write_sctlr(uint32_t sctlr)
{
	asm ("mcr	p15, 0, %[sctlr], c1, c0, 0"
			: : [sctlr] "r" (sctlr)
	);
}

static inline void write_ttbr0(uint32_t ttbr0)
{
	asm ("mcr	p15, 0, %[ttbr0], c2, c0, 0"
			: : [ttbr0] "r" (ttbr0)
	);
}

static inline void write_dacr(uint32_t dacr)
{
	asm ("mcr	p15, 0, %[dacr], c3, c0, 0"
			: : [dacr] "r" (dacr)
	);
}

static inline void isb(void)
{
	asm ("isb");
}

static inline void dsb(void)
{
	asm ("dsb");
}

static inline void write_tlbiallis(void)
{
	/* Invalidate entire unified TLB Inner Shareable, r0 ignored */
	asm ("mcr	p15, 0, r0, c8, c3, 0");
}

static inline uint32_t read_cpsr(void)
{
	uint32_t cpsr;

	asm ("mrs	%[cpsr], cpsr"
			: [cpsr] "=r" (cpsr)
	);
	return cpsr;
}

static inline void write_cpsr(uint32_t cpsr)
{
	asm ("msr	cpsr, %[cpsr]"
			: : [cpsr] "r" (cpsr)
	);
}
#endif

#endif /*ARM32_H*/
