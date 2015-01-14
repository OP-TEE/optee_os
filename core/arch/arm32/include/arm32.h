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
#define CPSR_FIA	(CPSR_F | CPSR_I | CPSR_A)
#define CPSR_IT_MASK	(CPSR_IT_MASK1 | CPSR_IT_MASK2)
#define CPSR_IT_MASK1	0x06000000
#define CPSR_IT_MASK2	0x0000fc00

#define MPIDR_CPU_MASK		0xff
#define MPIDR_CLUSTER_SHIFT	8
#define MPIDR_CLUSTER_MASK	(0xff << MPIDR_CLUSTER_SHIFT)

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

#define ACTLR_SMP	(1 << 6)
#define ACTLR_DODMBS	(1 << 10)
#define ACTLR_L2RADIS	(1 << 11)
#define ACTLR_L1RADIS	(1 << 12)
#define ACTLR_L1PCTL	(1 << 13)
#define ACTLR_DDVM	(1 << 15)
#define ACTLR_DDI	(1 << 28)

#define NSACR_CP10	(1 << 10)
#define NSACR_CP11	(1 << 11)
#define NSACR_NSD32DIS	(1 << 14)
#define NSACR_NSASEDIS	(1 << 15)
#define NSACR_NS_L2ERR	(1 << 17)
#define NSACR_NS_SMP	(1 << 18)

#define DACR_DOMAIN(num, perm)		((perm) << ((num) * 2))
#define DACR_DOMAIN_PERM_NO_ACCESS	0x0
#define DACR_DOMAIN_PERM_CLIENT		0x1
#define DACR_DOMAIN_PERM_MANAGER	0x3

#define TTBCR_PD0	(1 << 4)
#define TTBCR_PD1	(1 << 5)

#define NSACR_CP10	(1 << 10)
#define NSACR_CP11	(1 << 11)

#define CPACR_CP(co_proc, access)	((access) << ((co_proc) * 2))
#define CPACR_CP_ACCESS_DENIED		0x0
#define CPACR_CP_ACCESS_PL1_ONLY	0x1
#define CPACR_CP_ACCESS_FULL		0x2

#ifndef ASM
static inline uint32_t read_mpidr(void)
{
	uint32_t mpidr;

	asm volatile ("mrc	p15, 0, %[mpidr], c0, c0, 5"
			: [mpidr] "=r" (mpidr)
	);

	return mpidr;
}

static inline uint32_t read_sctlr(void)
{
	uint32_t sctlr;

	asm volatile ("mrc	p15, 0, %[sctlr], c1, c0, 0"
			: [sctlr] "=r" (sctlr)
	);

	return sctlr;
}

static inline void write_sctlr(uint32_t sctlr)
{
	asm volatile ("mcr	p15, 0, %[sctlr], c1, c0, 0"
			: : [sctlr] "r" (sctlr)
	);
}

static inline uint32_t read_cpacr(void)
{
	uint32_t cpacr;

	asm volatile ("mrc	p15, 0, %[cpacr], c1, c0, 2"
			: [cpacr] "=r" (cpacr)
	);

	return cpacr;
}

static inline void write_cpacr(uint32_t cpacr)
{
	asm volatile ("mcr	p15, 0, %[cpacr], c1, c0, 2"
			: : [cpacr] "r" (cpacr)
	);
}

static inline void write_ttbr0(uint32_t ttbr0)
{
	asm volatile ("mcr	p15, 0, %[ttbr0], c2, c0, 0"
			: : [ttbr0] "r" (ttbr0)
	);
}

static inline uint32_t read_ttbr0(void)
{
	uint32_t ttbr0;

	asm volatile ("mrc	p15, 0, %[ttbr0], c2, c0, 0"
			: [ttbr0] "=r" (ttbr0)
	);

	return ttbr0;
}

static inline void write_ats1cpw(uint32_t va)
{
	asm volatile ("mcr	p15, 0, %[va], c7, c8, 1"
			: : [va] "r" (va)
	);
}

static inline uint32_t read_par(void)
{
	uint32_t par;

	asm volatile ("mrc	p15, 0, %[par], c7, c4, 0"
			: [par] "=r" (par)
	);
	return par;
}

static inline void write_ttbr1(uint32_t ttbr1)
{
	asm volatile ("mcr	p15, 0, %[ttbr1], c2, c0, 1"
			: : [ttbr1] "r" (ttbr1)
	);
}

static inline uint32_t read_ttbr1(void)
{
	uint32_t ttbr1;

	asm volatile ("mrc	p15, 0, %[ttbr1], c2, c0, 1"
			: [ttbr1] "=r" (ttbr1)
	);

	return ttbr1;
}


static inline void write_ttbcr(uint32_t ttbcr)
{
	asm volatile ("mcr	p15, 0, %[ttbcr], c2, c0, 2"
			: : [ttbcr] "r" (ttbcr)
	);
}

static inline void write_dacr(uint32_t dacr)
{
	asm volatile ("mcr	p15, 0, %[dacr], c3, c0, 0"
			: : [dacr] "r" (dacr)
	);
}

static inline uint32_t read_ifar(void)
{
	uint32_t ifar;

	asm volatile ("mrc	p15, 0, %[ifar], c6, c0, 2"
			: [ifar] "=r" (ifar)
	);

	return ifar;
}

static inline uint32_t read_dfar(void)
{
	uint32_t dfar;

	asm volatile ("mrc	p15, 0, %[dfar], c6, c0, 0"
			: [dfar] "=r" (dfar)
	);

	return dfar;
}

static inline uint32_t read_dfsr(void)
{
	uint32_t dfsr;

	asm volatile ("mrc	p15, 0, %[dfsr], c5, c0, 0"
			: [dfsr] "=r" (dfsr)
	);

	return dfsr;
}

static inline uint32_t read_ifsr(void)
{
	uint32_t ifsr;

	asm volatile ("mrc	p15, 0, %[ifsr], c5, c0, 1"
			: [ifsr] "=r" (ifsr)
	);

	return ifsr;
}



static inline void isb(void)
{
	asm volatile ("isb");
}

static inline void dsb(void)
{
	asm volatile ("dsb");
}

static inline uint32_t read_contextidr(void)
{
	uint32_t contextidr;

	asm volatile ("mrc	p15, 0, %[contextidr], c13, c0, 1"
			: [contextidr] "=r" (contextidr)
	);

	return contextidr;
}

static inline void write_contextidr(uint32_t contextidr)
{
	asm volatile ("mcr	p15, 0, %[contextidr], c13, c0, 1"
			: : [contextidr] "r" (contextidr)
	);
}

static inline uint32_t read_cpsr(void)
{
	uint32_t cpsr;

	asm volatile ("mrs	%[cpsr], cpsr"
			: [cpsr] "=r" (cpsr)
	);
	return cpsr;
}

static inline void write_cpsr(uint32_t cpsr)
{
	asm volatile ("msr	cpsr_fsxc, %[cpsr]"
			: : [cpsr] "r" (cpsr)
	);
}

static inline uint32_t read_spsr(void)
{
	uint32_t spsr;

	asm volatile ("mrs	%[spsr], spsr"
			: [spsr] "=r" (spsr)
	);
	return spsr;
}

static inline uint32_t read_actlr(void)
{
	uint32_t actlr;

	asm volatile ("mrc	p15, 0, %[actlr], c1, c0, 1"
			: [actlr] "=r" (actlr)
	);

	return actlr;
}

static inline void write_actlr(uint32_t actlr)
{
	asm volatile ("mcr	p15, 0, %[actlr], c1, c0, 1"
			: : [actlr] "r" (actlr)
	);
}

static inline uint32_t read_nsacr(void)
{
	uint32_t nsacr;

	asm volatile ("mrc	p15, 0, %[nsacr], c1, c1, 2"
			: [nsacr] "=r" (nsacr)
	);

	return nsacr;
}

static inline void write_nsacr(uint32_t nsacr)
{
	asm volatile ("mcr	p15, 0, %[nsacr], c1, c1, 2"
			: : [nsacr] "r" (nsacr)
	);
}

#endif /*ASM*/

#endif /*ARM32_H*/
