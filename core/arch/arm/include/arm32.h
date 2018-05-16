/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#ifndef ARM32_H
#define ARM32_H

#include <sys/cdefs.h>
#include <stdint.h>
#include <util.h>

#define CPSR_MODE_MASK	ARM32_CPSR_MODE_MASK
#define CPSR_MODE_USR	ARM32_CPSR_MODE_USR
#define CPSR_MODE_FIQ	ARM32_CPSR_MODE_FIQ
#define CPSR_MODE_IRQ	ARM32_CPSR_MODE_IRQ
#define CPSR_MODE_SVC	ARM32_CPSR_MODE_SVC
#define CPSR_MODE_MON	ARM32_CPSR_MODE_MON
#define CPSR_MODE_ABT	ARM32_CPSR_MODE_ABT
#define CPSR_MODE_UND	ARM32_CPSR_MODE_UND
#define CPSR_MODE_SYS	ARM32_CPSR_MODE_SYS

#define CPSR_T		ARM32_CPSR_T
#define CPSR_F_SHIFT	ARM32_CPSR_F_SHIFT
#define CPSR_F		ARM32_CPSR_F
#define CPSR_I		ARM32_CPSR_I
#define CPSR_A		ARM32_CPSR_A
#define CPSR_FIA	ARM32_CPSR_FIA
#define CPSR_IT_MASK	ARM32_CPSR_IT_MASK
#define CPSR_IT_MASK1	ARM32_CPSR_IT_MASK1
#define CPSR_IT_MASK2	ARM32_CPSR_IT_MASK2

#define SCR_NS		BIT32(0)
#define SCR_IRQ		BIT32(1)
#define SCR_FIQ		BIT32(2)
#define SCR_EA		BIT32(3)
#define SCR_FW		BIT32(4)
#define SCR_AW		BIT32(5)
#define SCR_NET		BIT32(6)
#define SCR_SCD		BIT32(7)
#define SCR_HCE		BIT32(8)
#define SCR_SIF		BIT32(9)

#define SCTLR_M		BIT32(0)
#define SCTLR_A		BIT32(1)
#define SCTLR_C		BIT32(2)
#define SCTLR_CP15BEN	BIT32(5)
#define SCTLR_SW	BIT32(10)
#define SCTLR_Z		BIT32(11)
#define SCTLR_I		BIT32(12)
#define SCTLR_V		BIT32(13)
#define SCTLR_RR	BIT32(14)
#define SCTLR_HA	BIT32(17)
#define SCTLR_WXN	BIT32(19)
#define SCTLR_UWXN	BIT32(20)
#define SCTLR_FI	BIT32(21)
#define SCTLR_VE	BIT32(24)
#define SCTLR_EE	BIT32(25)
#define SCTLR_NMFI	BIT32(26)
#define SCTLR_TRE	BIT32(28)
#define SCTLR_AFE	BIT32(29)
#define SCTLR_TE	BIT32(30)

/* Only valid for Cortex-A15 */
#define ACTLR_CA15_ENABLE_INVALIDATE_BTB	BIT(0)
/* Only valid for Cortex-A8 */
#define ACTLR_CA8_ENABLE_INVALIDATE_BTB		BIT(6)
/* Only valid for Cortex-A9 */
#define ACTLR_CA9_WFLZ				BIT(3)

#define ACTLR_SMP	BIT32(6)

#define NSACR_CP10	BIT32(10)
#define NSACR_CP11	BIT32(11)
#define NSACR_NSD32DIS	BIT32(14)
#define NSACR_NSASEDIS	BIT32(15)
#define NSACR_NS_L2ERR	BIT32(17)
#define NSACR_NS_SMP	BIT32(18)

#define CPACR_ASEDIS	BIT32(31)
#define CPACR_D32DIS	BIT32(30)
#define CPACR_CP(co_proc, access)	SHIFT_U32((access), ((co_proc) * 2))
#define CPACR_CP_ACCESS_DENIED		0x0
#define CPACR_CP_ACCESS_PL1_ONLY	0x1
#define CPACR_CP_ACCESS_FULL		0x3


#define DACR_DOMAIN(num, perm)		SHIFT_U32((perm), ((num) * 2))
#define DACR_DOMAIN_PERM_NO_ACCESS	0x0
#define DACR_DOMAIN_PERM_CLIENT		0x1
#define DACR_DOMAIN_PERM_MANAGER	0x3

#define PAR_F			BIT32(0)
#define PAR_SS			BIT32(1)
#define PAR_LPAE		BIT32(11)
#define PAR_PA_SHIFT		12
#define PAR32_PA_MASK		(BIT32(20) - 1)
#define PAR64_PA_MASK		(BIT64(28) - 1)

/*
 * TTBCR has different register layout if LPAE is enabled or not.
 * TTBCR.EAE == 0 => LPAE is not enabled
 * TTBCR.EAE == 1 => LPAE is enabled
 */
#define TTBCR_EAE	BIT32(31)

/* When TTBCR.EAE == 0 */
#define TTBCR_PD0	BIT32(4)
#define TTBCR_PD1	BIT32(5)

/* When TTBCR.EAE == 1 */
#define TTBCR_T0SZ_SHIFT	0
#define TTBCR_EPD0		BIT32(7)
#define TTBCR_IRGN0_SHIFT	8
#define TTBCR_ORGN0_SHIFT	10
#define TTBCR_SH0_SHIFT		12
#define TTBCR_T1SZ_SHIFT	16
#define TTBCR_A1		BIT32(22)
#define TTBCR_EPD1		BIT32(23)
#define TTBCR_IRGN1_SHIFT	24
#define TTBCR_ORGN1_SHIFT	26
#define TTBCR_SH1_SHIFT		28

/* Normal memory, Inner/Outer Non-cacheable */
#define TTBCR_XRGNX_NC		0x0
/* Normal memory, Inner/Outer Write-Back Write-Allocate Cacheable */
#define TTBCR_XRGNX_WB		0x1
/* Normal memory, Inner/Outer Write-Through Cacheable */
#define TTBCR_XRGNX_WT		0x2
/* Normal memory, Inner/Outer Write-Back no Write-Allocate Cacheable */
#define TTBCR_XRGNX_WBWA	0x3

/* Non-shareable */
#define TTBCR_SHX_NSH		0x0
/* Outer Shareable */
#define TTBCR_SHX_OSH		0x2
/* Inner Shareable */
#define TTBCR_SHX_ISH		0x3

#define TTBR_ASID_MASK		0xff
#define TTBR_ASID_SHIFT		48


#define FSR_LPAE		BIT32(9)
#define FSR_WNR			BIT32(11)

/* Valid if FSR.LPAE is 1 */
#define FSR_STATUS_MASK		(BIT32(6) - 1)

/* Valid if FSR.LPAE is 0 */
#define FSR_FS_MASK		(BIT32(10) | (BIT32(4) - 1))

/* ID_PFR1 bit fields */
#define IDPFR1_VIRT_SHIFT            12
#define IDPFR1_VIRT_MASK             (0xF << IDPFR1_VIRT_SHIFT)
#define IDPFR1_GENTIMER_SHIFT        16
#define IDPFR1_GENTIMER_MASK         (0xF << IDPFR1_GENTIMER_SHIFT)

#ifndef ASM
static inline uint32_t read_midr(void)
{
	uint32_t midr;

	asm volatile ("mrc	p15, 0, %[midr], c0, c0, 0"
			: [midr] "=r" (midr)
	);

	return midr;
}

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

static inline void write_ttbr0_64bit(uint64_t ttbr0)
{
	asm volatile ("mcrr	p15, 0, %Q[ttbr0], %R[ttbr0], c2"
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

static inline uint64_t read_ttbr0_64bit(void)
{
	uint64_t ttbr0;

	asm volatile ("mrrc	p15, 0, %Q[ttbr0], %R[ttbr0], c2"
			: [ttbr0] "=r" (ttbr0)
	);

	return ttbr0;
}

static inline void write_ttbr1(uint32_t ttbr1)
{
	asm volatile ("mcr	p15, 0, %[ttbr1], c2, c0, 1"
			: : [ttbr1] "r" (ttbr1)
	);
}

static inline void write_ttbr1_64bit(uint64_t ttbr1)
{
	asm volatile ("mcrr	p15, 1, %Q[ttbr1], %R[ttbr1], c2"
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

static inline uint32_t read_ttbcr(void)
{
	uint32_t ttbcr;

	asm volatile ("mrc	p15, 0, %[ttbcr], c2, c0, 2"
			: [ttbcr] "=r" (ttbcr)
	);

	return ttbcr;
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

static inline void write_scr(uint32_t scr)
{
	asm volatile ("mcr	p15, 0, %[scr], c1, c1, 0"
			: : [scr] "r" (scr)
	);
}

static inline void isb(void)
{
	asm volatile ("isb");
}

static inline void dsb(void)
{
	asm volatile ("dsb");
}

static inline void dsb_ish(void)
{
	asm volatile ("dsb ish");
}

static inline void dsb_ishst(void)
{
	asm volatile ("dsb ishst");
}

static inline void dmb(void)
{
	asm volatile ("dmb");
}

static inline void sev(void)
{
	asm volatile ("sev");
}

static inline void wfe(void)
{
	asm volatile ("wfe");
}

/* Address translate privileged write translation (current state secure PL1) */
static inline void write_ats1cpw(uint32_t va)
{
	asm volatile ("mcr	p15, 0, %0, c7, c8, 1" : : "r" (va));
}

static inline void write_ats1cpr(uint32_t va)
{
	asm volatile ("mcr	p15, 0, %0, c7, c8, 0" : : "r" (va));
}

static inline void write_ats1cpuw(uint32_t va)
{
	asm volatile ("mcr	p15, 0, %0, c7, c8, 3" : : "r" (va));
}

static inline void write_ats1cpur(uint32_t va)
{
	asm volatile ("mcr	p15, 0, %0, c7, c8, 2" : : "r" (va));
}

static inline uint32_t read_par32(void)
{
	uint32_t val;

	asm volatile ("mrc	p15, 0, %0, c7, c4, 0" : "=r" (val));
	return val;
}

#ifdef CFG_WITH_LPAE
static inline uint64_t read_par64(void)
{
	uint64_t val;

	asm volatile ("mrrc	p15, 0, %Q0, %R0, c7" : "=r" (val));
	return val;
}
#endif

static inline void write_tlbimvaais(uint32_t mva)
{
	asm volatile ("mcr	p15, 0, %[mva], c8, c3, 3"
			: : [mva] "r" (mva)
	);
}

static inline void write_mair0(uint32_t mair0)
{
	asm volatile ("mcr	p15, 0, %[mair0], c10, c2, 0"
			: : [mair0] "r" (mair0)
	);
}

static inline void write_prrr(uint32_t prrr)
{
	/*
	 * Same physical register as MAIR0.
	 *
	 * When an implementation includes the Large Physical Address
	 * Extension, and address translation is using the Long-descriptor
	 * translation table formats, MAIR0 replaces the PRRR
	 */
	write_mair0(prrr);
}

static inline void write_mair1(uint32_t mair1)
{
	asm volatile ("mcr	p15, 0, %[mair1], c10, c2, 1"
			: : [mair1] "r" (mair1)
	);
}

static inline void write_nmrr(uint32_t nmrr)
{
	/*
	 * Same physical register as MAIR1.
	 *
	 * When an implementation includes the Large Physical Address
	 * Extension, and address translation is using the Long-descriptor
	 * translation table formats, MAIR1 replaces the NMRR
	 */
	write_mair1(nmrr);
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

static inline uint64_t read_cntpct(void)
{
	uint64_t val;

	asm volatile("mrrc p15, 0, %Q0, %R0, c14" : "=r" (val));
	return val;
}

static inline uint32_t read_cntfrq(void)
{
	uint32_t frq;

	asm volatile("mrc p15, 0, %0, c14, c0, 0" : "=r" (frq));
	return frq;
}

static inline void write_cntfrq(uint32_t frq)
{
	asm volatile("mcr p15, 0, %0, c14, c0, 0" : : "r" (frq));
}

static inline uint32_t read_cntkctl(void)
{
	uint32_t cntkctl;

	asm volatile("mrc p15, 0, %0, c14, c1, 0" : "=r" (cntkctl));
	return cntkctl;
}

static inline void write_cntkctl(uint32_t cntkctl)
{
	asm volatile("mcr p15, 0, %0, c14, c1, 0" : : "r" (cntkctl));
}

static __always_inline uint32_t read_pc(void)
{
	uint32_t val;

	asm volatile ("adr %0, ." : "=r" (val));
	return val;
}

static __always_inline uint32_t read_sp(void)
{
	uint32_t val;

	asm volatile ("mov %0, sp" : "=r" (val));
	return val;
}

static __always_inline uint32_t read_lr(void)
{
	uint32_t val;

	asm volatile ("mov %0, lr" : "=r" (val));
	return val;
}

static __always_inline uint32_t read_fp(void)
{
	uint32_t val;

	asm volatile ("mov %0, fp" : "=r" (val));
	return val;
}

static __always_inline uint32_t read_r7(void)
{
	uint32_t val;

	asm volatile ("mov %0, r7" : "=r" (val));
	return val;
}

/* Register read/write functions for GICC registers by using system interface */
static inline uint32_t read_icc_ctlr(void)
{
	uint32_t v;

	asm volatile ("mrc p15,0,%0,c12,c12,4" : "=r" (v));
	return v;
}

static inline void write_icc_ctlr(uint32_t v)
{
	asm volatile ("mcr p15,0,%0,c12,c12,4" : : "r" (v));
}

static inline void write_icc_pmr(uint32_t v)
{
	asm volatile ("mcr p15,0,%0,c4,c6,0" : : "r" (v));
}

static inline uint32_t read_icc_iar0(void)
{
	uint32_t v;

	asm volatile ("mrc p15,0,%0,c12,c8,0" : "=r" (v));
	return v;
}

static inline void write_icc_eoir0(uint32_t v)
{
	asm volatile ("mcr p15,0,%0,c12,c8,1" : : "r" (v));
}

static inline uint64_t read_pmu_ccnt(void)
{
	uint32_t val;

	asm volatile("mrc p15, 0, %0, c9, c13, 0" : "=r"(val));
	return val;
}

static inline void wfi(void)
{
	asm volatile("wfi");
}
#endif /*ASM*/

#endif /*ARM32_H*/
