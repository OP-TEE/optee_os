/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#ifndef __ARM32_H
#define __ARM32_H

#include <compiler.h>
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

#define PMCR_DP		BIT32(5)

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
#define SCTLR_SPAN	BIT32(23)
#define SCTLR_VE	BIT32(24)
#define SCTLR_EE	BIT32(25)
#define SCTLR_NMFI	BIT32(27)
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
#define CPACR_CP_ACCESS_DENIED		U(0x0)
#define CPACR_CP_ACCESS_PL1_ONLY	U(0x1)
#define CPACR_CP_ACCESS_FULL		U(0x3)


#define DACR_DOMAIN(num, perm)		SHIFT_U32((perm), ((num) * 2))
#define DACR_DOMAIN_PERM_NO_ACCESS	U(0x0)
#define DACR_DOMAIN_PERM_CLIENT		U(0x1)
#define DACR_DOMAIN_PERM_MANAGER	U(0x3)

#define PAR_F			BIT32(0)
#define PAR_SS			BIT32(1)
#define PAR_LPAE		BIT32(11)
#define PAR_PA_SHIFT		U(12)
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
#define TTBCR_T0SZ_SHIFT	U(0)
#define TTBCR_EPD0		BIT32(7)
#define TTBCR_IRGN0_SHIFT	U(8)
#define TTBCR_ORGN0_SHIFT	U(10)
#define TTBCR_SH0_SHIFT		U(12)
#define TTBCR_T1SZ_SHIFT	U(16)
#define TTBCR_A1		BIT32(22)
#define TTBCR_EPD1		BIT32(23)
#define TTBCR_IRGN1_SHIFT	U(24)
#define TTBCR_ORGN1_SHIFT	U(26)
#define TTBCR_SH1_SHIFT		U(28)

/* Normal memory, Inner/Outer Non-cacheable */
#define TTBCR_XRGNX_NC		U(0x0)
/* Normal memory, Inner/Outer Write-Back Write-Allocate Cacheable */
#define TTBCR_XRGNX_WB		U(0x1)
/* Normal memory, Inner/Outer Write-Through Cacheable */
#define TTBCR_XRGNX_WT		U(0x2)
/* Normal memory, Inner/Outer Write-Back no Write-Allocate Cacheable */
#define TTBCR_XRGNX_WBWA	U(0x3)

/* Non-shareable */
#define TTBCR_SHX_NSH		U(0x0)
/* Outer Shareable */
#define TTBCR_SHX_OSH		U(0x2)
/* Inner Shareable */
#define TTBCR_SHX_ISH		U(0x3)

#define TTBR_ASID_MASK		U(0xff)
#define TTBR_ASID_SHIFT		U(48)

#define TLBI_MVA_SHIFT		U(12)
#define TLBI_ASID_MASK		U(0xff)

#define FSR_LPAE		BIT32(9)
#define FSR_WNR			BIT32(11)

/* Valid if FSR.LPAE is 1 */
#define FSR_STATUS_MASK		(BIT32(6) - 1)

/* Valid if FSR.LPAE is 0 */
#define FSR_FS_MASK		(BIT32(10) | (BIT32(4) - 1))

/* ID_PFR1 bit fields */
#define IDPFR1_VIRT_SHIFT            U(12)
#define IDPFR1_VIRT_MASK             SHIFT_U32(0xF, IDPFR1_VIRT_SHIFT)
#define IDPFR1_GENTIMER_SHIFT        U(16)
#define IDPFR1_GENTIMER_MASK         SHIFT_U32(0xF, IDPFR1_GENTIMER_SHIFT)

#ifndef __ASSEMBLER__
#include <generated/arm32_sysreg.h>
#ifdef CFG_ARM_GICV3
#include <generated/arm32_gicv3_sysreg.h>
#endif

static inline __noprof void isb(void)
{
	asm volatile ("isb" : : : "memory");
}

static inline __noprof void dsb(void)
{
	asm volatile ("dsb" : : : "memory");
}

static inline __noprof void dsb_ish(void)
{
	asm volatile ("dsb ish" : : : "memory");
}

static inline __noprof void dsb_ishst(void)
{
	asm volatile ("dsb ishst" : : : "memory");
}

static inline __noprof void dmb(void)
{
	asm volatile ("dmb" : : : "memory");
}

static inline __noprof void sev(void)
{
	asm volatile ("sev" : : : "memory");
}

static inline __noprof void wfe(void)
{
	asm volatile ("wfe" : : : "memory");
}

static inline __noprof uint32_t read_cpsr(void)
{
	uint32_t cpsr;

	asm volatile ("mrs	%[cpsr], cpsr"
			: [cpsr] "=r" (cpsr)
	);
	return cpsr;
}

static inline __noprof void write_cpsr(uint32_t cpsr)
{
	asm volatile ("msr	cpsr_fsxc, %[cpsr]"
			: : [cpsr] "r" (cpsr)
	);
}

static inline __noprof uint32_t read_spsr(void)
{
	uint32_t spsr;

	asm volatile ("mrs	%[spsr], spsr"
			: [spsr] "=r" (spsr)
	);
	return spsr;
}

static inline __noprof void wfi(void)
{
	asm volatile("wfi" : : : "memory");
}

static __always_inline __noprof uint32_t read_pc(void)
{
	uint32_t val;

	asm volatile ("adr %0, ." : "=r" (val));
	return val;
}

static __always_inline __noprof uint32_t read_sp(void)
{
	uint32_t val;

	asm volatile ("mov %0, sp" : "=r" (val));
	return val;
}

static __always_inline __noprof uint32_t read_lr(void)
{
	uint32_t val;

	asm volatile ("mov %0, lr" : "=r" (val));
	return val;
}

static __always_inline __noprof uint32_t read_fp(void)
{
	uint32_t val;

	asm volatile ("mov %0, fp" : "=r" (val));
	return val;
}

static __always_inline __noprof uint32_t read_r7(void)
{
	uint32_t val;

	asm volatile ("mov %0, r7" : "=r" (val));
	return val;
}

#endif /*__ASSEMBLER__*/

#endif /*__ARM32_H*/
