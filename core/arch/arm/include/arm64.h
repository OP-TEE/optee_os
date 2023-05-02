/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015, Linaro Limited
 */
#ifndef ARM64_H
#define ARM64_H

#include <compiler.h>
#include <sys/cdefs.h>
#include <stdint.h>
#include <util.h>

#define SCTLR_M		BIT64(0)
#define SCTLR_A		BIT64(1)
#define SCTLR_C		BIT64(2)
#define SCTLR_SA	BIT64(3)
#define SCTLR_I		BIT64(12)
#define SCTLR_ENDB	BIT64(13)
#define SCTLR_WXN	BIT64(19)
#define SCTLR_SPAN	BIT64(23)
#define SCTLR_ENDA	BIT64(27)
#define SCTLR_ENIB	BIT64(30)
#define SCTLR_ENIA	BIT64(31)
#define SCTLR_BT0	BIT64(35)
#define SCTLR_BT1	BIT64(36)
#define SCTLR_ITFSB	BIT64(37)

#define SCTLR_TCF_MASK	SHIFT_U64(0x3, 40)
#define SCTLR_TCF_NONE	SHIFT_U64(0x0, 40)
#define SCTLR_TCF_SYNC	SHIFT_U64(0x1, 40)
#define SCTLR_TCF_ASYNC	SHIFT_U64(0x2, 40)
#define SCTLR_TCF_ASYMM	SHIFT_U64(0x3, 40)

#define SCTLR_TCF0_MASK	SHIFT_U64(0x3, 38)
#define SCTLR_TCF0_NONE	SHIFT_U64(0x0, 38)
#define SCTLR_TCF0_SYNC	SHIFT_U64(0x1, 38)
#define SCTLR_TCF0_ASYNC SHIFT_U64(0x2, 38)
#define SCTLR_TCF0_ASYMM SHIFT_U64(0x3, 38)

#define SCTLR_ATA0	BIT64(42)
#define SCTLR_ATA	BIT64(43)

#define TTBR_ASID_MASK		U(0xff)
#define TTBR_ASID_SHIFT		U(48)

#define CLIDR_LOUIS_SHIFT	U(21)
#define CLIDR_LOC_SHIFT		U(24)
#define CLIDR_FIELD_WIDTH	U(3)

#define CSSELR_LEVEL_SHIFT	U(1)

#define DAIFBIT_FIQ			BIT32(0)
#define DAIFBIT_IRQ			BIT32(1)
#define DAIFBIT_ABT			BIT32(2)
#define DAIFBIT_DBG			BIT32(3)
#define DAIFBIT_ALL			(DAIFBIT_FIQ | DAIFBIT_IRQ | \
					 DAIFBIT_ABT | DAIFBIT_DBG)

#define DAIF_F_SHIFT		U(6)
#define DAIF_F			BIT32(6)
#define DAIF_I			BIT32(7)
#define DAIF_A			BIT32(8)
#define DAIF_D			BIT32(9)
#define DAIF_AIF		(DAIF_A | DAIF_I | DAIF_F)

#define SPSR_MODE_RW_SHIFT	U(4)
#define SPSR_MODE_RW_MASK	U(0x1)
#define SPSR_MODE_RW_64		U(0x0)
#define SPSR_MODE_RW_32		U(0x1)

#define SPSR_64_MODE_SP_SHIFT	U(0)
#define SPSR_64_MODE_SP_MASK	U(0x1)
#define SPSR_64_MODE_SP_EL0	U(0x0)
#define SPSR_64_MODE_SP_ELX	U(0x1)

#define SPSR_64_MODE_EL_SHIFT	U(2)
#define SPSR_64_MODE_EL_MASK	U(0x3)
#define SPSR_64_MODE_EL1	U(0x1)
#define SPSR_64_MODE_EL0	U(0x0)

#define SPSR_64_DAIF_SHIFT	U(6)
#define SPSR_64_DAIF_MASK	U(0xf)

#define SPSR_32_AIF_SHIFT	U(6)
#define SPSR_32_AIF_MASK	U(0x7)

#define SPSR_32_E_SHIFT		U(9)
#define SPSR_32_E_MASK		U(0x1)
#define SPSR_32_E_LITTLE	U(0x0)
#define SPSR_32_E_BIG		U(0x1)

#define SPSR_32_T_SHIFT		U(5)
#define SPSR_32_T_MASK		U(0x1)
#define SPSR_32_T_ARM		U(0x0)
#define SPSR_32_T_THUMB		U(0x1)

#define SPSR_32_MODE_SHIFT	U(0)
#define SPSR_32_MODE_MASK	U(0xf)
#define SPSR_32_MODE_USR	U(0x0)


#define SPSR_64(el, sp, daif)						\
	(SPSR_MODE_RW_64 << SPSR_MODE_RW_SHIFT |			\
	((el) & SPSR_64_MODE_EL_MASK) << SPSR_64_MODE_EL_SHIFT |	\
	((sp) & SPSR_64_MODE_SP_MASK) << SPSR_64_MODE_SP_SHIFT |	\
	((daif) & SPSR_64_DAIF_MASK) << SPSR_64_DAIF_SHIFT)

#define SPSR_32(mode, isa, aif)						\
	(SPSR_MODE_RW_32 << SPSR_MODE_RW_SHIFT |			\
	SPSR_32_E_LITTLE << SPSR_32_E_SHIFT |				\
	((mode) & SPSR_32_MODE_MASK) << SPSR_32_MODE_SHIFT |		\
	((isa) & SPSR_32_T_MASK) << SPSR_32_T_SHIFT |			\
	((aif) & SPSR_32_AIF_MASK) << SPSR_32_AIF_SHIFT)


#define TCR_T0SZ_SHIFT		U(0)
#define TCR_EPD0		BIT64(7)
#define TCR_IRGN0_SHIFT		U(8)
#define TCR_ORGN0_SHIFT		U(10)
#define TCR_SH0_SHIFT		U(12)
#define TCR_T1SZ_SHIFT		U(16)
#define TCR_A1			BIT64(22)
#define TCR_EPD1		BIT64(23)
#define TCR_IRGN1_SHIFT		U(24)
#define TCR_ORGN1_SHIFT		U(26)
#define TCR_SH1_SHIFT		U(28)
#define TCR_EL1_IPS_SHIFT	U(32)
#define TCR_EL1_IPS_MASK	UINT64_C(0x7)
#define TCR_TG1_4KB		SHIFT_U64(2, 30)
#define TCR_RES1		BIT64(31)
#define TCR_TBI0		BIT64(37)
#define TCR_TBI1		BIT64(38)
#define TCR_TCMA0		BIT64(57)
#define TCR_TCMA1		BIT64(58)


/* Normal memory, Inner/Outer Non-cacheable */
#define TCR_XRGNX_NC		U(0x0)
/* Normal memory, Inner/Outer Write-Back Write-Allocate Cacheable */
#define TCR_XRGNX_WB		U(0x1)
/* Normal memory, Inner/Outer Write-Through Cacheable */
#define TCR_XRGNX_WT		U(0x2)
/* Normal memory, Inner/Outer Write-Back no Write-Allocate Cacheable */
#define TCR_XRGNX_WBWA		U(0x3)

/* Non-shareable */
#define TCR_SHX_NSH		U(0x0)
/* Outer Shareable */
#define TCR_SHX_OSH		U(0x2)
/* Inner Shareable */
#define TCR_SHX_ISH		U(0x3)

#define ESR_EC_SHIFT		U(26)
#define ESR_EC_MASK		U(0x3f)

#define ESR_EC_UNKNOWN		U(0x00)
#define ESR_EC_WFI		U(0x01)
#define ESR_EC_AARCH32_CP15_32	U(0x03)
#define ESR_EC_AARCH32_CP15_64	U(0x04)
#define ESR_EC_AARCH32_CP14_MR	U(0x05)
#define ESR_EC_AARCH32_CP14_LS	U(0x06)
#define ESR_EC_FP_ASIMD		U(0x07)
#define ESR_EC_AARCH32_CP10_ID	U(0x08)
#define ESR_EC_PAUTH		U(0x09)
#define ESR_EC_AARCH32_CP14_64	U(0x0c)
#define ESR_EC_BTI		U(0x0d)
#define ESR_EC_ILLEGAL		U(0x0e)
#define ESR_EC_AARCH32_SVC	U(0x11)
#define ESR_EC_AARCH64_SVC	U(0x15)
#define ESR_EC_AARCH64_SYS	U(0x18)
#define ESR_EC_ERET		U(0x1a)
#define ESR_EC_FPAC		U(0x1c)
#define ESR_EC_IABT_EL0		U(0x20)
#define ESR_EC_IABT_EL1		U(0x21)
#define ESR_EC_PC_ALIGN		U(0x22)
#define ESR_EC_DABT_EL0		U(0x24)
#define ESR_EC_DABT_EL1		U(0x25)
#define ESR_EC_SP_ALIGN		U(0x26)
#define ESR_EC_AARCH32_FP	U(0x28)
#define ESR_EC_AARCH64_FP	U(0x2c)
#define ESR_EC_SERROR		U(0x2f)
#define ESR_EC_BREAKPT_EL0	U(0x30)
#define ESR_EC_BREAKPT_EL1	U(0x31)
#define ESR_EC_SOFTSTP_EL0	U(0x32)
#define ESR_EC_SOFTSTP_EL1	U(0x33)
#define ESR_EC_WATCHPT_EL0	U(0x34)
#define ESR_EC_WATCHPT_EL1	U(0x35)
#define ESR_EC_AARCH32_BKPT	U(0x38)
#define ESR_EC_AARCH64_BRK	U(0x3c)

/* Combined defines for DFSC and IFSC */
#define ESR_FSC_MASK		U(0x3f)
#define ESR_FSC_SIZE_L0		U(0x00)
#define ESR_FSC_SIZE_L1		U(0x01)
#define ESR_FSC_SIZE_L2		U(0x02)
#define ESR_FSC_SIZE_L3		U(0x03)
#define ESR_FSC_TRANS_L0	U(0x04)
#define ESR_FSC_TRANS_L1	U(0x05)
#define ESR_FSC_TRANS_L2	U(0x06)
#define ESR_FSC_TRANS_L3	U(0x07)
#define ESR_FSC_ACCF_L1		U(0x09)
#define ESR_FSC_ACCF_L2		U(0x0a)
#define ESR_FSC_ACCF_L3		U(0x0b)
#define ESR_FSC_PERMF_L1	U(0x0d)
#define ESR_FSC_PERMF_L2	U(0x0e)
#define ESR_FSC_PERMF_L3	U(0x0f)
#define ESR_FSC_TAG_CHECK	U(0x11)
#define ESR_FSC_ALIGN		U(0x21)

/* WnR for DABT and RES0 for IABT */
#define ESR_ABT_WNR		BIT32(6)

#define CPACR_EL1_FPEN_SHIFT	U(20)
#define CPACR_EL1_FPEN_MASK	U(0x3)
#define CPACR_EL1_FPEN_NONE	U(0x0)
#define CPACR_EL1_FPEN_EL1	U(0x1)
#define CPACR_EL1_FPEN_EL0EL1	U(0x3)
#define CPACR_EL1_FPEN(x)	((x) >> CPACR_EL1_FPEN_SHIFT \
				      & CPACR_EL1_FPEN_MASK)


#define PAR_F			BIT32(0)
#define PAR_PA_SHIFT		U(12)
#define PAR_PA_MASK		(BIT64(36) - 1)

#define TLBI_MVA_SHIFT		U(12)
#define TLBI_ASID_SHIFT		U(48)
#define TLBI_ASID_MASK		U(0xff)

#define ID_AA64PFR1_EL1_BT_MASK	ULL(0xf)
#define FEAT_BTI_IMPLEMENTED	ULL(0x1)

#define ID_AA64PFR1_EL1_MTE_MASK	UL(0xf)
#define ID_AA64PFR1_EL1_MTE_SHIFT	U(8)
#define FEAT_MTE_NOT_IMPLEMENTED	U(0x0)
#define FEAT_MTE_IMPLEMENTED		U(0x1)
#define FEAT_MTE2_IMPLEMENTED		U(0x2)
#define FEAT_MTE3_IMPLEMENTED		U(0x3)

#define ID_AA64ISAR1_GPI_SHIFT		U(28)
#define ID_AA64ISAR1_GPI_MASK		U(0xf)
#define ID_AA64ISAR1_GPI_NI		U(0x0)
#define ID_AA64ISAR1_GPI_IMP_DEF	U(0x1)

#define ID_AA64ISAR1_GPA_SHIFT		U(24)
#define ID_AA64ISAR1_GPA_MASK		U(0xf)
#define ID_AA64ISAR1_GPA_NI		U(0x0)
#define ID_AA64ISAR1_GPA_ARCHITECTED	U(0x1)

#define ID_AA64ISAR1_API_SHIFT			U(8)
#define ID_AA64ISAR1_API_MASK			U(0xf)
#define ID_AA64ISAR1_API_NI			U(0x0)
#define ID_AA64ISAR1_API_IMP_DEF		U(0x1)
#define ID_AA64ISAR1_API_IMP_DEF_EPAC		U(0x2)
#define ID_AA64ISAR1_API_IMP_DEF_EPAC2		U(0x3)
#define ID_AA64ISAR1_API_IMP_DEF_EPAC2_FPAC	U(0x4)
#define ID_AA64ISAR1_API_IMP_DEF_EPAC2_FPAC_CMB	U(0x5)

#define ID_AA64ISAR1_APA_SHIFT			U(4)
#define ID_AA64ISAR1_APA_MASK			U(0xf)
#define ID_AA64ISAR1_APA_NI			U(0x0)
#define ID_AA64ISAR1_APA_ARCHITECTED		U(0x1)
#define ID_AA64ISAR1_APA_ARCH_EPAC		U(0x2)
#define ID_AA64ISAR1_APA_ARCH_EPAC2		U(0x3)
#define ID_AA64ISAR1_APA_ARCH_EPAC2_FPAC	U(0x4)
#define ID_AA64ISAR1_APA_ARCH_EPAC2_FPAC_CMB	U(0x5)

#define GCR_EL1_RRND				BIT64(16)

#ifndef __ASSEMBLER__
static inline __noprof void isb(void)
{
	asm volatile ("isb" : : : "memory");
}

static inline __noprof void dsb(void)
{
	asm volatile ("dsb sy" : : : "memory");
}

static inline __noprof void dsb_ish(void)
{
	asm volatile ("dsb ish" : : : "memory");
}

static inline __noprof void dsb_ishst(void)
{
	asm volatile ("dsb ishst" : : : "memory");
}

static inline __noprof void sev(void)
{
	asm volatile ("sev" : : : "memory");
}

static inline __noprof void wfe(void)
{
	asm volatile ("wfe" : : : "memory");
}

static inline __noprof void wfi(void)
{
	asm volatile ("wfi" : : : "memory");
}

static inline __noprof void write_at_s1e1r(uint64_t va)
{
	asm volatile ("at	S1E1R, %0" : : "r" (va));
}

static __always_inline __noprof uint64_t read_pc(void)
{
	uint64_t val;

	asm volatile ("adr %0, ." : "=r" (val));
	return val;
}

static __always_inline __noprof uint64_t read_fp(void)
{
	uint64_t val;

	asm volatile ("mov %0, x29" : "=r" (val));
	return val;
}

static inline __noprof uint64_t read_pmu_ccnt(void)
{
	uint64_t val;

	asm volatile("mrs %0, PMCCNTR_EL0" : "=r"(val));
	return val;
}

static inline __noprof void tlbi_vaae1is(uint64_t mva)
{
	asm volatile ("tlbi	vaae1is, %0" : : "r" (mva));
}

static inline __noprof void tlbi_vale1is(uint64_t mva)
{
	asm volatile ("tlbi	vale1is, %0" : : "r" (mva));
}

/*
 * Templates for register read/write functions based on mrs/msr
 */

#define DEFINE_REG_READ_FUNC_(reg, type, asmreg)		\
static inline __noprof type read_##reg(void)			\
{								\
	uint64_t val64 = 0;					\
								\
	asm volatile("mrs %0, " #asmreg : "=r" (val64));	\
	return val64;						\
}

#define DEFINE_REG_WRITE_FUNC_(reg, type, asmreg)		\
static inline __noprof void write_##reg(type val)		\
{								\
	uint64_t val64 = val;					\
								\
	asm volatile("msr " #asmreg ", %0" : : "r" (val64));	\
}

#define DEFINE_U32_REG_READ_FUNC(reg) \
		DEFINE_REG_READ_FUNC_(reg, uint32_t, reg)

#define DEFINE_U32_REG_WRITE_FUNC(reg) \
		DEFINE_REG_WRITE_FUNC_(reg, uint32_t, reg)

#define DEFINE_U32_REG_READWRITE_FUNCS(reg)	\
		DEFINE_U32_REG_READ_FUNC(reg)	\
		DEFINE_U32_REG_WRITE_FUNC(reg)

#define DEFINE_U64_REG_READ_FUNC(reg) \
		DEFINE_REG_READ_FUNC_(reg, uint64_t, reg)

#define DEFINE_U64_REG_WRITE_FUNC(reg) \
		DEFINE_REG_WRITE_FUNC_(reg, uint64_t, reg)

#define DEFINE_U64_REG_READWRITE_FUNCS(reg)	\
		DEFINE_U64_REG_READ_FUNC(reg)	\
		DEFINE_U64_REG_WRITE_FUNC(reg)

/*
 * Define register access functions
 */

DEFINE_U32_REG_READWRITE_FUNCS(cpacr_el1)
DEFINE_U32_REG_READWRITE_FUNCS(daif)
DEFINE_U32_REG_READWRITE_FUNCS(fpcr)
DEFINE_U32_REG_READWRITE_FUNCS(fpsr)

DEFINE_U32_REG_READ_FUNC(ctr_el0)
#define read_ctr() read_ctr_el0()
DEFINE_U32_REG_READ_FUNC(contextidr_el1)
DEFINE_U64_REG_READ_FUNC(sctlr_el1)

/* ARM Generic timer functions */
DEFINE_REG_READ_FUNC_(cntfrq, uint32_t, cntfrq_el0)
DEFINE_REG_READ_FUNC_(cntvct, uint64_t, cntvct_el0)
DEFINE_REG_READ_FUNC_(cntpct, uint64_t, cntpct_el0)
DEFINE_REG_READ_FUNC_(cntkctl, uint32_t, cntkctl_el1)
DEFINE_REG_WRITE_FUNC_(cntkctl, uint32_t, cntkctl_el1)
DEFINE_REG_READ_FUNC_(cntps_ctl, uint32_t, cntps_ctl_el1)
DEFINE_REG_WRITE_FUNC_(cntps_ctl, uint32_t, cntps_ctl_el1)
DEFINE_REG_READ_FUNC_(cntps_tval, uint32_t, cntps_tval_el1)
DEFINE_REG_WRITE_FUNC_(cntps_tval, uint32_t, cntps_tval_el1)

DEFINE_REG_READ_FUNC_(pmccntr, uint64_t, pmccntr_el0)

DEFINE_U64_REG_READWRITE_FUNCS(ttbr0_el1)
DEFINE_U64_REG_READWRITE_FUNCS(ttbr1_el1)
DEFINE_U64_REG_READWRITE_FUNCS(tcr_el1)

DEFINE_U64_REG_READ_FUNC(esr_el1)
DEFINE_U64_REG_READ_FUNC(far_el1)
DEFINE_U64_REG_READ_FUNC(mpidr_el1)
/* Alias for reading this register to avoid ifdefs in code */
#define read_mpidr() read_mpidr_el1()
DEFINE_U64_REG_READ_FUNC(midr_el1)
/* Alias for reading this register to avoid ifdefs in code */
#define read_midr() read_midr_el1()
DEFINE_U64_REG_READ_FUNC(par_el1)

DEFINE_U64_REG_WRITE_FUNC(mair_el1)

DEFINE_U64_REG_READ_FUNC(id_aa64pfr1_el1)
DEFINE_U64_REG_READ_FUNC(id_aa64isar1_el1)
DEFINE_REG_READ_FUNC_(apiakeylo, uint64_t, S3_0_c2_c1_0)
DEFINE_REG_READ_FUNC_(apiakeyhi, uint64_t, S3_0_c2_c1_1)

DEFINE_REG_WRITE_FUNC_(apibkeylo, uint64_t, S3_0_c2_c1_2)
DEFINE_REG_WRITE_FUNC_(apibkeyhi, uint64_t, S3_0_c2_c1_3)

DEFINE_REG_READ_FUNC_(apdakeylo, uint64_t, S3_0_c2_c2_0)
DEFINE_REG_READ_FUNC_(apdakeyhi, uint64_t, S3_0_c2_c2_1)

DEFINE_REG_WRITE_FUNC_(apdbkeylo, uint64_t, S3_0_c2_c2_2)
DEFINE_REG_WRITE_FUNC_(apdbkeyhi, uint64_t, S3_0_c2_c2_3)

DEFINE_REG_WRITE_FUNC_(apgakeylo, uint64_t, S3_0_c2_c3_0)
DEFINE_REG_WRITE_FUNC_(apgakeyhi, uint64_t, S3_0_c2_c3_1)

/* Register read/write functions for GICC registers by using system interface */
DEFINE_REG_READ_FUNC_(icc_ctlr, uint32_t, S3_0_C12_C12_4)
DEFINE_REG_WRITE_FUNC_(icc_ctlr, uint32_t, S3_0_C12_C12_4)
DEFINE_REG_WRITE_FUNC_(icc_pmr, uint32_t, S3_0_C4_C6_0)
DEFINE_REG_READ_FUNC_(icc_iar0, uint32_t, S3_0_c12_c8_0)
DEFINE_REG_READ_FUNC_(icc_iar1, uint32_t, S3_0_c12_c12_0)
DEFINE_REG_WRITE_FUNC_(icc_eoir0, uint32_t, S3_0_c12_c8_1)
DEFINE_REG_WRITE_FUNC_(icc_eoir1, uint32_t, S3_0_c12_c12_1)
DEFINE_REG_WRITE_FUNC_(icc_igrpen0, uint32_t, S3_0_C12_C12_6)
DEFINE_REG_WRITE_FUNC_(icc_igrpen1, uint32_t, S3_0_C12_C12_7)
#endif /*__ASSEMBLER__*/

#endif /*ARM64_H*/

