/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015, Linaro Limited
 * Copyright (c) 2019-2023, Arm Limited. All rights reserved.
 */
#ifndef __ARM_H
#define __ARM_H

#include <stdbool.h>
#include <stdint.h>
#include <util.h>

/* MIDR definitions */
#define MIDR_PRIMARY_PART_NUM_SHIFT	U(4)
#define MIDR_PRIMARY_PART_NUM_WIDTH	U(12)
#define MIDR_PRIMARY_PART_NUM_MASK	(BIT(MIDR_PRIMARY_PART_NUM_WIDTH) - 1)

#define MIDR_IMPLEMENTER_SHIFT		U(24)
#define MIDR_IMPLEMENTER_WIDTH		U(8)
#define MIDR_IMPLEMENTER_MASK		(BIT(MIDR_IMPLEMENTER_WIDTH) - 1)
#define MIDR_IMPLEMENTER_ARM		U(0x41)

#define MIDR_VARIANT_SHIFT		U(20)
#define MIDR_VARIANT_WIDTH		U(4)
#define MIDR_VARIANT_MASK		(BIT(MIDR_VARIANT_WIDTH) - 1)

#define MIDR_REVISION_SHIFT		U(0)
#define MIDR_REVISION_WIDTH		U(4)
#define MIDR_REVISION_MASK		(BIT(MIDR_REVISION_WIDTH) - 1)

#define CORTEX_A5_PART_NUM		U(0xC05)
#define CORTEX_A7_PART_NUM		U(0xC07)
#define CORTEX_A8_PART_NUM		U(0xC08)
#define CORTEX_A9_PART_NUM		U(0xC09)
#define CORTEX_A15_PART_NUM		U(0xC0F)
#define CORTEX_A17_PART_NUM		U(0xC0E)
#define CORTEX_A57_PART_NUM		U(0xD07)
#define CORTEX_A72_PART_NUM		U(0xD08)
#define CORTEX_A73_PART_NUM		U(0xD09)
#define CORTEX_A75_PART_NUM		U(0xD0A)
#define CORTEX_A65_PART_NUM		U(0xD06)
#define CORTEX_A65AE_PART_NUM		U(0xD43)
#define CORTEX_A76_PART_NUM		U(0xD0B)
#define CORTEX_A76AE_PART_NUM		U(0xD0E)
#define CORTEX_A77_PART_NUM		U(0xD0D)
#define CORTEX_A78_PART_NUM		U(0xD41)
#define CORTEX_A78AE_PART_NUM		U(0xD42)
#define CORTEX_A78C_PART_NUM		U(0xD4B)
#define CORTEX_A710_PART_NUM		U(0xD47)
#define CORTEX_X1_PART_NUM		U(0xD44)
#define CORTEX_X2_PART_NUM		U(0xD48)
#define NEOVERSE_E1_PART_NUM		U(0xD4A)
#define NEOVERSE_N1_PART_NUM		U(0xD0C)
#define NEOVERSE_N2_PART_NUM		U(0xD49)
#define NEOVERSE_V1_PART_NUM		U(0xD40)

/* MPIDR definitions */
#define MPIDR_AFFINITY_BITS	U(8)
#define MPIDR_AFFLVL_MASK	ULL(0xff)
#define MPIDR_AFF0_SHIFT	U(0)
#define MPIDR_AFF0_MASK		(MPIDR_AFFLVL_MASK << MPIDR_AFF0_SHIFT)
#define MPIDR_AFF1_SHIFT	U(8)
#define MPIDR_AFF1_MASK		(MPIDR_AFFLVL_MASK << MPIDR_AFF1_SHIFT)
#define MPIDR_AFF2_SHIFT	U(16)
#define MPIDR_AFF2_MASK		(MPIDR_AFFLVL_MASK << MPIDR_AFF2_SHIFT)
#define MPIDR_AFF3_SHIFT	U(32)
#define MPIDR_AFF3_MASK		(MPIDR_AFFLVL_MASK << MPIDR_AFF3_SHIFT)

#define MPIDR_MT_SHIFT		U(24)
#define MPIDR_MT_MASK		BIT(MPIDR_MT_SHIFT)

#define MPIDR_CPU_MASK		MPIDR_AFF0_MASK
#define MPIDR_CLUSTER_SHIFT	MPIDR_AFF1_SHIFT
#define MPIDR_CLUSTER_MASK	MPIDR_AFF1_MASK

#define MPIDR_AARCH32_AFF_MASK	(MPIDR_AFF0_MASK | MPIDR_AFF1_MASK | \
				 MPIDR_AFF2_MASK)

/* ID_ISAR5 Cryptography Extension masks */
#define ID_ISAR5_AES		GENMASK_32(7, 4)
#define ID_ISAR5_SHA1		GENMASK_32(11, 8)
#define ID_ISAR5_SHA2		GENMASK_32(15, 12)
#define ID_ISAR5_CRC32		GENMASK_32(19, 16)

/* CLIDR definitions */
#define CLIDR_LOUIS_SHIFT	U(21)
#define CLIDR_LOC_SHIFT		U(24)
#define CLIDR_FIELD_WIDTH	U(3)

/* CSSELR definitions */
#define CSSELR_LEVEL_SHIFT	U(1)

/* CTR definitions */
#define CTR_CWG_SHIFT		U(24)
#define CTR_CWG_MASK		U(0xf)
#define CTR_ERG_SHIFT		U(20)
#define CTR_ERG_MASK		U(0xf)
#define CTR_DMINLINE_SHIFT	U(16)
#define CTR_DMINLINE_WIDTH	U(4)
#define CTR_DMINLINE_MASK	(BIT(4) - 1)
#define CTR_L1IP_SHIFT		U(14)
#define CTR_L1IP_MASK		U(0x3)
#define CTR_IMINLINE_SHIFT	U(0)
#define CTR_IMINLINE_MASK	U(0xf)
#define CTR_WORD_SIZE		U(4)

#define ARM32_CPSR_MODE_MASK	U(0x1f)
#define ARM32_CPSR_MODE_USR	U(0x10)
#define ARM32_CPSR_MODE_FIQ	U(0x11)
#define ARM32_CPSR_MODE_IRQ	U(0x12)
#define ARM32_CPSR_MODE_SVC	U(0x13)
#define ARM32_CPSR_MODE_MON	U(0x16)
#define ARM32_CPSR_MODE_ABT	U(0x17)
#define ARM32_CPSR_MODE_UND	U(0x1b)
#define ARM32_CPSR_MODE_SYS	U(0x1f)

#define ARM32_CPSR_T		BIT(5)
#define ARM32_CPSR_F_SHIFT	U(6)
#define ARM32_CPSR_F		BIT(6)
#define ARM32_CPSR_I		BIT(7)
#define ARM32_CPSR_A		BIT(8)
#define ARM32_CPSR_E		BIT(9)
#define ARM32_CPSR_FIA		(ARM32_CPSR_F | ARM32_CPSR_I | ARM32_CPSR_A)
#define ARM32_CPSR_IT_MASK	(ARM32_CPSR_IT_MASK1 | ARM32_CPSR_IT_MASK2)
#define ARM32_CPSR_IT_MASK1	U(0x06000000)
#define ARM32_CPSR_IT_MASK2	U(0x0000fc00)

/* ARM Generic timer definitions */
#define CNTKCTL_PL0PCTEN	BIT(0) /* physical counter el0 access enable */
#define CNTKCTL_PL0VCTEN	BIT(1) /* virtual counter el0 access enable */

#ifdef ARM32
#include <arm32.h>
#endif

#ifdef ARM64
#include <arm64.h>
#endif

#ifndef __ASSEMBLER__
static inline __noprof uint64_t barrier_read_counter_timer(void)
{
	isb();
#ifdef CFG_CORE_SEL2_SPMC
	return read_cntvct();
#else
	return read_cntpct();
#endif
}

static inline bool feat_bti_is_implemented(void)
{
#ifdef ARM32
	return false;
#else
	return ((read_id_aa64pfr1_el1() & ID_AA64PFR1_EL1_BT_MASK) ==
		FEAT_BTI_IMPLEMENTED);
#endif
}

static inline unsigned int feat_mte_implemented(void)
{
#ifdef ARM32
	return 0;
#else
	return (read_id_aa64pfr1_el1() >> ID_AA64PFR1_EL1_MTE_SHIFT) &
	       ID_AA64PFR1_EL1_MTE_MASK;
#endif
}

static inline unsigned int feat_pan_implemented(void)
{
#ifdef ARM32
	return 0;
#else
	return (read_id_aa64mmfr1_el1() >> ID_AA64MMFR1_EL1_PAN_SHIFT) &
	       ID_AA64MMFR1_EL1_PAN_MASK;
#endif
}

static inline bool feat_crc32_implemented(void)
{
#ifdef ARM32
	return read_id_isar5() & ID_ISAR5_CRC32;
#else
	return read_id_aa64isar0_el1() & ID_AA64ISAR0_CRC32;
#endif
}

static inline bool feat_aes_implemented(void)
{
#ifdef ARM32
	return read_id_isar5() & ID_ISAR5_AES;
#else
	return read_id_aa64isar0_el1() & ID_AA64ISAR0_AES;
#endif
}

static inline bool feat_sha1_implemented(void)
{
#ifdef ARM32
	return read_id_isar5() & ID_ISAR5_SHA1;
#else
	return read_id_aa64isar0_el1() & ID_AA64ISAR0_SHA1;
#endif
}

static inline bool feat_sha256_implemented(void)
{
#ifdef ARM32
	return read_id_isar5() & ID_ISAR5_SHA2;
#else
	return read_id_aa64isar0_el1() & ID_AA64ISAR0_SHA2;
#endif
}

static inline bool feat_sha512_implemented(void)
{
#ifdef ARM32
	return false;
#else
	return ((read_id_aa64isar0_el1() & ID_AA64ISAR0_SHA2) >>
		ID_AA64ISAR0_SHA2_SHIFT) == ID_AA64ISAR0_SHA2_FEAT_SHA512;
#endif
}

static inline bool feat_sha3_implemented(void)
{
#ifdef ARM32
	return false;
#else
	return read_id_aa64isar0_el1() & ID_AA64ISAR0_SHA3;
#endif
}

static inline bool feat_sm3_implemented(void)
{
#ifdef ARM32
	return false;
#else
	return read_id_aa64isar0_el1() & ID_AA64ISAR0_SM3;
#endif
}

static inline bool feat_sm4_implemented(void)
{
#ifdef ARM32
	return false;
#else
	return read_id_aa64isar0_el1() & ID_AA64ISAR0_SM4;
#endif
}

static inline bool feat_pauth_is_implemented(void)
{
#ifdef ARM32
	return false;
#else
	uint64_t mask =
		SHIFT_U64(ID_AA64ISAR1_GPI_MASK, ID_AA64ISAR1_GPI_SHIFT) |
		SHIFT_U64(ID_AA64ISAR1_GPA_MASK, ID_AA64ISAR1_GPA_SHIFT) |
		SHIFT_U64(ID_AA64ISAR1_API_MASK, ID_AA64ISAR1_API_SHIFT) |
		SHIFT_U64(ID_AA64ISAR1_APA_MASK, ID_AA64ISAR1_APA_SHIFT);

	/* If any of the fields is not zero, PAuth is implemented by arch */
	return (read_id_aa64isar1_el1() & mask) != 0U;
#endif
}

#endif

#endif /*__ARM_H*/
