/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015, Linaro Limited
 */
#ifndef ARM_H
#define ARM_H

#include <util.h>

/* MIDR definitions */
#define MIDR_PRIMARY_PART_NUM_SHIFT	4
#define MIDR_PRIMARY_PART_NUM_WIDTH	12
#define MIDR_PRIMARY_PART_NUM_MASK	(BIT(MIDR_PRIMARY_PART_NUM_WIDTH) - 1)

#define MIDR_IMPLEMENTER_SHIFT		24
#define MIDR_IMPLEMENTER_WIDTH		8
#define MIDR_IMPLEMENTER_MASK		(BIT(MIDR_IMPLEMENTER_WIDTH) - 1)
#define MIDR_IMPLEMENTER_ARM		0x41

#define CORTEX_A7_PART_NUM		0xC07
#define CORTEX_A8_PART_NUM		0xC08
#define CORTEX_A9_PART_NUM		0xC09
#define CORTEX_A15_PART_NUM		0xC0F
#define CORTEX_A17_PART_NUM		0xC0E
#define CORTEX_A57_PART_NUM		0xD07
#define CORTEX_A72_PART_NUM		0xD08
#define CORTEX_A73_PART_NUM		0xD09
#define CORTEX_A75_PART_NUM		0xD0A

/* MPIDR definitions */
#define MPIDR_CPU_MASK		0xff
#define MPIDR_CLUSTER_SHIFT	8
#define MPIDR_CLUSTER_MASK	(0xff << MPIDR_CLUSTER_SHIFT)

/* CLIDR definitions */
#define CLIDR_LOUIS_SHIFT	21
#define CLIDR_LOC_SHIFT		24
#define CLIDR_FIELD_WIDTH	3

/* CSSELR definitions */
#define CSSELR_LEVEL_SHIFT	1

/* CTR definitions */
#define CTR_CWG_SHIFT		24
#define CTR_CWG_MASK		0xf
#define CTR_ERG_SHIFT		20
#define CTR_ERG_MASK		0xf
#define CTR_DMINLINE_SHIFT	16
#define CTR_DMINLINE_WIDTH	4
#define CTR_DMINLINE_MASK	((1 << 4) - 1)
#define CTR_L1IP_SHIFT		14
#define CTR_L1IP_MASK		0x3
#define CTR_IMINLINE_SHIFT	0
#define CTR_IMINLINE_MASK	0xf

#define ARM32_CPSR_MODE_MASK	0x1f
#define ARM32_CPSR_MODE_USR	0x10
#define ARM32_CPSR_MODE_FIQ	0x11
#define ARM32_CPSR_MODE_IRQ	0x12
#define ARM32_CPSR_MODE_SVC	0x13
#define ARM32_CPSR_MODE_MON	0x16
#define ARM32_CPSR_MODE_ABT	0x17
#define ARM32_CPSR_MODE_UND	0x1b
#define ARM32_CPSR_MODE_SYS	0x1f

#define ARM32_CPSR_T		(1 << 5)
#define ARM32_CPSR_F_SHIFT	6
#define ARM32_CPSR_F		(1 << 6)
#define ARM32_CPSR_I		(1 << 7)
#define ARM32_CPSR_A		(1 << 8)
#define ARM32_CPSR_E		(1 << 9)
#define ARM32_CPSR_FIA		(ARM32_CPSR_F | ARM32_CPSR_I | ARM32_CPSR_A)
#define ARM32_CPSR_IT_MASK	(ARM32_CPSR_IT_MASK1 | ARM32_CPSR_IT_MASK2)
#define ARM32_CPSR_IT_MASK1	0x06000000
#define ARM32_CPSR_IT_MASK2	0x0000fc00

/* ARM Generic timer definitions */
#define CNTKCTL_PL0PCTEN	BIT(0) /* physical counter el0 access enable */
#define CNTKCTL_PL0VCTEN	BIT(1) /* virtual counter el0 access enable */

#ifdef ARM32
#include <arm32.h>
#endif

#ifdef ARM64
#include <arm64.h>
#endif

#endif /*ARM_H*/
