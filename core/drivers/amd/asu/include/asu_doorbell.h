/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2024 - 2025 Advanced Micro Devices, Inc. All Rights Reserved.
 *
 */

#ifndef _ASU_DOORBELL_H_
#define _ASU_DOORBELL_H_

#include <stdint.h>

#define PAR_IPIPSU_NUM_INSTANCES	1U

/* Parameter definitions for peripheral ASU IPI */
#define PAR_IPIPSU_0_DEVICE_ID		0U
#define PAR_IPIPSU_0_BASEADDR		0xEB330000U
#define PAR_IPIPSU_0_BIT_MASK		0x00000001U
#define PAR_IPIPSU_0_INT_ID		0x59U
#define PAR_IPIPSU_NUM_TARGETS		16U
#define PAR_PSV_IPI_PMC_BIT_MASK	(0x2U)
#define PAR_PSV_IPI_0_BIT_MASK		(0x4U)
#define PAR_PSV_IPI_1_BIT_MASK		(0x8U)
#define PAR_PSV_IPI_2_BIT_MASK		(0x10U)
#define PAR_PSV_IPI_3_BIT_MASK		0x20U
#define PAR_PSV_IPI_4_BIT_MASK		0x40U
#define PAR_PSV_IPI_5_BIT_MASK		0x80U
#define PAR_PSV_IPI_PMC_NOBUF_BIT_MASK	0x100U
#define PAR_PSV_IPI_6_BIT_MASK		0x200U
#define IPIPSU_ALL_MASK			0xFFFFU

#define IPIPSU_TRIG_OFFSET	0x00U
#define IPIPSU_OBS_OFFSET	0x04U
#define IPIPSU_ISR_OFFSET	0x10U
#define IPIPSU_IMR_OFFSET	0x14U
#define IPIPSU_IER_OFFSET	0x18U

struct doorbell_config {
	uint32_t deviceid;
	uintptr_t baseaddr;
	uint32_t bitmask;
	uint32_t intrid;
	uintptr_t intrparent;
	uint32_t target_count;
	uint32_t target_mask[PAR_IPIPSU_NUM_TARGETS];
};

struct doorbell_config configtable = {
	.deviceid = PAR_IPIPSU_0_DEVICE_ID,
	.baseaddr = PAR_IPIPSU_0_BASEADDR,
	.bitmask = PAR_IPIPSU_0_BIT_MASK,
	.intrid = PAR_IPIPSU_0_INT_ID,
	.target_count = PAR_IPIPSU_NUM_TARGETS,
	.target_mask = {
		PAR_PSV_IPI_PMC_BIT_MASK,
		PAR_PSV_IPI_0_BIT_MASK,
		PAR_PSV_IPI_1_BIT_MASK,
		PAR_PSV_IPI_2_BIT_MASK,
		PAR_PSV_IPI_3_BIT_MASK,
		PAR_PSV_IPI_4_BIT_MASK,
		PAR_PSV_IPI_5_BIT_MASK,
		PAR_PSV_IPI_PMC_NOBUF_BIT_MASK,
		PAR_PSV_IPI_6_BIT_MASK,
	}
};

#endif /* _ASU_DOORBELL_H_ */
