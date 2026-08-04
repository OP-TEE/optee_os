/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef XPU_TARGET_H
#define XPU_TARGET_H

/* MEMNOC_SCH_MPU: resource groups 10..15 are free for runtime allocation */
#define DDR_MPU_BASE			UL(0xAC0000)
#define DDR_MPU_ADDR_OFFSET		UL(0x80000000)
#define DDR_XPU_RG_START		UL(10)
#define DDR_XPU_RG_COUNT		UL(6)

/*
 * OCIMEM_MPU register window. The base is well below CORE_MMU_PGDIR_SIZE,
 * so a pgdir-granularity mapping would round it down to address 0 and a
 * small explicit range is mapped instead. Resource groups 9..10 are free
 * for runtime allocation.
 */
#define IMEM_MPU_BASE			UL(0x54000)
#define IMEM_MPU_MAP_SIZE		(2 * SMALL_PAGE_SIZE)
#define IMEM_XPU_RG_START		UL(9)
#define IMEM_XPU_RG_COUNT		UL(2)

/* AP (secure + non-secure), TME ROM, and debug may read the DIAG log */
#define DIAG_XPU_READ_QAD \
	(QAD_ENV_APPS | QAD_TME_ROM | QAD_DEBUG)

#endif /* XPU_TARGET_H */
