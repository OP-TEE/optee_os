/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef XPU_TARGET_H
#define XPU_TARGET_H

/* MACHX_LLCC_MPU: resource groups 30..39 are free for runtime allocation */
#define DDR_MPU_BASE			UL(0x4060000)
#define DDR_MPU_ADDR_OFFSET		UL(0x0)
#define DDR_XPU_RG_START		UL(30)
#define DDR_XPU_RG_COUNT		UL(10)

/*
 * OCIMEM_MPU register window. The base is well below CORE_MMU_PGDIR_SIZE,
 * so a pgdir-granularity mapping would round it down to address 0 and a
 * small explicit range is mapped instead. Resource groups 6..9 are free
 * for runtime allocation.
 */
#define IMEM_MPU_BASE			UL(0x54000)
#define IMEM_MPU_MAP_SIZE		(2 * SMALL_PAGE_SIZE)
#define IMEM_XPU_RG_START		UL(6)
#define IMEM_XPU_RG_COUNT		UL(4)

/*
 * AP (secure + non-secure), TME ROM, debug, AP boot loader, modem, and
 * PRIME may read the DIAG log.
 */
#define DIAG_XPU_READ_QAD \
	(QAD_ENV_APPS | QAD_TME_ROM | QAD_DEBUG | QAD_AP_QC_BL | QAD_MSA | \
	 QAD_PRIME)

#endif /* XPU_TARGET_H */
