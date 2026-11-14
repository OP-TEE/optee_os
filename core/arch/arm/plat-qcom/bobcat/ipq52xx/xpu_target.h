/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef XPU_TARGET_H
#define XPU_TARGET_H

#include <drivers/qcom/xpuv4.h>

/* TZDRAM is secure-APPS only, for both read and write */
#define TZDRAM_XPU_READ_QAD		QAD_APPS_SEC
#define TZDRAM_XPU_WRITE_QAD		QAD_APPS_SEC

/* Only secure APPS may write the DIAG log */
#define DIAG_XPU_WRITE_QAD		QAD_APPS_SEC

/* MEMNOC_SCH_MPU: resource groups 10..15 are free for runtime allocation */
#define DDR_MPU_BASE			UL(0xAC0000)
/*
 * The MPU does not see the DRAM at its physical addresses. It sees the two
 * DRAM windows, the one below 4 GiB and the one above it, placed back to
 * back from address 0. These macros turn a physical address of the first and
 * of the second window into the address that the MPU has for it.
 */
#define DDR_MPU_ADDR_LOW(pa)		((pa) - UL(0x80000000))
#define DDR_MPU_ADDR_HIGH(pa)		((pa) - ULL(0x780000000))
#define DDR_XPU_RG_START		UL(10)
#define DDR_XPU_RG_COUNT		UL(6)

/* Convert a physical DRAM address into the address the DDR MPU uses */
static inline paddr_t ddr_mpu_addr(paddr_t pa)
{
	return pa < ULL(0x100000000) ? DDR_MPU_ADDR_LOW(pa) :
				       DDR_MPU_ADDR_HIGH(pa);
}

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
