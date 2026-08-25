/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef TARGET_CONFIG_H
#define TARGET_CONFIG_H

#define GENI_UART_REG_BASE		UL(0x1A84000)

#define DRAM0_BASE			UL(0x80000000)
#define DRAM0_SIZE			UL(0x80000000)
#define DRAM1_BASE			ULL(0x800000000)
#define DRAM1_SIZE			UL(0x80000000)

#define GICD_BASE			UL(0xB000000)
#define GICC_BASE			UL(0xB002000)
#define GICD_PIDR2			UL(0xFD8)

#define IMEM_BASE			UL(0x8600000)
#define IMEM_SIZE			UL(0x18000)

#define QCOM_RNG_REG_BASE		UL(0x4C5000)

#define QCOM_WDT_TMR_BASE		UL(0x0B117000)
#define QCOM_WDT_BARK_INT_ID		UL(0x23)

#define QCOM_EL3_INTR_DELEGATION_SVC_ID	UL(0x02001D03)
#define NON_SEC_WDOG_BITE_INT_ID	UL(0x136)
#define XPU_VIOLATION_INT_ID		UL(0xB1)
#define RESET_SGI_INT_ID		UL(0xF)
#define MEMNOC_ERROR_INT_ID		UL(0x3A)
#define C1_NOC_ERROR_INT_ID		UL(0x3B)
#define C2_NOC_ERROR_INT_ID		UL(0x3C)
#define SNOC_ERROR_INT_ID		UL(0x9D)
#define NSS_NOC_ERROR_INT_ID		UL(0xF2)

#endif /* TARGET_CONFIG_H */
