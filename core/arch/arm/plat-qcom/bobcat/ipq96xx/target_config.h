/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef TARGET_CONFIG_H
#define TARGET_CONFIG_H

#define GENI_UART_REG_BASE		UL(0x1A98000)

#define DRAM0_BASE			UL(0x80000000)
#define DRAM0_SIZE			UL(0x80000000)
#define DRAM1_BASE			ULL(0x800000000)
#define DRAM1_SIZE			ULL(0x380000000)

#define GICD_BASE			UL(0xF200000)
#define GICR_BASE			UL(0xF240000)

#define IMEM_BASE			UL(0x8600000)
#define IMEM_SIZE			UL(0x20000)

#define QCOM_WDT_TMR_BASE		UL(0x0F411000)
#define QCOM_WDT_BARK_INT_ID		UL(0x36)

#if defined(CFG_QCOM_TMEL_KM)
/* TCSR hardware key fuse registers for key management */
#define CFG_TCSR_FUSE_PRI_HW_KEY_BASE_START	UL(0x193D404)
#define CFG_TCSR_FUSE_PRI_HW_KEY_REG_COUNT	8
#define CFG_TCSR_FUSE_SEC_HW_KEY_BASE_START	UL(0x193D424)
#define CFG_TCSR_FUSE_SEC_HW_KEY_REG_COUNT	8
#endif

#endif /* TARGET_CONFIG_H */
