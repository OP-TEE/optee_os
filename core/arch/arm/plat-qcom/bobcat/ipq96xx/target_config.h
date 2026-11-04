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

/* CDSP (Turing/NSP) PAS register windows. */
#define GCC_BASE			UL(0x01800000)
#define GCC_SIZE			UL(0x00080000)

#define TURING_BASE			UL(0x26000000)
#define TURING_SIZE			UL(0x00400000)

#define MPM2_MPM_BASE			UL(0x004A0000)
#define MPM2_MPM_SIZE			UL(0x00010000)

#define TCSR_SPARE_BASE			UL(0x01959000)
#define TCSR_SPARE_SIZE			UL(0x00001000)

#define CDSP_TCSR_BASE			UL(0x01966000)
#define CDSP_TCSR_SIZE			UL(0x00001000)

#endif /* TARGET_CONFIG_H */
