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

/*
 * QMP-Lite mailbox — OP-TEE ↔ TME communication
 *
 * Inbound  (OP-TEE → TME): OP-TEE writes outgoing messages to this region.
 * Outbound (TME → OP-TEE): OP-TEE reads incoming messages from this region.
 *
 * Addresses from the IPQ52xx TRM.
 */
#define TME_QMP_LITE_INBOUND_MBOX_ADDR		UL(0x32090000)
#define TME_QMP_LITE_OUTBOUND_MBOX_ADDR		UL(0x32091000)

/* Mailbox payload capacity in bytes (≤ QMP_LITE_MAX_MSG_SIZE = 255). */
#define TME_QMP_LITE_MBOX_SIZE			32U

/* Incoming Interrupt: TME → OP-TEE */
#define TME_QMP_LITE_IRQ_IN			100u

/* Outgoing Interrupt: OP-TEE → TME (APCS_*_TZ_IPC_INTERRUPT) */
#define TME_QMP_LITE_IRQ_OUT_REG_ADDR		UL(0x0B111004)
#define TME_QMP_LITE_IRQ_OUT_BIT_MASK		0x00200000U

#if defined(CFG_QCOM_TMEL_KM)
/* TCSR hardware key fuse registers for key management */
#define CFG_TCSR_FUSE_PRI_HW_KEY_BASE_START	UL(0x193D404)
#define CFG_TCSR_FUSE_PRI_HW_KEY_REG_COUNT	8
#define CFG_TCSR_FUSE_SEC_HW_KEY_BASE_START	UL(0x193D424)
#define CFG_TCSR_FUSE_SEC_HW_KEY_REG_COUNT	8
#endif

#endif /* TARGET_CONFIG_H */
