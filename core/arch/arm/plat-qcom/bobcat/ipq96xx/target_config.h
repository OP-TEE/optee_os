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

/*
 * QMP-Lite mailbox — OP-TEE ↔ TME communication
 *
 * Inbound  (OP-TEE → TME): OP-TEE writes outgoing messages to this region.
 * Outbound (TME → OP-TEE): OP-TEE reads incoming messages from this region.
 *
 * Addresses from the IPQ96xx TRM.
 */
#define TME_QMP_LITE_INBOUND_MBOX_ADDR		UL(0x22090000)
#define TME_QMP_LITE_OUTBOUND_MBOX_ADDR		UL(0x22091000)

/* Mailbox payload capacity in bytes (≤ QMP_LITE_MAX_MSG_SIZE = 255). */
#define TME_QMP_LITE_MBOX_SIZE			32U

/* Incoming Interrupt: TME → OP-TEE */
#define TME_QMP_LITE_IRQ_IN			154u

/* Outgoing Interrupt: OP-TEE → TME (APCS_*_TZ_IPC_INTERRUPT) */
#define TME_QMP_LITE_IRQ_OUT_REG_ADDR		UL(0x0F400008)
#define TME_QMP_LITE_IRQ_OUT_BIT_MASK		0x00200000U

#endif /* TARGET_CONFIG_H */
