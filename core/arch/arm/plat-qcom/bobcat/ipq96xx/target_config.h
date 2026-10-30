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

#if defined(CFG_QCOM_TMEL_AUTH)
/* TME-Lite secure authentication request version supported by this SoC */
#define TMEL_AUTH_VERSION			2
#endif

#if defined(CFG_QCOM_TMEL_KM)
/* TCSR hardware key fuse registers for key management */
#define CFG_TCSR_FUSE_PRI_HW_KEY_BASE_START	UL(0x193D404)
#define CFG_TCSR_FUSE_PRI_HW_KEY_REG_COUNT	8
#define CFG_TCSR_FUSE_SEC_HW_KEY_BASE_START	UL(0x193D424)
#define CFG_TCSR_FUSE_SEC_HW_KEY_REG_COUNT	8
#endif

#endif /* TARGET_CONFIG_H */
