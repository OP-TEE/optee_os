/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * BRUIN family (QCM2290 / QRB2210, SM4125 Agatti) arch config for OP-TEE.
 */

#ifndef ARCH_CONFIG_H
#define ARCH_CONFIG_H

/* GIC-500 (GICv3). GICC_BASE is unused with CFG_ARM_GICV3=y. */
#define GICD_BASE			UL(0x0F200000)
#define GICR_BASE			UL(0x0F300000)
#define GICC_BASE			UL(0x0F200000)

/* Diag-log region (only used when CFG_QCOM_DIAG_LOG=y). */
#define IMEM_DIAG_OFFSET		UL(0x720)
#define DIAG_SIZE			UL(0x3000)
#define DIAG_BASE			(IMEM_BASE + IMEM_SIZE - DIAG_SIZE)
#define DIAG_LOG_START_INFO		(IMEM_BASE + IMEM_DIAG_OFFSET)

/* TCSR boot-misc (forced-dload detect). */
#define TCSR_BOOT_MISC_DETECT		UL(0x01FD3000)

#endif /* ARCH_CONFIG_H */
