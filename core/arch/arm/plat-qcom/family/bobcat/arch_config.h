/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef ARCH_CONFIG_H
#define ARCH_CONFIG_H

#define IMEM_DIAG_OFFSET		UL(0x730)
#define DIAG_SIZE			UL(0x6000)
#define DIAG_BASE			UL(0x8608000)
#define DIAG_LOG_START_INFO		(IMEM_BASE + IMEM_DIAG_OFFSET)
#define TCSR_BOOT_MISC_DETECT		UL(0x195C100)

#if defined(CFG_QCOM_MBOX)
/* In bytes; at most QMP_LITE_MAX_MSG_SIZE (255) */
#define TME_QMP_LITE_MBOX_SIZE		32U
#endif

#if defined(CFG_QCOM_TMEL_HUK)
#define QCOM_SERIAL_NUM_FUSE_ADDR	UL(0xA60A8)
#endif

#if defined(CFG_QCOM_TMEL_KM)
#define TCSR_FUSE_PRI_HW_KEY_BASE_START	UL(0x193D404)
#define TCSR_FUSE_PRI_HW_KEY_REG_COUNT	8
#define TCSR_FUSE_SEC_HW_KEY_BASE_START	UL(0x193D424)
#define TCSR_FUSE_SEC_HW_KEY_REG_COUNT	8
#endif

#define TMEL_COM_IPC_BUF_ADDR		(CFG_TZDRAM_START + CFG_TZDRAM_SIZE)

#endif /* ARCH_CONFIG_H */
