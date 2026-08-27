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

#if defined(CFG_QCOM_TMEL_HUK)
/* Serial-number fuse used as the die ID (identical across bobcat SoCs) */
#define QCOM_SERIAL_NUM_FUSE_ADDR	UL(0xA60A8)
#endif

#if defined(CFG_QCOM_TMEL_COM)
/*
 * Coherent carveout at the end of TZDRAM for TMEL IPC buffers.
 */
#define TMECOM_IPCBUF_CARVEOUT_SIZE	CFG_TMECOM_IPCBUF_CARVEOUT_SIZE
#define TMECOM_IPC_BUF_PA		\
	(CFG_TZDRAM_START + CFG_TZDRAM_SIZE - TMECOM_IPCBUF_CARVEOUT_SIZE)
#endif

#if defined(CFG_QCOM_TMEL_KM)
/* TCSR hardware key register addresses (set per-SoC in target_config.h) */
#define TCSR_FUSE_PRI_HW_KEY_BASE_START	CFG_TCSR_FUSE_PRI_HW_KEY_BASE_START
#define TCSR_FUSE_PRI_HW_KEY_REG_COUNT	CFG_TCSR_FUSE_PRI_HW_KEY_REG_COUNT
#define TCSR_FUSE_SEC_HW_KEY_BASE_START	CFG_TCSR_FUSE_SEC_HW_KEY_BASE_START
#define TCSR_FUSE_SEC_HW_KEY_REG_COUNT	CFG_TCSR_FUSE_SEC_HW_KEY_REG_COUNT
#endif

#endif /* ARCH_CONFIG_H */
