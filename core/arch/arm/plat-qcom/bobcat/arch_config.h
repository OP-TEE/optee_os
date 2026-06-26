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

#endif /* ARCH_CONFIG_H */
