/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2024, Linaro Limited
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#include <mm/generic_ram_layout.h>
#include <arch_config.h>
#include <target_config.h>

/* Make stacks aligned to data cache line length */
#define STACK_ALIGNMENT			64

#define MAX_XLAT_TABLES		(40 + (CFG_RESERVED_VASPACE_SIZE) / \
				 (CORE_MMU_PGDIR_SIZE) + 5)

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

#endif /*PLATFORM_CONFIG_H*/
