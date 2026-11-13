/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef ARCH_CONFIG_H
#define ARCH_CONFIG_H

#define GICD_BASE			UL(0x0f200000)

#define HWKM_MASTER_BASE		UL(0x04440000)
#define HWKM_MASTER_SIZE		UL(0x00020000)

#define HWKM_CRYPTO0_BASE		UL(0x01b00000)
#define HWKM_CRYPTO0_SIZE		UL(0x00040000)

#define HWKM_SDC1_SDCC_ICE_BASE		UL(0x04748000)
#define HWKM_SDC1_SDCC_ICE_SIZE		UL(0x00018000)

#endif /* ARCH_CONFIG_H */
