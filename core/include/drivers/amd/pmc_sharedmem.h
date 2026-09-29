/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Advanced Micro Devices, Inc. All rights reserved.
 *
 */

#ifndef __PMC_SHAREDMEM_H__
#define __PMC_SHAREDMEM_H__

#include <stdint.h>

/* Run-Time Configuration Area (RTCA) base; populated by PLM at boot. */
#define PMC_RTCA_BASEADDR		0xF2014000U

/*
 * PLM version register; packed as
 * Major[31:24] | Minor[23:16] | RC[15:8] | UserDefined[7:0].
 */
#define PMC_RTCA_VERSION_OFFSET		0x320U

#define PMC_VERSION_MAJOR_SHIFT		24U
#define PMC_VERSION_MAJOR_MASK		0xFF000000U
#define PMC_VERSION_MINOR_SHIFT		16U
#define PMC_VERSION_MINOR_MASK		0x00FF0000U

#endif /* __PMC_SHAREDMEM_H__ */
