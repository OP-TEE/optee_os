/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __RPM_TARGET_H__
#define __RPM_TARGET_H__

#include <util.h>

#define RPM_MSG_RAM_BASE		UL(0x045f0000)
#define RPM_MSG_RAM_SIZE		UL(0x7000)

#define RPM_IPCC_LEGACY_BASE		UL(0xf400000)

#define RPM_IPCC_LEGACY_RPM_FW_OFFS	0x8
#define RPM_IPCC_LEGACY_RPM_FW_MASK	0x1

#endif /* __RPM_TARGET_H__ */
