/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */


#ifndef __RPM_TARGET_H__
#define __RPM_TARGET_H__

#include <util.h>

/* MSG RAM (rpm_porting_notes.md Section 1). */
#define RPM_MSG_RAM_BASE		UL(0x045f0000)
#define RPM_MSG_RAM_SIZE		UL(0x7000)

/* IPCC doorbell (rpm_porting_notes.md Section 4). */
#define RPM_IPCC_BASE			UL(0xf400000)
#define RPM_IPCC_PROTOCOL_MPROC		0
#define RPM_IPCC_CLIENT_AOP		0 /* RPM/AOP side */
#define RPM_IPCC_CLIENT_TZ		1 /* this side */
#define RPM_IPCC_RPM_SIGNAL_IDX		0
#define RPM_IPCC_RPM_GIC_IRQ		12

#define RPM_IPCC_LEGACY_AOP_OFFS	0x8
#define RPM_IPCC_LEGACY_AOP_MASK	0x1

#endif /* __RPM_TARGET_H__ */
