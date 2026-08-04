/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef XPUV4_H
#define XPUV4_H

#include <util.h>

/*
 * QAD vector for the secure APPS domain: bit 0 = QAD_APPS identifier,
 * bit 31 = secure qualifier.
 */
#define QAD_APPS_SEC		(BIT32(0) | BIT32(31))

/*
 * AP execution-environment QAD vector (secure + non-secure APPS).
 */
#define QAD_ENV_APPS		(BIT32(0) | BIT32(31) | BIT32(30))

/*
 * Per-master QAD identifiers, so read/write policy vectors in platform
 * config spell out which masters have access instead of an opaque hex
 * literal. Identifiers and their meaning come from the XPU4 static QAD
 * assignment; not every identifier is wired to a real master on every SoC.
 */
#define QAD_TME_ROM		BIT32(1)
#define QAD_DEBUG		BIT32(3)
#define QAD_AP_QC_BL		BIT32(4)
#define QAD_MSA			BIT32(5)
#define QAD_PRIME		BIT32(6)

#endif /* XPUV4_H */
