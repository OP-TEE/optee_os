// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <util.h>

#include "iris.h"

#define CPU_CS_VCICMD				0x000a0020

/* Written at start only, not on resume */
static const struct pas_iris_write before_checks[] = {
	PAS_IRIS_WRITE(SS_TZ_CP_VP8_SECURE_OVERRIDE_DEC, 0),
	PAS_IRIS_WRITE(SS_TZ_CP_VP9_SECURE_OVERRIDE_DEC, 0),
	PAS_IRIS_WRITE(SS_TZ_SEC_SID_F_SECURE_OVERRIDE, 1),
};

static const struct pas_iris_write after_checks[] = {
	PAS_IRIS_CHECK(CPU_CS_VCICMD, 1),
};

const struct pas_iris_cfg iris_cfg = {
	.before_checks = { before_checks, ARRAY_SIZE(before_checks) },
	.after_checks = { after_checks, ARRAY_SIZE(after_checks) },
};
