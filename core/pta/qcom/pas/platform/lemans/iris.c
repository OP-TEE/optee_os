// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <util.h>

#include "iris.h"

#define WRAPPER_SEC_CSR1			0x000b1084
#define WRAPPER_SEC_CSR7			0x000b109c

/* Written before every release */
static const struct pas_iris_write after_clear[] = {
	PAS_IRIS_WRITE(WRAPPER_SEC_CSR1, 1),
};

static const struct pas_iris_write after_thresholds[] = {
	PAS_IRIS_WRITE(SS_TZ_SEC_THRESHOLD_AV1, 1280),
};

static const struct pas_iris_write after_checks[] = {
	PAS_IRIS_CHECK(SS_TZ_SEC_SID_F_SECURE_OVERRIDE, 1),
	PAS_IRIS_WRITE(SS_TZ_SEC_SID_C_SECURE_OVERRIDE, 1),
	PAS_IRIS_WRITE(SS_TZ_SEC_SID_D_SECURE_OVERRIDE, 1),
	PAS_IRIS_WRITE(SS_TZ_SEC_SID_E_SECURE_OVERRIDE, 1),
	PAS_IRIS_WRITE(WRAPPER_SEC_CSR7, 1),
};

const struct pas_iris_cfg iris_cfg = {
	.after_clear = { after_clear, ARRAY_SIZE(after_clear) },
	.after_thresholds = { after_thresholds, ARRAY_SIZE(after_thresholds) },
	.after_checks = { after_checks, ARRAY_SIZE(after_checks) },
	.every_release = true,
};
