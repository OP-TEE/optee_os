/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2024, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef _IRIS_H_
#define _IRIS_H_

#include "pas_subsys.h"

#define IRIS_WRAPPER_TOP_REG_BASE	0x000b0000
#define IRIS_WRAPPER_TZ_REG_BASE	0x000c0000
#define IRIS_CORE0_TZ_REG_BASE		0x000c2000
#define IRIS_CORE1_TZ_REG_BASE		0x000c3000

#define IRIS_CLK_SETTLE_US		1U

extern const struct qcom_pas_ops iris_ops;

#endif /* _IRIS_H_ */
