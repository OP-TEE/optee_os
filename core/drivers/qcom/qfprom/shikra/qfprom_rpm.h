/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __QFPROM_RPM_H__
#define __QFPROM_RPM_H__

#include <tee_api_types.h>

TEE_Result qfprom_rpm_enable(void);
TEE_Result qfprom_rpm_disable(void);

#endif /* __QFPROM_RPM_H__ */
