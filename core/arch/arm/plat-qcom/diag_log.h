/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __DIAG_LOG_H
#define __DIAG_LOG_H

#include <compiler.h>
#include <config.h>
#include <platform_config.h>
#include <util.h>

void qcom_diag_log_init(void);
void qcom_diag_log_puts(const char *str);

#endif /* __DIAG_LOG_H */
