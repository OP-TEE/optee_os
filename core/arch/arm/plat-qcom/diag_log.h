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

#if defined(CFG_QCOM_DIAG_LOG)
void qcom_diag_log_init(void);
void qcom_diag_log_puts(const char *str);
#else
static inline void qcom_diag_log_init(void) { }
static inline void qcom_diag_log_puts(const char *str __unused) { }
#endif

#endif /* __DIAG_LOG_H */
