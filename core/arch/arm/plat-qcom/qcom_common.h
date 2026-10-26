/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __QCOM_COMMON_H
#define __QCOM_COMMON_H

#include <compiler.h>
#include <config.h>
#include <platform_config.h>
#include <stdbool.h>
#include <tee_api_types.h>
#include <util.h>

/* Diagnostic log */
#if defined(CFG_QCOM_DIAG_LOG)
void qcom_diag_log_init(void);
void qcom_diag_log_puts(const char *str);
#else
static inline void qcom_diag_log_init(void) { }
static inline void qcom_diag_log_puts(const char *str __unused) { }
#endif

/* GICv2 EL3 interrupt delegation */
#if defined(CFG_QCOM_GICV2_EL3_INTR_DELEGATION)
void qcom_gicv2_el3_intr_delegation_init(void);
void qcom_gicv2_el3_intr_delegation_init_per_cpu(void);
#else
static inline void qcom_gicv2_el3_intr_delegation_init(void) { }
static inline void qcom_gicv2_el3_intr_delegation_init_per_cpu(void) { }
#endif

/* Boot mode */
TEE_Result qcom_is_dload_mode(bool *enabled);

#endif /* __QCOM_COMMON_H */
