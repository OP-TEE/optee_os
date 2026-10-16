/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef GICV2_EL3_INTR_DELEGATION_H
#define GICV2_EL3_INTR_DELEGATION_H

#ifdef CFG_QCOM_GICV2_EL3_INTR_DELEGATION
void qcom_gicv2_el3_intr_delegation_init_per_cpu(void);
#else
static inline void qcom_gicv2_el3_intr_delegation_init_per_cpu(void) { }
#endif

#endif /* GICV2_EL3_INTR_DELEGATION_H */
