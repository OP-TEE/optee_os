/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef EL3_INTR_DELEGATION_H
#define EL3_INTR_DELEGATION_H

#ifdef CFG_QCOM_EL3_INTR_DELEGATION
void el3_intr_delegation_init_per_cpu(void);
#else
static inline void el3_intr_delegation_init_per_cpu(void) { }
#endif

#endif /* EL3_INTR_DELEGATION_H */
