/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2022, Foundries.io Ltd
 *
 * Copyright (C) 2023 ProvenRun S.A.S
 */

#ifndef __DRIVERS_VERSAL_PMC_H
#define __DRIVERS_VERSAL_PMC_H

#include <drivers/versal_mbox.h>

TEE_Result versal_pmc_notify(struct versal_ipi_cmd *cmd,
			     struct versal_ipi_cmd *rsp, uint32_t *err);

#endif
