/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef DRIVERS_QCOM_XPU_H
#define DRIVERS_QCOM_XPU_H

#include <tee_api_types.h>
#include <types_ext.h>

/*
 * Restrict [start, start + size) to the given read/write QAD permission
 * vectors and lock it. start and size must be 4KB aligned, size non-zero.
 */
TEE_Result xpu_protect_region(paddr_t start, size_t size,
			      uint32_t read_perm, uint32_t write_perm);

#endif /* DRIVERS_QCOM_XPU_H */
