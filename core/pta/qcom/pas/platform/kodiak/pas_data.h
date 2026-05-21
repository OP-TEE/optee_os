/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2025, Linaro Limited
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef _PAS_DATA_H_
#define _PAS_DATA_H_

#include <drivers/clk_qcom.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <stdint.h>

struct qcom_pas_data {
	uint32_t pas_id;
	struct io_pa_va base;
	size_t size;
	paddr_t fw_base;
	size_t fw_size;
	enum qcom_clk_group clk_group;
};

#endif /* _PAS_DATA_H_ */
