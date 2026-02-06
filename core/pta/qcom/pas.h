/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2025, Linaro Limited
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef _PAS_H_
#define _PAS_H_

#include <kernel/thread_arch.h>
#include <mm/core_memprot.h>
#include <drivers/clk_qcom.h>

struct qcom_pas_data {
	struct io_pa_va base;
	size_t size;
	paddr_t fw_base;
	size_t fw_size;
	enum qcom_clk_group clk_group;
};

TEE_Result wpss_dsp_start(struct qcom_pas_data *data);

#endif /* _PAS_H_ */
