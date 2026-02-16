/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef _DSP_H_
#define _DSP_H_

#include "pas.h"

struct dsp_fw_boot_regs {
	uint32_t xo_cbcr;
	uint32_t sleep_cbcr;
	uint32_t core_cbcr;
	uint32_t rst_evb;
	uint32_t core_start;
	uint32_t boot_cmd;
	uint32_t boot_status;
};

TEE_Result dsp_fw_start(struct qcom_pas_data *data,
			const struct dsp_fw_boot_regs *regs);

#endif /* _DSP_H_ */
