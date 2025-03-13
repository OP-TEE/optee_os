/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2025, Linaro Limited
 */

#ifndef _CLK_QCOM_H_
#define _CLK_QCOM_H_

#include <stdint.h>
#include <tee_api_types.h>

enum qcom_clk_group {
	QCOM_CLKS_WPSS,

	QCOM_CLKS_MAX,
};

TEE_Result qcom_clock_enable(enum qcom_clk_group group);

#endif /* _CLK_QCOM_H_ */
