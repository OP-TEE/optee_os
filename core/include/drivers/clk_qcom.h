/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2025, Linaro Limited
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef _CLK_QCOM_H_
#define _CLK_QCOM_H_

#include <stdint.h>
#include <tee_api_types.h>

#define REG_POLL_TIMEOUT(_addr, _timeout_us, _delay_us, _retp, _match)	\
	do {								\
		uint32_t __val;						\
		int __rc;						\
									\
		__rc = IO_READ32_POLL_TIMEOUT(_addr, __val,		\
					     (_match)(__val),		\
					     _delay_us, _timeout_us);	\
		*(_retp) = __rc ? -1 : 0;				\
	} while (0)

enum qcom_clk_group {
	QCOM_CLKS_WPSS,
	QCOM_CLKS_TURING,
	QCOM_CLKS_LPASS,
	QCOM_CLKS_MAX,
};

TEE_Result qcom_clock_enable(enum qcom_clk_group group);
TEE_Result qcom_clock_enable_cbc(vaddr_t cbcr);
TEE_Result qcom_clock_enable_pas(enum qcom_clk_group group);

#endif /* _CLK_QCOM_H_ */
