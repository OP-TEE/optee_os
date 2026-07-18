/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2025, Linaro Limited
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef _PAS_DATA_H_
#define _PAS_DATA_H_

#include <drivers/clk_qcom.h>
#include <mm/core_memprot.h>
#include <stdint.h>

#define PAS_ID_QDSP6		1
#define PAS_ID_WPSS		6
#define PAS_ID_IRIS		9
#define PAS_ID_TURING		18
#define PAS_ID_TURING1		30
#define PAS_ID_GPDSP0		39
#define PAS_ID_GPDSP1		40

struct qcom_pas_data {
	uint32_t pas_id;
	struct io_pa_va base;
	size_t size;
	paddr_t fw_base;
	size_t fw_size;
	enum qcom_clk_group clk_group;
};

#endif /* _PAS_DATA_H_ */
