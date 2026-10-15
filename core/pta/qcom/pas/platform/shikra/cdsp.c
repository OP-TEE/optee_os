// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <io.h>
#include <platform_config.h>
#include <resource_table.h>
#include <stdint.h>
#include <string.h>

#include "cdsp.h"

/*
 * RST_EVB lives at offset 0x10 into the QDSP6SS PUB register block, which
 * itself starts at TURING_BASE + 0x300000 (see clock_group_qcom.h's
 * TURING_QDSP6SS_DBG_CFG/RET_CFG at +0x300018/+0x30001c for the same block).
 */
#define TURING_QDSP6SS_RST_EVB		0x300010

static const struct fw_rsc_devmem cdsp_mem_res[] = { };

DEFINE_RESOURCE_TABLE(CDSP, ARRAY_SIZE(cdsp_mem_res));

static TEE_Result cdsp_fw_start(struct qcom_pas_data *data)
{
	vaddr_t base = io_pa_or_va(&data->base, data->size);

	if (!base)
		return TEE_ERROR_GENERIC;

	/*
	 * Program the firmware entry point. The core itself is released
	 * later, once the Q6 PLL is configured, by
	 * qcom_clock_enable_pas_processor().
	 */
	io_write32(base + TURING_QDSP6SS_RST_EVB, data->fw_base >> 4);
	dsb();

	return TEE_SUCCESS;
}

static TEE_Result cdsp_fw_shutdown(struct qcom_pas_data *data)
{
	return qcom_clock_pas_reset(data->clk_group);
}

static TEE_Result cdsp_get_resource_table(struct resource_table *rt,
					  size_t *rt_size)
{
	const struct fw_rsc_hdr header = {
		.type = RSC_DEVMEM,
	};
	static struct resource_table table = {
		.ver = 1,
		.num = CDSP_NUM_MEM_RESOURCES,
	};

	return get_mem_rsc(rt, rt_size, &table, &header,
			   cdsp_mem_res,
			   CDSP_RESOURCE_TABLE_HEADER_SIZE,
			   CDSP_RESOURCE_TABLE_SIZE);
}

const struct qcom_pas_ops cdsp_ops = {
	.fw_start = cdsp_fw_start,
	.fw_shutdown = cdsp_fw_shutdown,
	.get_resource_table = cdsp_get_resource_table,
};
