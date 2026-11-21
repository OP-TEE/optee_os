// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <io.h>
#include <resource_table.h>
#include <stdint.h>
#include <string.h>

#include "dsp_fw.h"
#include "wpss.h"

#define WPSS_QDSP6V67SS_PUB_REG	0x00000000

static const struct fw_rsc_devmem wpss_mem_res[] = {
	{ .name = "wlan_fw_mem", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x80c00000, .pa = 0x80c00000, .len = 0xc00000, },
	{ .name = "wlan_ce_mem", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x004cd000, .pa = 0x004cd000, .len = 0x1000, },
};

static TEE_Result wpss_fw_start(struct qcom_pas_data *data)
{
	static const struct dsp_fw_start_regs regs = {
		.sleep_cbcr = WPSS_QDSP6V67SS_PUB_REG + 0x3c,
		.core_cbcr = WPSS_QDSP6V67SS_PUB_REG + 0x20,
		.qdsp6ss = WPSS_QDSP6V67SS_PUB_REG,
		.xo_cbcr = WPSS_QDSP6V67SS_PUB_REG + 0x38,
	};

	return dsp_fw_start(data, &regs);
}

static TEE_Result wpss_fw_shutdown(struct qcom_pas_data *data __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

const struct qcom_pas_ops wpss_ops = {
	.fw_start = wpss_fw_start,
	.fw_shutdown = wpss_fw_shutdown,
	.devmem = wpss_mem_res,
	.devmem_num = ARRAY_SIZE(wpss_mem_res),
};
