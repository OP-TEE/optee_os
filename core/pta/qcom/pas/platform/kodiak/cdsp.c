// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <io.h>
#include <resource_table.h>
#include <stdint.h>
#include <string.h>

#include "cdsp.h"
#include "dsp_fw.h"

#define TURING_QDSP6V68SS_PUB_REG	0x00b00000
#define TURING_QDSP6V68SS_CC_REG	0x00b18000
#define TURING_QDSP6SS_Q6_CC_REG	0x00b40000

static const struct fw_rsc_devmem turing_mem_res[] = {
	{ .name = "tcsr_2", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x01fc0000, .pa = 0x01fc0000, .len = 0x00030000, },
	{ .name = "tcsr_mutex", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x01f40000, .pa = 0x01f40000, .len = 0x00020000, },
	{ .name = "efuse", .flags = IOMMU_READ,
		.da = 0x00780000, .pa = 0x00780000, .len = 0x0000A000, },
	{ .name = "mailbox", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x406000, .pa = 0x406000, .len = 0x00001000, },
	{ .name = "smem", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x80900000, .pa = 0x80900000, .len = 0x00200000, },
	{ .name = "cmd_db", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x80860000, .pa = 0x80860000, .len = 0x00020000, },
	{ .name = "aoss_msg_ram", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x0c300000, .pa = 0x0c300000, .len = 0x00100000, },
	{ .name = "clk_ctl", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x00100000, .pa = 0x00100000, .len = 0x001f0000, },
	{ .name = "rpmh_pdc", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x0b2b0000, .pa = 0x0b2b0000, .len = 0x00010000, },
	{ .name = "rpmh_seqmem", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x0b4b0000, .pa = 0x0b4b0000, .len = 0x00010000, },
	{ .name = "rpmh_bcm", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x0bbf0000, .pa = 0x0bbf0000, .len = 0x0002000, },
	{ .name = "ddr_reg", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x09080000, .pa = 0x09080000, .len = 0x00001000, },
	{ .name = "llcc_bdcast", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x09600000, .pa = 0x09600000, .len = 0x00058000, },
	{ .name = "llcc0", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x09200000, .pa = 0x09200000, .len = 0x00058000, },
	{ .name = "llcc1", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x09280000, .pa = 0x09280000, .len = 0x00058000, },
	{ .name = "rdpm", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x00634000, .pa = 0x00634000, .len = 0x00004000, },
};

DEFINE_RESOURCE_TABLE(TURING, ARRAY_SIZE(turing_mem_res));

static TEE_Result cdsp_fw_start(struct qcom_pas_data *data)
{
	const struct dsp_fw_start_regs regs = {
		.boot_status = TURING_QDSP6V68SS_PUB_REG + 0x408,
		.core_start = TURING_QDSP6V68SS_PUB_REG + 0x400,
		.core_cbcr = TURING_QDSP6SS_Q6_CC_REG + 0x1040,
		.sleep_cbcr = TURING_QDSP6V68SS_CC_REG + 0x58,
		.boot_cmd = TURING_QDSP6V68SS_PUB_REG + 0x404,
		.rst_evb = TURING_QDSP6V68SS_PUB_REG + 0x10,
		.xo_cbcr = TURING_QDSP6V68SS_CC_REG + 0x54,
	};

	return dsp_fw_start(data, &regs);
}

static TEE_Result cdsp_fw_shutdown(struct qcom_pas_data *data __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

static TEE_Result cdsp_get_resource_table(struct resource_table *rt,
					  size_t *rt_size)
{
	const struct fw_rsc_hdr header = {
		.type = RSC_DEVMEM,
	};
	static struct resource_table table = {
		.ver = 1,
		.num = TURING_NUM_MEM_RESOURCES,
		.offset[TURING_NUM_MEM_RESOURCES - 1] = 0,
	};

	return get_mem_rsc(rt, rt_size, &table, &header,
			   turing_mem_res,
			   TURING_RESOURCE_TABLE_HEADER_SIZE,
			   TURING_RESOURCE_TABLE_SIZE);
}

const struct qcom_pas_ops cdsp_ops = {
	.fw_start = cdsp_fw_start,
	.fw_shutdown = cdsp_fw_shutdown,
	.get_resource_table = cdsp_get_resource_table,
};
