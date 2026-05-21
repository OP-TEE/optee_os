// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <io.h>
#include <resource_table.h>
#include <stdint.h>
#include <string.h>

#include "dsp_fw.h"
#include "lpass.h"

#define LPASS_QDSP6V67SS_PUB_REG	0x00400000
#define LPASS_MCC_REG			0x00950000

static const struct fw_rsc_devmem lpass_mem_res[] = {
	{ .name = "efuse", .flags = IOMMU_READ,
		.da = 0x00786000, .pa = 0x00786000, .len = 0x00020000, },
	{ .name = "rng", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x010d4000, .pa = 0x010d4000, .len = 0x00001000, },
	{ .name = "mailbox", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x00403000, .pa = 0x00403000, .len = 0x00001000, },
	{ .name = "rpmh", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x0a000000, .pa = 0x0a000000, .len = 0x05000000, },
	{ .name = "tcsr_2", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x01fc0000, .pa = 0x01fc0000, .len = 0x00030000, },
	{ .name = "tcsr_mutex", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x01f40000, .pa = 0x01f40000, .len = 0x00020000, },
	{ .name = "smem", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x80900000, .pa = 0x80900000, .len = 0x00200000, },
	{ .name = "gcc", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x00100000, .pa = 0x00100000, .len = 0x001F0000, },
	{ .name = "cmd_db", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x80860000, .pa = 0x80860000, .len = 0x00020000, },
	{ .name = "i2c", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x00a80000, .pa = 0x00a80000, .len = 0x00004000, },
	{ .name = "pinctrl", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x0f100000, .pa = 0x0f100000, .len = 0x00300000, },
};

DEFINE_RESOURCE_TABLE(LPASS, ARRAY_SIZE(lpass_mem_res));

static TEE_Result lpass_fw_start(struct qcom_pas_data *data)
{
	const struct dsp_fw_start_regs regs = {
		.boot_status = LPASS_QDSP6V67SS_PUB_REG + 0x408,
		.core_start = LPASS_QDSP6V67SS_PUB_REG + 0x400,
		.sleep_cbcr = LPASS_QDSP6V67SS_PUB_REG + 0x3c,
		.lpass.efuse_evb_sel = LPASS_MCC_REG + 0xb000,
		.core_cbcr = LPASS_QDSP6V67SS_PUB_REG + 0x20,
		.boot_cmd = LPASS_QDSP6V67SS_PUB_REG + 0x404,
		.xo_cbcr = LPASS_QDSP6V67SS_PUB_REG + 0x38,
		.rst_evb = LPASS_QDSP6V67SS_PUB_REG + 0x10,
	};
	vaddr_t base = 0;

	base = io_pa_or_va(&data->base, data->size);
	if (!base)
		return TEE_ERROR_GENERIC;

	io_write32(base + regs.lpass.efuse_evb_sel, 0);

	return dsp_fw_start(data, &regs);
}

static TEE_Result lpass_fw_shutdown(struct qcom_pas_data *data __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

static TEE_Result lpass_get_resource_table(struct resource_table *rt,
					   size_t *rt_size)
{
	const struct fw_rsc_hdr header = {
		.type = RSC_DEVMEM,
	};
	static struct resource_table table = {
		.ver = 1,
		.num = LPASS_NUM_MEM_RESOURCES,
		.offset[LPASS_NUM_MEM_RESOURCES - 1] = 0,
	};

	return get_mem_rsc(rt, rt_size, &table, &header,
			   lpass_mem_res,
			   LPASS_RESOURCE_TABLE_HEADER_SIZE,
			   LPASS_RESOURCE_TABLE_SIZE);
}

const struct qcom_pas_ops lpass_ops = {
	.fw_start = lpass_fw_start,
	.fw_shutdown = lpass_fw_shutdown,
	.get_resource_table = lpass_get_resource_table,
};
