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

static const struct fw_rsc_devmem cdsp_mem_res[] = {
	{ .name = "cdsp_0",  .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x00340000, .pa = 0x00340000, .len = 0x00040000 },
	{ .name = "cdsp_1",  .flags = IOMMU_READ,
		.da = 0x003c0000, .pa = 0x003c0000, .len = 0x0002b000 },
	{ .name = "cdsp_2",  .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x003eb000, .pa = 0x003eb000, .len = 0x00001000 },
	{ .name = "cdsp_3",  .flags = IOMMU_READ,
		.da = 0x003ec000, .pa = 0x003ec000, .len = 0x00004000 },
	{ .name = "cdsp_4",  .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x003f2000, .pa = 0x003f2000, .len = 0x00001000 },
	{ .name = "cdsp_5",  .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x003f8000, .pa = 0x003f8000, .len = 0x00001000 },
	{ .name = "cdsp_6",  .flags = IOMMU_READ,
		.da = 0x003f9000, .pa = 0x003f9000, .len = 0x00001000 },
	{ .name = "cdsp_7",  .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x00400000, .pa = 0x00400000, .len = 0x00800000 },
	{ .name = "cdsp_8",  .flags = IOMMU_READ,
		.da = 0x01400000, .pa = 0x01400000, .len = 0x00004000 },
	{ .name = "cdsp_9",  .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x01404000, .pa = 0x01404000, .len = 0x00001000 },
	{ .name = "cdsp_10", .flags = IOMMU_READ,
		.da = 0x01405000, .pa = 0x01405000, .len = 0x0000b000 },
	{ .name = "cdsp_11", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x01410000, .pa = 0x01410000, .len = 0x00001000 },
	{ .name = "cdsp_12", .flags = IOMMU_READ,
		.da = 0x01411000, .pa = 0x01411000, .len = 0x00001000 },
	{ .name = "cdsp_13", .flags = IOMMU_READ,
		.da = 0x01413000, .pa = 0x01413000, .len = 0x00004000 },
	{ .name = "cdsp_14", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x01417000, .pa = 0x01417000, .len = 0x00002000 },
	{ .name = "cdsp_15", .flags = IOMMU_READ,
		.da = 0x01419000, .pa = 0x01419000, .len = 0x00006000 },
	{ .name = "cdsp_16", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x0141f000, .pa = 0x0141f000, .len = 0x00001000 },
	{ .name = "cdsp_17", .flags = IOMMU_READ,
		.da = 0x01420000, .pa = 0x01420000, .len = 0x00008000 },
	{ .name = "cdsp_18", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x01428000, .pa = 0x01428000, .len = 0x001c8000 },
	{ .name = "cdsp_19", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x018ea000, .pa = 0x018ea000, .len = 0x00001000 },
	{ .name = "cdsp_20", .flags = IOMMU_READ,
		.da = 0x01b40000, .pa = 0x01b40000, .len = 0x00010000 },
	{ .name = "cdsp_21", .flags = IOMMU_READ,
		.da = 0x01b8a000, .pa = 0x01b8a000, .len = 0x00001000 },
	{ .name = "cdsp_22", .flags = IOMMU_READ,
		.da = 0x0445b000, .pa = 0x0445b000, .len = 0x00001000 },
	{ .name = "cdsp_23", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x045f3000, .pa = 0x045f3000, .len = 0x00001000 },
	{ .name = "cdsp_24", .flags = IOMMU_READ,
		.da = 0x045f6000, .pa = 0x045f6000, .len = 0x00001000 },
	{ .name = "cdsp_25", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x0e000000, .pa = 0x0e000000, .len = 0x01000000 },
	/*
	 * DSP takes a translation fault on its first SMEM access.
	 * Without this mapping it hits an mmu fault/watchdog and
	 * never reaches the running state.
	 */
	{ .name = "smem", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x86000000, .pa = 0x86000000, .len = 0x200000, },
};

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
		.offset[CDSP_NUM_MEM_RESOURCES - 1] = 0,
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
