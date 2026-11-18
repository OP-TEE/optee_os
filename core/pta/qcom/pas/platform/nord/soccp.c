// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <drivers/clk_qcom.h>
#include <inttypes.h>
#include <io.h>
#include <kernel/delay.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <resource_table.h>
#include <stdint.h>
#include <trace.h>

#include "soccp.h"

#define SOCCP_CSR_CNOC_REG_BASE		0xd40000
#define SOCCP_CSR_CNOC_REG_SIZE		0x61000
#define SOCCP_RVSSMP_RESET_VECTOR	0x3000c
#define SOCCP_SID3			0x60014
#define SOCCP_START_ADDR		0x8bc00000

register_phys_mem(MEM_AREA_IO_NSEC, SOCCP_CSR_CNOC_REG_BASE,
		SOCCP_CSR_CNOC_REG_SIZE);

static TEE_Result soccp_fw_start(struct qcom_pas_data *data)
{
	struct io_pa_va soccp_csr_io = { .pa = SOCCP_CSR_CNOC_REG_BASE };
	vaddr_t soccp_csr = io_pa_or_va(&soccp_csr_io, SOCCP_CSR_CNOC_REG_SIZE);

	(void)data;

	if (!soccp_csr)
		return TEE_ERROR_GENERIC;

	io_write32(soccp_csr + SOCCP_RVSSMP_RESET_VECTOR, SOCCP_START_ADDR);
	io_write32(soccp_csr + SOCCP_SID3, 4);
	dsb();
	EMSG("SoCCP start address %#" PRIx32
			" programmed at register %#" PRIx32,
			(uint32_t)SOCCP_START_ADDR,
			(uint32_t)(SOCCP_CSR_CNOC_REG_BASE +
				SOCCP_RVSSMP_RESET_VECTOR));

	return TEE_SUCCESS;
}

static TEE_Result soccp_fw_shutdown(struct qcom_pas_data *data)
{
	return qcom_clock_pas_reset(data->clk_group);
}

static const struct fw_rsc_devmem soccp_mem_res[] = {
	{ .name = "soccp_0", .flags = IOMMU_READ,
		.da = 0x00100000, .pa = 0x00100000, .len = 0x00008000 },
	{ .name = "soccp_1", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x0011f000, .pa = 0x0011f000, .len = 0x00001000 },
	{ .name = "soccp_2", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x00123000, .pa = 0x00123000, .len = 0x00001000 },
	{ .name = "soccp_3", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x0012f000, .pa = 0x0012f000, .len = 0x00001000 },
	{ .name = "soccp_4", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0xe013e000, .pa = 0x0013e000, .len = 0x00001000 },
	{ .name = "soccp_5", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x00162000, .pa = 0x00162000, .len = 0x00001000 },
	{ .name = "soccp_6", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0xe1f42000, .pa = 0x01f42000, .len = 0x00002000 },
	{ .name = "soccp_7", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0xe1f4a000, .pa = 0x01f4a000, .len = 0x00002000 },
	{ .name = "soccp_8", .flags = IOMMU_READ,
		.da = 0xe1fd4000, .pa = 0x01fd4000, .len = 0x00001000 },
	{ .name = "soccp_9", .flags = IOMMU_READ,
		.da = 0xe1fda000, .pa = 0x01fda000, .len = 0x00001000 },
	{ .name = "soccp_10", .flags = IOMMU_READ,
		.da = 0x08900000, .pa = 0x08900000, .len = 0x00009000 },
	{ .name = "soccp_11", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x08914000, .pa = 0x08914000, .len = 0x00001000 },
	{ .name = "soccp_12", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x08920000, .pa = 0x08920000, .len = 0x00003000 },
	{ .name = "soccp_13", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x08938000, .pa = 0x08938000, .len = 0x00001000 },
	{ .name = "soccp_14", .flags = IOMMU_READ,
		.da = 0x08a00000, .pa = 0x08a00000, .len = 0x00007000 },
	{ .name = "soccp_15", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x08a18000, .pa = 0x08a18000, .len = 0x00003000 },
	{ .name = "soccp_16", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x08a1d000, .pa = 0x08a1d000, .len = 0x00001000 },
	{ .name = "soccp_17", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x08a26000, .pa = 0x08a26000, .len = 0x00002000 },
	{ .name = "soccp_18", .flags = IOMMU_READ,
		.da = 0x08b00000, .pa = 0x08b00000, .len = 0x00006000 },
	{ .name = "soccp_19", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x08b1f000, .pa = 0x08b1f000, .len = 0x00003000 },
	{ .name = "soccp_20", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x08b32000, .pa = 0x08b32000, .len = 0x00001000 },
	{ .name = "soccp_21", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0xe900c000, .pa = 0x0900c000, .len = 0x00001000 },
	{ .name = "soccp_22", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0xe900f000, .pa = 0x0900f000, .len = 0x00001000 },
	{ .name = "soccp_23", .flags = IOMMU_READ,
		.da = 0xe904e000, .pa = 0x0904e000, .len = 0x00001000 },
	{ .name = "soccp_24", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0xe908e000, .pa = 0x0908e000, .len = 0x00001000 },
	{ .name = "soccp_25", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0xe90d4000, .pa = 0x090d4000, .len = 0x00001000 },
	{ .name = "soccp_26", .flags = IOMMU_READ,
		.da = 0xe9116000, .pa = 0x09116000, .len = 0x00001000 },
	{ .name = "soccp_27", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0xe9194000, .pa = 0x09194000, .len = 0x00001000 },
	{ .name = "soccp_28", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0xe9321000, .pa = 0x09321000, .len = 0x00001000 },
	{ .name = "soccp_29", .flags = IOMMU_READ,
		.da = 0xe93fc000, .pa = 0x093fc000, .len = 0x00001000 },
	{ .name = "soccp_30", .flags = IOMMU_READ,
		.da = 0x360d4000, .pa = 0x360d4000, .len = 0x00004000 },
	{ .name = "soccp_31", .flags = IOMMU_READ,
		.da = 0x36200000, .pa = 0x36200000, .len = 0x00010000 },
	/* QUP ranges */
	{ .name = "qup_3_0_1_2", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x00800000, .pa = 0x00800000, .len = 0x00300000, },
	{ .name = "qup_range_3_3", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x00c00000, .pa = 0x00c00000, .len = 0x00100000, },
	/* PIL takes a translation fault on its first SMEM access.
	 * Without this mapping it hits an mmufault/watchdog and
	 * never reaches the running state.
	 */
	{ .name = "smem", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0xf6800000, .pa = 0x89b00000, .len = 0x400000, },
	{ .name = "globalsync", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0xf6c00000, .pa = 0x89f00000, .len = 0x200000, },
};


DEFINE_RESOURCE_TABLE(SOCCP, ARRAY_SIZE(soccp_mem_res));

static TEE_Result soccp_get_resource_table(struct resource_table *rt,
		size_t *rt_size)
{
	const struct fw_rsc_hdr header = {
		.type = RSC_DEVMEM,
	};
	static struct resource_table table = {
		.ver = 1,
		.num = SOCCP_NUM_MEM_RESOURCES,
		.offset[SOCCP_NUM_MEM_RESOURCES - 1] = 0,
	};

	return get_mem_rsc(rt, rt_size, &table, &header,
			soccp_mem_res,
			SOCCP_RESOURCE_TABLE_HEADER_SIZE,
			SOCCP_RESOURCE_TABLE_SIZE);
}

const struct qcom_pas_ops soccp_ops = {
	.fw_start = soccp_fw_start,
	.fw_shutdown = soccp_fw_shutdown,
	.get_resource_table = soccp_get_resource_table,
};
