/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef _PAS_RESOURCES_H_
#define _PAS_RESOURCES_H_

#include <io.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "pas.h"

/*
 * WPSS
 */
static const struct fw_rsc_devmem wpss_mem_res[] = {
	{.name = "wlan_fw_mem", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x80c00000, .pa = 0x80c00000, .len = 0xc00000, },
	{.name = "wlan_ce_mem", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x004cd000, .pa = 0x004cd000, .len = 0x1000, },
};

static const struct fw_rsc_hdr wpss_mem_hdr = {
	.type = RSC_DEVMEM,
};

DEFINE_RESOURCE_TABLE(WPSS, ARRAY_SIZE(wpss_mem_res));

static struct resource_table wpss_rt = {
	.ver = 1,
	.num = WPSS_NUM_MEM_RESOURCES,
	.offset[WPSS_NUM_MEM_RESOURCES - 1] = 0,
};

/*
 * Compute
 */
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

static const struct fw_rsc_hdr turing_mem_hdr = {
	.type = RSC_DEVMEM,
};

DEFINE_RESOURCE_TABLE(TURING, ARRAY_SIZE(turing_mem_res));

static struct resource_table turing_rt = {
	.ver = 1,
	.num = TURING_NUM_MEM_RESOURCES,
	.offset[TURING_NUM_MEM_RESOURCES - 1] = 0,
};

#endif /* _PAS_RESOURCES_H_ */
