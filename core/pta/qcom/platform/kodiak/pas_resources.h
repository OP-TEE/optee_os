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

#endif /* _PAS_RESOURCES_H_ */
