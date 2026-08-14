// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <assert.h>
#include <config.h>
#include <drivers/qcom/xpu.h>
#include <drivers/qcom/xpuv4.h>
#include <initcall.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <tee_api_types.h>
#include <trace.h>
#include <util.h>
#include <xpu_target.h>

/* This SoC's XPU4 instances, handed to the driver at protection time */
static const struct xpu4_instance xpu4_instances[] = {
	{
		.base = DDR_MPU_BASE,
		.map_size = CORE_MMU_PGDIR_SIZE,
		.addr_off = DDR_MPU_ADDR_OFFSET,
		.guard_start = DRAM0_BASE,
		.guard_size = DRAM0_SIZE,
		.rg_start = DDR_XPU_RG_START,
		.rg_count = DDR_XPU_RG_COUNT,
	},
	{
		.base = IMEM_MPU_BASE,
		.map_size = IMEM_MPU_MAP_SIZE,
		.addr_off = IMEM_BASE,
		.guard_start = IMEM_BASE,
		.guard_size = IMEM_SIZE,
		.rg_start = IMEM_XPU_RG_START,
		.rg_count = IMEM_XPU_RG_COUNT,
	},
};

register_phys_mem_pgdir(MEM_AREA_IO_SEC, DDR_MPU_BASE, CORE_MMU_PGDIR_SIZE);
register_phys_mem(MEM_AREA_IO_SEC, IMEM_MPU_BASE, IMEM_MPU_MAP_SIZE);

/* A memory region to protect and the QAD read/write policy to apply */
struct xpu_region {
	const char *name;
	paddr_t base;
	size_t size;
	uint32_t read_qad;
	uint32_t write_qad;
	bool enabled;
};

static const struct xpu_region xpu_regions[] = {
	{
		.name = "TZDRAM",
		.base = CFG_TZDRAM_START,
		.size = CFG_TZDRAM_SIZE,
		.read_qad = TZDRAM_XPU_READ_QAD,
		.write_qad = TZDRAM_XPU_WRITE_QAD,
		.enabled = true,
	},
	{
		/*
		 * The DIAG log buffer only holds data when the log itself
		 * is built in, so protecting it otherwise would lock a
		 * resource group for a region nothing uses.
		 */
		.name = "DIAG log",
		.base = DIAG_BASE,
		.size = DIAG_SIZE,
		.read_qad = DIAG_XPU_READ_QAD,
		.write_qad = DIAG_XPU_WRITE_QAD,
		.enabled = IS_ENABLED(CFG_QCOM_DIAG_LOG),
	},
};

static TEE_Result plat_xpu_protect(void)
{
	TEE_Result res = TEE_SUCCESS;
	size_t i = 0;

	static_assert(IS_ALIGNED(CFG_TZDRAM_START, SIZE_4K));
	static_assert(IS_ALIGNED(CFG_TZDRAM_SIZE, SIZE_4K));

	xpu4_register_instances(xpu4_instances, ARRAY_SIZE(xpu4_instances));

	/* Protect what is left even if one region could not be programmed */
	for (i = 0; i < ARRAY_SIZE(xpu_regions); i++) {
		const struct xpu_region *r = &xpu_regions[i];
		TEE_Result rc = TEE_SUCCESS;

		if (!r->enabled)
			continue;

		rc = xpu_protect_region(r->base, r->size, r->read_qad,
					r->write_qad);
		if (rc) {
			EMSG("XPU: %s protection failed: %#" PRIx32,
			     r->name, rc);
			if (!res)
				res = rc;
		}
	}

	return res;
}
service_init(plat_xpu_protect);
