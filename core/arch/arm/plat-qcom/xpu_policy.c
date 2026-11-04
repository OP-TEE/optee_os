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
#include <qcom_common.h>
#include <tee_api_types.h>
#include <trace.h>
#include <util.h>
#include <xpu_target.h>

enum {
	XPU_INST_DDR,
	XPU_INST_IMEM,
};

static const struct xpu4_guard imem_guards[] = {
	{
		.start = IMEM_BASE,
		.size = IMEM_SIZE,
	},
};

/*
 * This SoC's XPU4 instances, handed to the driver at protection time. What
 * the DDR one guards is the DRAM, which plat_xpu_init() fills in.
 */
static struct xpu4_instance xpu4_instances[] = {
	[XPU_INST_DDR] = {
		.base = DDR_MPU_BASE,
		.map_size = CORE_MMU_PGDIR_SIZE,
		.addr_off = DDR_MPU_ADDR_OFFSET,
		.rg_start = DDR_XPU_RG_START,
		.rg_count = DDR_XPU_RG_COUNT,
	},
	[XPU_INST_IMEM] = {
		.base = IMEM_MPU_BASE,
		.map_size = IMEM_MPU_MAP_SIZE,
		.addr_off = IMEM_BASE,
		.guards = imem_guards,
		.guard_count = ARRAY_SIZE(imem_guards),
		.rg_start = IMEM_XPU_RG_START,
		.rg_count = IMEM_XPU_RG_COUNT,
	},
};

register_phys_mem_pgdir(MEM_AREA_IO_SEC, DDR_MPU_BASE, CORE_MMU_PGDIR_SIZE);
register_phys_mem(MEM_AREA_IO_SEC, IMEM_MPU_BASE, IMEM_MPU_MAP_SIZE);

static TEE_Result plat_xpu_init(void)
{
	struct xpu4_instance *ddr = &xpu4_instances[XPU_INST_DDR];
	TEE_Result res = TEE_SUCCESS;

	res = qcom_xpu_get_ddr_guards(&ddr->guards, &ddr->guard_count);
	if (res)
		EMSG("XPU: DDR guards are incomplete: %#" PRIx32, res);

	xpu4_register_instances(xpu4_instances, ARRAY_SIZE(xpu4_instances));

	return res;
}

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

	/* Protect what the guards cover even if they are incomplete */
	res = plat_xpu_init();

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
