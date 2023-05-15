// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2017 NXP
 */

#include <arm.h>
#include <arm32.h>
#include <console.h>
#include <io.h>
#include <imx.h>
#include <imx_pm.h>
#include <kernel/panic.h>
#include <kernel/cache_helpers.h>
#include <mm/core_mmu.h>
#include <mm/core_memprot.h>
#include <mmdc.h>
#include <platform_config.h>
#include <sm/pm.h>
#include <sm/psci.h>
#include <sm/sm.h>
#include <string.h>

paddr_t iram_tbl_phys_addr = -1UL;
void *iram_tbl_virt_addr;

#define READ_DATA_FROM_HARDWARE		0

static uint32_t imx7d_ddrc_ddr3_setting[][2] = {
	{ 0x0, READ_DATA_FROM_HARDWARE },
	{ 0x1a0, READ_DATA_FROM_HARDWARE },
	{ 0x1a4, READ_DATA_FROM_HARDWARE },
	{ 0x1a8, READ_DATA_FROM_HARDWARE },
	{ 0x64, READ_DATA_FROM_HARDWARE },
	{ 0x490, READ_DATA_FROM_HARDWARE },
	{ 0xd0, READ_DATA_FROM_HARDWARE },
	{ 0xd4, READ_DATA_FROM_HARDWARE },
	{ 0xdc, READ_DATA_FROM_HARDWARE },
	{ 0xe0, READ_DATA_FROM_HARDWARE },
	{ 0xe4, READ_DATA_FROM_HARDWARE },
	{ 0xf4, READ_DATA_FROM_HARDWARE },
	{ 0x100, READ_DATA_FROM_HARDWARE },
	{ 0x104, READ_DATA_FROM_HARDWARE },
	{ 0x108, READ_DATA_FROM_HARDWARE },
	{ 0x10c, READ_DATA_FROM_HARDWARE },
	{ 0x110, READ_DATA_FROM_HARDWARE },
	{ 0x114, READ_DATA_FROM_HARDWARE },
	{ 0x120, READ_DATA_FROM_HARDWARE },
	{ 0x180, READ_DATA_FROM_HARDWARE },
	{ 0x190, READ_DATA_FROM_HARDWARE },
	{ 0x194, READ_DATA_FROM_HARDWARE },
	{ 0x200, READ_DATA_FROM_HARDWARE },
	{ 0x204, READ_DATA_FROM_HARDWARE },
	{ 0x214, READ_DATA_FROM_HARDWARE },
	{ 0x218, READ_DATA_FROM_HARDWARE },
	{ 0x240, READ_DATA_FROM_HARDWARE },
	{ 0x244, READ_DATA_FROM_HARDWARE },
};

static uint32_t imx7d_ddrc_phy_ddr3_setting[][2] = {
	{ 0x0, READ_DATA_FROM_HARDWARE },
	{ 0x4, READ_DATA_FROM_HARDWARE },
	{ 0x10, READ_DATA_FROM_HARDWARE },
	{ 0xb0, READ_DATA_FROM_HARDWARE },
	{ 0x9c, READ_DATA_FROM_HARDWARE },
	{ 0x7c, READ_DATA_FROM_HARDWARE },
	{ 0x80, READ_DATA_FROM_HARDWARE },
	{ 0x84, READ_DATA_FROM_HARDWARE },
	{ 0x88, READ_DATA_FROM_HARDWARE },
	{ 0x6c, READ_DATA_FROM_HARDWARE },
	{ 0x20, READ_DATA_FROM_HARDWARE },
	{ 0x30, READ_DATA_FROM_HARDWARE },
	{ 0x50, 0x01000010 },
	{ 0x50, 0x00000010 },
	{ 0xc0, 0x0e407304 },
	{ 0xc0, 0x0e447304 },
	{ 0xc0, 0x0e447306 },
	{ 0xc0, 0x0e447304 },
	{ 0xc0, 0x0e407306 },
};

static struct imx7_pm_data imx7d_pm_data_ddr3 = {
	.ddrc_num = ARRAY_SIZE(imx7d_ddrc_ddr3_setting),
	.ddrc_offset = imx7d_ddrc_ddr3_setting,
	.ddrc_phy_num = ARRAY_SIZE(imx7d_ddrc_phy_ddr3_setting),
	.ddrc_phy_offset = imx7d_ddrc_phy_ddr3_setting,
};

paddr_t phys_addr[] = {
	AIPS1_BASE, AIPS2_BASE, AIPS3_BASE
};

int pm_imx7_iram_tbl_init(void)
{
	uint32_t i;
	struct tee_mmap_region map;

	/* iram mmu translation table already initialized */
	if (iram_tbl_phys_addr != (-1UL))
		return 0;

	iram_tbl_phys_addr = TRUSTZONE_OCRAM_START + 16 * 1024;
	iram_tbl_virt_addr = phys_to_virt(iram_tbl_phys_addr,
					  MEM_AREA_TEE_COHERENT,
					  16 * 1024);

	/* 16KB */
	memset(iram_tbl_virt_addr, 0, 16 * 1024);

	for (i = 0; i < ARRAY_SIZE(phys_addr); i++) {
		map.pa = phys_addr[i];
		map.va = (vaddr_t)phys_to_virt(phys_addr[i], MEM_AREA_IO_SEC,
					       AIPS1_SIZE);
		map.region_size = CORE_MMU_PGDIR_SIZE;
		map.size = AIPS1_SIZE; /* 4M for AIPS1/2/3 */
		map.type = MEM_AREA_IO_SEC;
		map.attr = TEE_MATTR_VALID_BLOCK | TEE_MATTR_PRW |
			   TEE_MATTR_SECURE |
			   (TEE_MATTR_MEM_TYPE_DEV <<
			    TEE_MATTR_MEM_TYPE_SHIFT);
		map_memarea_sections(&map, (uint32_t *)iram_tbl_virt_addr);
	}

	/* Note IRAM_S_BASE is not 1M aligned, so take care */
	map.pa = ROUNDDOWN(IRAM_S_BASE, CORE_MMU_PGDIR_SIZE);
	map.va = (vaddr_t)phys_to_virt(map.pa, MEM_AREA_TEE_COHERENT,
				       CORE_MMU_PGDIR_SIZE);
	map.region_size = CORE_MMU_PGDIR_SIZE;
	map.size = CORE_MMU_PGDIR_SIZE;
	map.type = MEM_AREA_TEE_COHERENT;
	map.attr = TEE_MATTR_VALID_BLOCK | TEE_MATTR_PRWX | TEE_MATTR_SECURE;
	map_memarea_sections(&map, (uint32_t *)iram_tbl_virt_addr);

	map.pa = GIC_BASE;
	map.va = (vaddr_t)phys_to_virt((paddr_t)GIC_BASE, MEM_AREA_IO_SEC, 1);
	map.region_size = CORE_MMU_PGDIR_SIZE;
	map.size = CORE_MMU_PGDIR_SIZE;
	map.type = MEM_AREA_TEE_COHERENT;
	map.attr = TEE_MATTR_VALID_BLOCK | TEE_MATTR_PRW | TEE_MATTR_SECURE;
	map_memarea_sections(&map, (uint32_t *)iram_tbl_virt_addr);

	return 0;
}

int imx7_suspend_init(void)
{
	uint32_t i;
	uint32_t (*ddrc_offset_array)[2];
	uint32_t (*ddrc_phy_offset_array)[2];
	uint32_t suspend_ocram_base =
		core_mmu_get_va(TRUSTZONE_OCRAM_START + SUSPEND_OCRAM_OFFSET,
				MEM_AREA_TEE_COHERENT,
				sizeof(struct imx7_pm_info));
	struct imx7_pm_info *p = (struct imx7_pm_info *)suspend_ocram_base;
	struct imx7_pm_data *pm_data;

	pm_imx7_iram_tbl_init();

	dcache_op_level1(DCACHE_OP_CLEAN_INV);

	p->pa_base = TRUSTZONE_OCRAM_START + SUSPEND_OCRAM_OFFSET;
	p->tee_resume = virt_to_phys((void *)(vaddr_t)ca7_cpu_resume);
	p->pm_info_size = sizeof(*p);
	p->ccm_va_base = core_mmu_get_va(CCM_BASE, MEM_AREA_IO_SEC, 1);
	p->ccm_pa_base = CCM_BASE;
	p->ddrc_va_base = core_mmu_get_va(DDRC_BASE, MEM_AREA_IO_SEC, 1);
	p->ddrc_pa_base = DDRC_BASE;
	p->ddrc_phy_va_base = core_mmu_get_va(DDRC_PHY_BASE, MEM_AREA_IO_SEC,
					      1);
	p->ddrc_phy_pa_base = DDRC_PHY_BASE;
	p->src_va_base = core_mmu_get_va(SRC_BASE, MEM_AREA_IO_SEC, 1);
	p->src_pa_base = SRC_BASE;
	p->iomuxc_gpr_va_base = core_mmu_get_va(IOMUXC_GPR_BASE,
						MEM_AREA_IO_SEC, 1);
	p->iomuxc_gpr_pa_base = IOMUXC_GPR_BASE;
	p->gpc_va_base = core_mmu_get_va(GPC_BASE, MEM_AREA_IO_SEC, 1);
	p->gpc_pa_base = GPC_BASE;
	p->anatop_va_base = core_mmu_get_va(ANATOP_BASE, MEM_AREA_IO_SEC, 1);
	p->anatop_pa_base = ANATOP_BASE;
	p->snvs_va_base = core_mmu_get_va(SNVS_BASE, MEM_AREA_IO_SEC, 1);
	p->snvs_pa_base = SNVS_BASE;
	p->lpsr_va_base = core_mmu_get_va(LPSR_BASE, MEM_AREA_IO_SEC, 1);
	p->lpsr_pa_base = LPSR_BASE;
	p->gic_va_base = core_mmu_get_va(GIC_BASE, MEM_AREA_IO_SEC, 1);
	p->gic_pa_base = GIC_BASE;

	/* TODO:lpsr disabled now */
	io_write32(p->lpsr_va_base, 0);

	p->ddr_type = imx_get_ddr_type();
	switch (p->ddr_type) {
	case IMX_DDR_TYPE_DDR3:
		pm_data = &imx7d_pm_data_ddr3;
		break;
	default:
		panic("Not supported ddr type\n");
		break;
	}

	p->ddrc_num = pm_data->ddrc_num;
	p->ddrc_phy_num = pm_data->ddrc_phy_num;
	ddrc_offset_array = pm_data->ddrc_offset;
	ddrc_phy_offset_array = pm_data->ddrc_phy_offset;

	for (i = 0; i < p->ddrc_num; i++) {
		p->ddrc_val[i][0] = ddrc_offset_array[i][0];
		if (ddrc_offset_array[i][1] == READ_DATA_FROM_HARDWARE)
			p->ddrc_val[i][1] = io_read32(p->ddrc_va_base +
						      ddrc_offset_array[i][0]);
		else
			p->ddrc_val[i][1] = ddrc_offset_array[i][1];

		if (p->ddrc_val[i][0] == 0xd0)
			p->ddrc_val[i][1] |= 0xc0000000;
	}

	/* initialize DDRC PHY settings */
	for (i = 0; i < p->ddrc_phy_num; i++) {
		p->ddrc_phy_val[i][0] = ddrc_phy_offset_array[i][0];
		if (ddrc_phy_offset_array[i][1] == READ_DATA_FROM_HARDWARE)
			p->ddrc_phy_val[i][1] =
				io_read32(p->ddrc_phy_va_base +
					  ddrc_phy_offset_array[i][0]);
		else
			p->ddrc_phy_val[i][1] = ddrc_phy_offset_array[i][1];
	}

	memcpy((void *)(suspend_ocram_base + sizeof(*p)),
	       (void *)(vaddr_t)imx7_suspend, SUSPEND_OCRAM_SIZE - sizeof(*p));

	dcache_clean_range((void *)suspend_ocram_base, SUSPEND_OCRAM_SIZE);

	/*
	 * Note that IRAM IOSEC map, if changed to MEM map,
	 * need to flush cache
	 */
	icache_inv_all();

	return 0;
}
