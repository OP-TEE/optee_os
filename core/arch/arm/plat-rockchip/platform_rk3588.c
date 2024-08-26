// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2019, Theobroma Systems Design und Consulting GmbH
 * Copyright (c) 2024, Rockchip, Inc. All rights reserved.
 */

#include <common.h>
#include <io.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <platform.h>
#include <platform_config.h>

#define FIREWALL_DDR_RGN(i)             ((i) * 0x4)
#define FIREWALL_DDR_CON                0xf0
#define FIREWALL_DSU_RGN(i)             ((i) * 0x4)
#define FIREWALL_DSU_CON(i)             (0xf0 + ((i) * 0x4))

#define RG_MAP_SECURE(top, base)        \
	(((((top) - 1) & 0x7fff) << 16) | ((base) & 0x7fff))

#define DDR_CHN_CNT                     4

register_phys_mem_pgdir(MEM_AREA_IO_SEC, FIREWALL_DDR_BASE, FIREWALL_DDR_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, FIREWALL_DSU_BASE, FIREWALL_DSU_SIZE);

int platform_secure_ddr_region(int rgn, paddr_t st, size_t sz)
{
	vaddr_t fw_ddr_base = (vaddr_t)phys_to_virt_io(FIREWALL_DDR_BASE,
						       FIREWALL_DDR_SIZE);
	vaddr_t fw_dsu_base = (vaddr_t)phys_to_virt_io(FIREWALL_DSU_BASE,
						       FIREWALL_DSU_SIZE);
	paddr_t ed = st + sz;
	uint32_t st_mb = st / SIZE_M(1);
	uint32_t ed_mb = ed / SIZE_M(1);
	uint32_t i = 0;

	if (!fw_ddr_base || !fw_dsu_base)
		panic();

	assert(rgn <= 16);
	assert(st < ed);

	/* Check aligned 1MB */
	assert(st % SIZE_M(1) == 0);
	assert(ed % SIZE_M(1) == 0);

	DMSG("protecting region %d: 0x%"PRIxPA"-0x%"PRIxPA"", rgn, st, ed);

	/* Map secure region in DDR */
	io_write32(fw_ddr_base + FIREWALL_DDR_RGN(rgn),
		   RG_MAP_SECURE(ed_mb, st_mb));

	/* Map secure region in each DSU channel and enable */
	for (i = 0; i < DDR_CHN_CNT; i++) {
		io_write32(fw_dsu_base + FIREWALL_DSU_RGN(i),
			   RG_MAP_SECURE(ed_mb, st_mb));
		io_setbits32(fw_dsu_base + FIREWALL_DSU_CON(i), BIT(rgn));
	}

	/* Enable secure region for DDR */
	io_setbits32(fw_ddr_base + FIREWALL_DDR_CON, BIT(rgn));

	return 0;
}
