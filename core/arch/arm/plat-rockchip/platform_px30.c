// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2019, Theobroma Systems Design und Consulting GmbH
 */

#include <common.h>
#include <io.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <platform.h>
#include <platform_config.h>

#define FIREWALL_DDR_FW_DDR_RGN(i)	((i) * 0x4)
#define FIREWALL_DDR_FW_DDR_MST(i)	(0x20 + (i) * 0x4)
#define FIREWALL_DDR_FW_DDR_CON_REG	0x40
#define FIREWALL_DDR_FW_DDR_RGN_NUM	8
#define FIREWALL_DDR_FW_DDR_MST_NUM	6

#define RG_MAP_SECURE(top, base)	((((top) - 1) << 16) | (base))

register_phys_mem_pgdir(MEM_AREA_IO_SEC, FIREWALL_DDR_BASE, FIREWALL_DDR_SIZE);

int platform_secure_ddr_region(int rgn, paddr_t st, size_t sz)
{
	vaddr_t fw_base = (vaddr_t)phys_to_virt_io(FIREWALL_DDR_BASE,
						   FIREWALL_DDR_SIZE);
	paddr_t ed = st + sz;
	uint32_t st_mb = st / SIZE_M(1);
	uint32_t ed_mb = ed / SIZE_M(1);

	if (!fw_base)
		panic();

	assert(rgn <= 7);
	assert(st < ed);

	/* Check aligned 1MB */
	assert(st % SIZE_M(1) == 0);
	assert(ed % SIZE_M(1) == 0);

	DMSG("protecting region %d: 0x%lx-0x%lx\n", rgn, st, ed);

	/* Map top and base */
	io_write32(fw_base + FIREWALL_DDR_FW_DDR_RGN(rgn),
		   RG_MAP_SECURE(ed_mb, st_mb));

	/* Enable secure setting */
	io_setbits32(fw_base + FIREWALL_DDR_FW_DDR_CON_REG, BIT(rgn));

	return 0;
}
