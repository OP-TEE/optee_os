// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2017, Fuzhou Rockchip Electronics Co., Ltd.
 * Copyright (C) 2019, Theobroma Systems Design und Consulting GmbH
 */

#include <common.h>
#include <io.h>
#include <mm/core_memprot.h>
#include <platform.h>
#include <platform_config.h>

register_phys_mem_pgdir(MEM_AREA_IO_SEC, SGRF_BASE, SGRF_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, DDRSGRF_BASE, DDRSGRF_SIZE);

#define SGRF_SOC_CON(n)		((n) * 4)
#define DDR_SGRF_DDR_CON(n)	((n) * 4)
#define DDR_RGN0_NS		BIT32(30)
#define SLAVE_ALL_NS		GENMASK_32(31, 16)

int platform_secure_init(void)
{
	vaddr_t sgrf_base = (vaddr_t)phys_to_virt_io(SGRF_BASE, SGRF_SIZE);
	vaddr_t ddrsgrf_base = (vaddr_t)phys_to_virt_io(DDRSGRF_BASE,
							DDRSGRF_SIZE);

	/* Set rgn0 non-secure */
	io_write32(ddrsgrf_base + DDR_SGRF_DDR_CON(0), DDR_RGN0_NS);

	/* Initialize all slave non-secure */
	io_write32(sgrf_base + SGRF_SOC_CON(7), SLAVE_ALL_NS);
	io_write32(sgrf_base + SGRF_SOC_CON(8), SLAVE_ALL_NS);
	io_write32(sgrf_base + SGRF_SOC_CON(9), SLAVE_ALL_NS);
	io_write32(sgrf_base + SGRF_SOC_CON(10), SLAVE_ALL_NS);

	return 0;
}
