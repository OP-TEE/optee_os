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

#define SGRF_DDRRGN_CON0_16(n)		((n) * 4)
#define SGRF_DDR_RGN_0_16_WMSK		GENMASK_32(11, 0)

register_phys_mem_pgdir(MEM_AREA_IO_SEC, SGRF_BASE, SGRF_SIZE);

int platform_secure_ddr_region(int rgn, paddr_t st, size_t sz)
{
	vaddr_t sgrf_base = (vaddr_t)phys_to_virt_io(SGRF_BASE, SGRF_SIZE);
	paddr_t ed = st + sz;
	uint32_t st_mb = st / SIZE_M(1);
	uint32_t ed_mb = ed / SIZE_M(1);

	if (!sgrf_base)
		panic();

	assert(rgn <= 7);
	assert(st < ed);

	/* Check aligned 1MB */
	assert(st % SIZE_M(1) == 0);
	assert(ed % SIZE_M(1) == 0);

	DMSG("protecting region %d: 0x%lx-0x%lx", rgn, st, ed);

	/* Set ddr region addr start */
	io_write32(sgrf_base + SGRF_DDRRGN_CON0_16(rgn),
		   BITS_WITH_WMASK(st_mb, SGRF_DDR_RGN_0_16_WMSK, 0));

	/* Set ddr region addr end */
	io_write32(sgrf_base + SGRF_DDRRGN_CON0_16(rgn + 8),
		   BITS_WITH_WMASK((ed_mb - 1), SGRF_DDR_RGN_0_16_WMSK, 0));

	io_write32(sgrf_base + SGRF_DDRRGN_CON0_16(16),
		   BIT_WITH_WMSK(rgn));

	return 0;
}
