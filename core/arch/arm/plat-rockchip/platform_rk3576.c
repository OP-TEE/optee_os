// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025, Rockchip RK3576 OP-TEE platform glue.
 */

#include <common.h>
#include <io.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <platform.h>
#include <platform_config.h>
#include <trace.h>
#include <util.h>

/* DDR firewall offsets (from TF-A rk3576/drivers/secure/firewall.h) */
#define FW_SGRF_DDR_RGN(i)		(0x0100 + (i) * 0x4)
#define FW_SGRF_DDR_RGN_CNT		16
#define FW_SGRF_DDR_CON			0x0168

/* base / (top - 1) encoded in 1 MB units, both clamped to 15 bits. */
#define RG_MAP_SECURE(top_mb, base_mb) \
	(((((top_mb) - 1) & 0x7fff) << 16) | ((base_mb) & 0x7fff))

register_phys_mem_pgdir(MEM_AREA_IO_SEC, SYS_SGRF_FW_BASE, SYS_SGRF_FW_SIZE);

int platform_secure_ddr_region(int rgn, paddr_t st, size_t sz)
{
	vaddr_t fw_base = (vaddr_t)phys_to_virt_io(SYS_SGRF_FW_BASE,
						   SYS_SGRF_FW_SIZE);
	paddr_t ed = st + sz;
	uint32_t st_mb = st / SIZE_M(1);
	uint32_t ed_mb = ed / SIZE_M(1);

	if (!fw_base)
		panic("SYS_SGRF_FW_BASE not mapped");

	assert(rgn >= 1 && rgn < FW_SGRF_DDR_RGN_CNT);
	assert(st < ed);
	assert(st % SIZE_M(1) == 0);
	assert(ed % SIZE_M(1) == 0);

	DMSG("protecting region %d: 0x%" PRIxPA "-0x%" PRIxPA,
	     rgn, st, ed);

	io_write32(fw_base + FW_SGRF_DDR_RGN(rgn),
		   RG_MAP_SECURE(ed_mb, st_mb));
	io_setbits32(fw_base + FW_SGRF_DDR_CON, BIT(rgn));

	return 0;
}
