// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2026, Daniel Golle <daniel@makrotopia.org>
 */

#include <io.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <platform.h>
#include <platform_config.h>
#include <trace.h>
#include <util.h>

/* DDR firewall (from TF-A rk3568/drivers/secure/secure.h) */
#define FIREWALL_DDR_RGN(i)		((i) * 0x4)
#define FIREWALL_DDR_RGN_CNT		16
#define FIREWALL_DDR_CON		0x80

/*
 * base / (top - 1) encoded in 128 KiB blocks (not the 1 MiB blocks
 * used on RK3576/RK3588), both clamped to 15 bits.
 */
#define RG_MAP_SECURE(top, base) \
	(((((top) - 1) & 0x7fff) << 16) | ((base) & 0x7fff))

register_phys_mem_pgdir(MEM_AREA_IO_SEC, FIREWALL_DDR_BASE, FIREWALL_DDR_SIZE);

int platform_secure_ddr_region(int rgn, paddr_t st, size_t sz)
{
	vaddr_t fw_base = (vaddr_t)phys_to_virt_io(FIREWALL_DDR_BASE,
						   FIREWALL_DDR_SIZE);
	paddr_t ed = st + sz;
	uint32_t st_blk = st / SIZE_K(128);
	uint32_t ed_blk = ed / SIZE_K(128);

	if (!fw_base)
		panic("FIREWALL_DDR_BASE not mapped");

	/*
	 * Validate at runtime, not with assert(): a misaligned or
	 * out-of-range region would otherwise be silently truncated by the
	 * block division in a release build (NDEBUG), leaving part of the
	 * secure DRAM reachable from the normal world. Fail closed instead.
	 */
	if (rgn < 1 || rgn >= FIREWALL_DDR_RGN_CNT || st >= ed ||
	    st % SIZE_K(128) || ed % SIZE_K(128) || ed_blk > 0x8000)
		panic("invalid secure DDR region");

	DMSG("protecting region %d: 0x%" PRIxPA "-0x%" PRIxPA, rgn, st, ed);

	io_write32(fw_base + FIREWALL_DDR_RGN(rgn),
		   RG_MAP_SECURE(ed_blk, st_blk));
	io_setbits32(fw_base + FIREWALL_DDR_CON, BIT(rgn));

	return 0;
}
