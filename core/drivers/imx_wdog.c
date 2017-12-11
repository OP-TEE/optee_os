// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2017-2018 NXP
 *
 * Peng Fan <peng.fan@nxp.com>
 */

#include <assert.h>
#include <drivers/imx_wdog.h>
#include <io.h>
#include <keep.h>
#include <kernel/dt.h>
#include <kernel/generic_boot.h>
#include <kernel/panic.h>
#include <libfdt.h>
#include <mm/core_mmu.h>
#include <mm/core_memprot.h>
#include <util.h>

static bool ext_reset;
static vaddr_t wdog_base;

void imx_wdog_restart(void)
{
	uint32_t val;

	if (!wdog_base) {
		EMSG("No wdog mapped\n");
		panic();
	}

#ifdef CFG_MX7ULP
	val = read32(wdog_base + WDOG_CS);

	write32(UNLOCK, wdog_base + WDOG_CNT);
	/* Enable wdog */
	write32(val | WDOG_CS_EN, wdog_base + WDOG_CS);

	write32(UNLOCK, wdog_base + WDOG_CNT);
	write32(1000, wdog_base + WDOG_TOVAL);
	write32(REFRESH, wdog_base + WDOG_CNT);
#else
	if (ext_reset)
		val = 0x14;
	else
		val = 0x24;

	DMSG("val %x\n", val);

	write16(val, wdog_base + WDT_WCR);
	dsb();

	if (read16(wdog_base + WDT_WCR) & WDT_WCR_WDE) {
		write16(WDT_SEQ1, wdog_base + WDT_WSR);
		write16(WDT_SEQ2, wdog_base + WDT_WSR);
	}

	write16(val, wdog_base + WDT_WCR);
	write16(val, wdog_base + WDT_WCR);
#endif
	while (1)
		;
}
KEEP_PAGER(imx_wdog_restart);

static TEE_Result imx_wdog_init(void)
{
	enum teecore_memtypes mtype;
	void *fdt;
	paddr_t pbase;
	vaddr_t vbase;
	ssize_t sz;
	int off;
	int st;
	uint32_t i;

#ifdef CFG_MX7
	static const char * const wdog_path[] = {
		"/soc/aips-bus@30000000/wdog@30280000",
		"/soc/aips-bus@30000000/wdog@30290000",
		"/soc/aips-bus@30000000/wdog@302a0000",
		"/soc/aips-bus@30000000/wdog@302b0000",
	};
#elif defined CFG_MX7ULP
	static const char * const wdog_path[] = {
		"/ahb-bridge0@40000000/wdog@403D0000",
		"/ahb-bridge0@40000000/wdog@40430000",
	};
#elif defined CFG_MX6SX
	static const char * const wdog_path[] = {
		"/soc/aips-bus@02000000/wdog@020bc000",
		"/soc/aips-bus@02000000/wdog@020c0000",
		"/soc/aips-bus@02200000/wdog@02288000",
	};
#else
	static const char * const wdog_path[] = {
		"/soc/aips-bus@02000000/wdog@020bc000",
		"/soc/aips-bus@02000000/wdog@020c0000",
	};
#endif

	fdt = get_dt_blob();
	if (!fdt) {
		EMSG("No DTB\n");
		return TEE_ERROR_NOT_SUPPORTED;
	}

	/* search the first usable wdog */
	for (i = 0; i < ARRAY_SIZE(wdog_path); i++) {
		off = fdt_path_offset(fdt, wdog_path[i]);
		if (off < 0)
			continue;

		st = _fdt_get_status(fdt, off);
		if (st & DT_STATUS_OK_SEC)
			break;
	}

	if (i == ARRAY_SIZE(wdog_path))
		return TEE_ERROR_ITEM_NOT_FOUND;

	DMSG("path: %s\n", wdog_path[i]);

	ext_reset = dt_have_prop(fdt, off, "fsl,ext-reset-output");

	pbase = _fdt_reg_base_address(fdt, off);
	if (pbase == (paddr_t)-1)
		return TEE_ERROR_ITEM_NOT_FOUND;

	sz = _fdt_reg_size(fdt, off);
	if (sz < 0)
		return TEE_ERROR_ITEM_NOT_FOUND;

	if ((st & DT_STATUS_OK_SEC) && !(st & DT_STATUS_OK_NSEC))
		mtype = MEM_AREA_IO_SEC;
	else
		mtype = MEM_AREA_IO_NSEC;

	/*
	 * Check to see whether it has been mapped using
	 * register_phys_mem or not.
	 */
	vbase = (vaddr_t)phys_to_virt(pbase, mtype);
	if (!vbase) {
		if (!core_mmu_add_mapping(mtype, pbase, sz)) {
			EMSG("Failed to map %zu bytes at PA 0x%"PRIxPA,
			     (size_t)sz, pbase);
			return TEE_ERROR_GENERIC;
		}
	}

	vbase = (vaddr_t)phys_to_virt(pbase, mtype);
	if (!vbase) {
		EMSG("Failed to get VA for PA 0x%"PRIxPA, pbase);
		return TEE_ERROR_GENERIC;
	}

	wdog_base = vbase;

	return TEE_SUCCESS;
}
driver_init(imx_wdog_init);
