// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2017-2019 NXP
 *
 * Peng Fan <peng.fan@nxp.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <assert.h>
#include <drivers/imx_wdog.h>
#include <io.h>
#include <keep.h>
#include <kernel/dt.h>
#include <kernel/generic_boot.h>
#include <kernel/panic.h>
#ifdef CFG_DT
#include <libfdt.h>
#endif
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
	val = io_read32(wdog_base + WDOG_CS);

	io_write32(wdog_base + WDOG_CNT, UNLOCK);
	/* Enable wdog */
	io_write32(wdog_base + WDOG_CS, val | WDOG_CS_EN);

	io_write32(wdog_base + WDOG_CNT, UNLOCK);
	io_write32(wdog_base + WDOG_TOVAL, 1000);
	io_write32(wdog_base + WDOG_CNT, REFRESH);
#else
	if (ext_reset)
		val = 0x14;
	else
		val = 0x24;

	DMSG("val %x\n", val);

	io_write16(wdog_base + WDT_WCR, val);
	dsb();

	if (io_read16(wdog_base + WDT_WCR) & WDT_WCR_WDE) {
		io_write16(wdog_base + WDT_WSR, WDT_SEQ1);
		io_write16(wdog_base + WDT_WSR, WDT_SEQ2);
	}

	io_write16(wdog_base + WDT_WCR, val);
	io_write16(wdog_base + WDT_WCR, val);
#endif

	while (1)
		;
}
DECLARE_KEEP_PAGER(imx_wdog_restart);

#if defined(CFG_DT) && !defined(CFG_EXTERNAL_DTB_OVERLAY)
static TEE_Result imx_wdog_base(vaddr_t *wdog_vbase)
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
#else
	static const char * const wdog_path[] = {
		"/soc/aips-bus@2000000/wdog@20bc000",
		"/soc/aips-bus@2000000/wdog@20c0000",
	};
#endif

	fdt = get_dt();
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

	*wdog_vbase = vbase;

	return TEE_SUCCESS;
}
#else
register_phys_mem_pgdir(MEM_AREA_IO_SEC, WDOG_BASE, CORE_MMU_PGDIR_SIZE);
static TEE_Result imx_wdog_base(vaddr_t *wdog_vbase)
{
	*wdog_vbase = (vaddr_t)phys_to_virt(WDOG_BASE, MEM_AREA_IO_SEC);
#if defined(CFG_IMX_WDOG_EXT_RESET)
	ext_reset = true;
#endif
	return TEE_SUCCESS;
}
#endif

static TEE_Result imx_wdog_init(void)
{
#if defined(PLATFORM_FLAVOR_mx7dsabresd) || \
	defined(PLATFORM_FLAVOR_mx7dclsom)

	ext_reset = true;
#endif
	return imx_wdog_base(&wdog_base);
}
driver_init(imx_wdog_init);
