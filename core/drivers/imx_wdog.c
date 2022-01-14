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
#include <kernel/boot.h>
#include <kernel/panic.h>
#include <libfdt.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <util.h>

static bool ext_reset_output __maybe_unused;
static vaddr_t wdog_base;

void imx_wdog_restart(bool external_reset __maybe_unused)
{
	uint32_t val = 0;

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
	if (external_reset && ext_reset_output)
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
static const char * const dt_wdog_match_table[] = {
	"fsl,imx21-wdt",
	"fsl,imx7ulp-wdt",
};

static TEE_Result imx_wdog_base(vaddr_t *wdog_vbase)
{
	const char *match = NULL;
	void *fdt = NULL;
	vaddr_t vbase = 0;
	int found_off = 0;
	size_t sz = 0;
	int off = 0;
	int st = 0;
	uint32_t i = 0;

	fdt = get_dt();
	if (!fdt) {
		EMSG("No DTB\n");
		return TEE_ERROR_NOT_SUPPORTED;
	}

	/* search the first usable wdog */
	for (i = 0; i < ARRAY_SIZE(dt_wdog_match_table); i++) {
		match = dt_wdog_match_table[i];
		off = 0;
		while (off >= 0) {
			off = fdt_node_offset_by_compatible(fdt, off, match);
			if (off > 0) {
				st = _fdt_get_status(fdt, off);
				if (st & DT_STATUS_OK_SEC) {
					DMSG("Wdog found at %u", off);
					found_off = off;
					break;
				}
			}
		}
		if (found_off)
			break;
		else
			DMSG("%s not found in DTB", dt_wdog_match_table[i]);
	}

	if (!found_off) {
		EMSG("No Watchdog found in DTB\n");
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	ext_reset_output = dt_have_prop(fdt, found_off,
					"fsl,ext-reset-output");

	if (dt_map_dev(fdt, found_off, &vbase, &sz) < 0) {
		EMSG("Failed to map Watchdog\n");
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	*wdog_vbase = vbase;

	return TEE_SUCCESS;
}
#else
register_phys_mem_pgdir(MEM_AREA_IO_SEC, WDOG_BASE, CORE_MMU_PGDIR_SIZE);
static TEE_Result imx_wdog_base(vaddr_t *wdog_vbase)
{
	*wdog_vbase = (vaddr_t)phys_to_virt(WDOG_BASE, MEM_AREA_IO_SEC, 1);
#if defined(CFG_IMX_WDOG_EXT_RESET)
	ext_reset_output = true;
#endif
	return TEE_SUCCESS;
}
#endif

static TEE_Result imx_wdog_init(void)
{
	return imx_wdog_base(&wdog_base);
}
driver_init(imx_wdog_init);
