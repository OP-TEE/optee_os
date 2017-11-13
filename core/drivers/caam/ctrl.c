// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2017-2018 NXP
 *
 */

#include <mm/core_memprot.h>
#include <kernel/dt.h>
#include <kernel/generic_boot.h>
#include <initcall.h>
#include <trace.h>
#include <types_ext.h>
#include <io.h>
#include <libfdt.h>

#include <imx.h>
#include <imx-regs.h>

#include "intern.h"
#include "ctrl_regs.h"
#include "version_regs.h"
#include "rng_regs.h"

//#define DRV_DEBUG
#ifdef DRV_DEBUG
#define DRV_TRACE(...)	trace_printf(__func__, __LINE__, 0, false, __VA_ARGS__)
#else
#define DRV_TRACE(...)
#endif

static const char *dt_ctrl_match_table = {
	"fsl,sec-v4.0-ctrl",
};

static void caam_clock_enable(unsigned char enable __maybe_unused)
{
#if !defined(CFG_MX7ULP)
	vaddr_t  ccm_base = (vaddr_t)phys_to_virt(CCM_BASE, MEM_AREA_IO_SEC);
#endif
#if defined(CFG_MX6) || defined(CFG_MX6UL)
	uint32_t reg;
	uint32_t mask;

	reg = read32(ccm_base + CCM_CCGR0);

	mask = (BM_CCM_CCGR0_CAAM_WRAPPER_IPG  |
			BM_CCM_CCGR0_CAAM_WRAPPER_ACLK |
			BM_CCM_CCGR0_CAAM_SECURE_MEM);

	if (enable) {
		reg |= mask;
	} else {
		reg &= ~mask;
	}

	write32(reg, (ccm_base + CCM_CCGR0));

	if (!soc_is_imx6ul()) {
		/* EMI slow clk */
		reg  = read32(ccm_base + CCM_CCGR6);
		mask = BM_CCM_CCGR6_EMI_SLOW;

		if (enable) {
			reg |= mask;
		} else {
			reg &= ~mask;
		}

		write32(reg, (ccm_base + CCM_CCGR6));
	}

#elif defined(CFG_MX7)
	if (enable) {
		write32(CCM_CCGRx_ALWAYS_ON(0),
			ccm_base + CCM_CCGRx_SET(CCM_CLOCK_DOMAIN_CAAM));
	} else {
		write32(CCM_CCGRx_ALWAYS_ON(0),
			ccm_base + CCM_CCGRx_CLR(CCM_CLOCK_DOMAIN_CAAM));
	}
#endif
}

static TEE_Result caam_init(void)
{
	TEE_Result ret = TEE_SUCCESS;
	size_t  size;
	vaddr_t ctrl_base;
	uint32_t jrnum, idx;

	void *fdt;
	int  node;

	fdt = get_dt_blob();
	if (!fdt) {
		DRV_TRACE("No DTB\n");
		return TEE_ERROR_NOT_SUPPORTED;
	}

	node = fdt_node_offset_by_compatible(fdt, 0, dt_ctrl_match_table);

	if (node < 0) {
		DRV_TRACE("Caam Node not found err = 0x%X\n", node);
	}

	/* Map the device in the system if not already present */
	if (dt_map_dev(fdt, node, &ctrl_base, &size) < 0) {
		DRV_TRACE("CAAM device not defined or not enabled\n");
		ret = TEE_ERROR_GENERIC;
		goto probe_exit;
	}

	/* Enable the CAAM clock - at this stage the OS is not loaded */
	caam_clock_enable(1);

	/*
	 * Enable DECO watchdogs
	 */
	io_mask32(ctrl_base + MCFGR, BM_MCFGR_WDE, BM_MCFGR_WDE);

	/*
	 * ERRATA:  mx6 devices have an issue wherein AXI bus transactions
	 * may not occur in the correct order. This isn't a problem running
	 * single descriptors, but can be if running multiple concurrent
	 * descriptors. Reworking the driver to throttle to single requests
	 * is impractical, thus the workaround is to limit the AXI pipeline
	 * to a depth of 1 (from it's default of 4) to preclude this situation
	 * from occurring.
	 *
	 * mx7 devices, this bit has no effect.
	 */
	io_mask32(ctrl_base + MCFGR, (1 << BS_MCFGR_AXIPIPE), BM_MCFGR_AXIPIPE);

	/*
	 * Make all Job Rings available in the HW as accessible in Non-Secure.
	 * Job Rings used by the TEE will be secured by the JR Driver Loaded
	 * itself.
	 * Don't Lock the configuration yet, will be done after loading all
	 * Job Ring drivers
	 */
	jrnum = read32(ctrl_base + CHANUM_MS) & BM_CHANUM_MS_JRNUM;
	jrnum >>= BS_CHANUM_MS_JRNUM;
	DRV_TRACE("Number of Job Ring available = %d", jrnum);

	if (jrnum == 0) {
		EMSG("No HW Job Ring available");
		ret = TEE_ERROR_GENERIC;
		goto probe_exit;
	}

	for (idx = 0; idx < jrnum; idx++) {
		write32(((MSTRID_NS_ARM << BS_JRxMIDR_LS_NONSEQ_MID) |
				 (MSTRID_NS_ARM << BS_JRxMIDR_LS_SEQ_MID)),
				ctrl_base + JRxMIDR_LS(idx));
		write32((MSTRID_NS_ARM << BS_JRxMIDR_MS_JROWN_MID),
				ctrl_base + JRxMIDR_MS(idx));
	}

	/* Lock all Job Ring access configuration */
	for (idx = 0; idx < jrnum; idx++) {
		DRV_TRACE("Lock JR[%d] Configuration", idx);
		io_mask32(ctrl_base + JRxMIDR_MS(idx),
			BM_JRxMIDR_MS_LMID, BM_JRxMIDR_MS_LMID);
	}


	/*
	 * Configure the TRNG Entropy delay because some soc have no
	 * access to the TRNG registers in Non-Secure (e.g. 6SX)
	 */
	kick_trng(ctrl_base, TRNG_SDCTL_ENT_DLY_MIN);

probe_exit:
	return ret;
}


driver_init(caam_init);
