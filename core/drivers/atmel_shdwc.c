// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015 Atmel Corporation,
 *                    Nicolas Ferre <nicolas.ferre@atmel.com>
 * Copyright (c) 2021, Microchip
 */

#include <drivers/atmel_shdwc.h>
#include <drivers/sam/at91_ddr.h>
#include <io.h>
#include <kernel/dt.h>
#include <kernel/thread.h>
#include <libfdt.h>
#include <stdbool.h>
#include <tee_api_defines.h>
#include <tee_api_types.h>
#include <trace.h>
#include <types_ext.h>
#include <util.h>

#include "at91_clk.h"

#define SHDW_WK_PIN(reg, cfg)	((reg) & \
					AT91_SHDW_WKUPIS((cfg)->wkup_pin_input))
#define SHDW_RTCWK(reg, cfg)	(((reg) >> ((cfg)->sr_rtcwk_shift)) & 0x1)
#define SHDW_RTTWK(reg, cfg)	(((reg) >> ((cfg)->sr_rttwk_shift)) & 0x1)
#define SHDW_RTCWKEN(cfg)	BIT((cfg)->mr_rtcwk_shift)
#define SHDW_RTTWKEN(cfg)	BIT((cfg)->mr_rttwk_shift)

#define SLOW_CLK_FREQ		32768ULL
#define DBC_PERIOD_US(x)	DIV_ROUND_UP((1000000ULL * (x)), SLOW_CLK_FREQ)

static vaddr_t shdwc_base;
static vaddr_t mpddrc_base;

bool atmel_shdwc_available(void)
{
	return shdwc_base != 0;
}

void __noreturn atmel_shdwc_shutdown(void)
{
	vaddr_t pmc_base = at91_pmc_get_base();

	/*
	 * Mask exception before entering assembly which does not expect to be
	 * interrupted.
	 */
	thread_mask_exceptions(THREAD_EXCP_ALL);

	__atmel_shdwc_shutdown(mpddrc_base, shdwc_base, pmc_base);

	/* We are going to shutdown the CPU so we will never hit this loop */
	while (true)
		;
}

static const unsigned long long sdwc_dbc_period[] = {
	0, 3, 32, 512, 4096, 32768,
};

static uint32_t at91_shdwc_debouncer_value(uint32_t in_period_us)
{
	int i = 0;
	int max_idx = ARRAY_SIZE(sdwc_dbc_period) - 1;
	uint64_t period_us = 0;
	uint64_t max_period_us = DBC_PERIOD_US(sdwc_dbc_period[max_idx]);

	if (in_period_us > max_period_us) {
		DMSG("debouncer period %"PRIu32" too big, using %"PRIu64" us",
		     in_period_us, max_period_us);
		return max_idx;
	}

	for (i = max_idx - 1; i > 0; i--) {
		period_us = DBC_PERIOD_US(sdwc_dbc_period[i]);
		if (in_period_us > period_us)
			break;
	}

	return i + 1;
}

static uint32_t at91_shdwc_get_wakeup_input(const void *fdt, int np)
{
	const uint32_t *prop = NULL;
	uint32_t wk_input_mask = 0;
	uint32_t wuir = 0;
	uint32_t wk_input = 0;
	int child = 0;
	int len = 0;

	fdt_for_each_subnode(child, fdt, np) {
		prop = fdt_getprop(fdt, child, "reg", &len);
		if (!prop || len != sizeof(uint32_t)) {
			DMSG("reg property is missing for node %s",
			     fdt_get_name(fdt, child, NULL));
			continue;
		}
		wk_input = fdt32_to_cpu(*prop);
		wk_input_mask = BIT32(wk_input);
		if (!(wk_input_mask & AT91_SHDW_WKUPEN_MASK)) {
			DMSG("wake-up input %"PRId32" out of bounds ignore",
			     wk_input);
			continue;
		}
		wuir |= wk_input_mask;

		if (fdt_getprop(fdt, child, "atmel,wakeup-active-high", NULL))
			wuir |= AT91_SHDW_WKUPT(wk_input);
	}

	return wuir;
}

static void at91_shdwc_dt_configure(const void *fdt, int np)
{
	const uint32_t *prop = NULL;
	uint32_t mode = 0;
	uint32_t tmp = 0;
	uint32_t input = 0;
	int len = 0;

	prop = fdt_getprop(fdt, np, "debounce-delay-us", &len);
	if (prop && len == sizeof(uint32_t)) {
		tmp = fdt32_to_cpu(*prop);
		mode |= AT91_SHDW_WKUPDBC(at91_shdwc_debouncer_value(tmp));
	}

	if (fdt_getprop(fdt, np, "atmel,wakeup-rtc-timer", &len))
		mode |= AT91_SHDW_RTCWKEN;

	io_write32(shdwc_base + AT91_SHDW_MR, mode);

	input = at91_shdwc_get_wakeup_input(fdt, np);
	io_write32(shdwc_base + AT91_SHDW_WUIR, input);
}

static TEE_Result atmel_shdwc_probe(const void *fdt, int node,
				    const void *compat_data __unused)
{
	int ddr_node = 0;
	size_t size = 0;
	uint32_t ddr = AT91_DDRSDRC_MD_LPDDR2;

	/*
	 * Assembly code relies on the fact that there is only one CPU to avoid
	 * any other one to invalidate TLB/I-Cache.
	 */
	COMPILE_TIME_ASSERT(CFG_TEE_CORE_NB_CORE == 1);

	if (dt_map_dev(fdt, node, &shdwc_base, &size) < 0)
		return TEE_ERROR_GENERIC;

	ddr_node = fdt_node_offset_by_compatible(fdt, -1,
						 "atmel,sama5d3-ddramc");
	if (ddr_node < 0)
		return TEE_ERROR_GENERIC;

	if (dt_map_dev(fdt, ddr_node, &mpddrc_base, &size) < 0)
		return TEE_ERROR_GENERIC;

	ddr = io_read32(mpddrc_base + AT91_DDRSDRC_MDR) & AT91_DDRSDRC_MD;
	if (ddr != AT91_DDRSDRC_MD_LPDDR2 && ddr != AT91_DDRSDRC_MD_LPDDR3)
		mpddrc_base = 0;

	at91_shdwc_dt_configure(fdt, node);

	return TEE_SUCCESS;
}

static const struct dt_device_match atmel_shdwc_match_table[] = {
	{ .compatible = "atmel,sama5d2-shdwc" },
	{ }
};

DEFINE_DT_DRIVER(atmel_shdwc_dt_driver) = {
	.name = "atmel_shdwc",
	.type = DT_DRIVER_NOTYPE,
	.match_table = atmel_shdwc_match_table,
	.probe = atmel_shdwc_probe,
};
