// SPDX-License-Identifier: GPL-2.0+ or BSD-3-Clause
/*
 *  Copyright (C) 2013 Boris BREZILLON <b.brezillon@overkiz.com>
 *  Copyright (C) 2021 Microchip
 */

#include "at91_clk.h"
#include <drivers/clk.h>
#include <drivers/clk_dt.h>

static struct clk *slow_clk;

#define SLOW_CLOCK_FREQ			32768

struct clk *at91_sckc_clk_get(void)
{
	return slow_clk;
}

static unsigned long sckc_get_rate(struct clk *clk __unused,
				   unsigned long parent_rate __unused)
{
	return SLOW_CLOCK_FREQ;
}

static const struct clk_ops sckc_clk_ops = {
	.get_rate = sckc_get_rate,
};

static TEE_Result sckc_pmc_setup(const void *fdt __unused, int offs,
				 const void *data __unused)
{
	struct clk *clk = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (slow_clk)
		return TEE_ERROR_GENERIC;

	clk = clk_alloc("slowck", &sckc_clk_ops, NULL, 0);
	if (!clk)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = clk_register(clk);
	if (res) {
		clk_free(clk);
		return res;
	}

	res = clk_dt_register_clk_provider(fdt, offs, clk_dt_get_simple_clk,
					   clk);
	if (res)
		return res;

	slow_clk = clk;

	return TEE_SUCCESS;
}

static const struct dt_device_match at91_sckc_match_table[] = {
	{ .compatible = "atmel,sama5d4-sckc" },
	{ .compatible = "microchip,sama7g5-sckc" },
	{ }
};

DEFINE_DT_DRIVER(at91_sckc_dt_driver) = {
	.name = "at91_sckc",
	.type = DT_DRIVER_CLK,
	.match_table = at91_sckc_match_table,
	.probe = sckc_pmc_setup,
};
