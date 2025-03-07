// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2024, Microchip
 */

#include <assert.h>
#include <drivers/clk.h>
#include <drivers/clk_dt.h>
#include <kernel/dt_driver.h>
#include <string.h>

#define MCHP_PIT64B_FREQ		UL(5000000)	/* 5 MHz */

static TEE_Result microchip_pit_probe(const void *fdt, int node,
				      const void *compat_data __unused)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct clk *parent = NULL;
	struct clk *pclk = NULL;
	struct clk *gclk = NULL;
	size_t i = 0;

	res = clk_dt_get_by_name(fdt, node, "pclk", &pclk);
	if (res)
		return res;

	res = clk_dt_get_by_name(fdt, node, "gclk", &gclk);
	if (res)
		return res;

	res = clk_enable(pclk);
	if (res)
		panic();

	while (1) {
		parent = clk_get_parent_by_index(gclk, i++);
		if (!parent)
			panic();
		if (!memcmp("syspll", clk_get_name(parent),
			    sizeof("syspll") - 1))
			break;
	}

	res = clk_set_parent(gclk, parent);
	if (res)
		panic();

	res = clk_set_rate(gclk, MCHP_PIT64B_FREQ);
	if (res)
		panic();

	return clk_enable(gclk);
}

static const struct dt_device_match microchip_pit_match_table[] = {
	{ .compatible = "microchip,sama7g5-pit64b" },
	{ }
};

DEFINE_DT_DRIVER(microchip_pit_dt_driver) = {
	.name = "microchip_pit",
	.type = DT_DRIVER_NOTYPE,
	.match_table = microchip_pit_match_table,
	.probe = microchip_pit_probe,
};
