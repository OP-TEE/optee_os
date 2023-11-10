// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022 Microchip
 */

#include <assert.h>
#include <config.h>
#include <drivers/clk.h>
#include <drivers/clk_dt.h>
#include <kernel/boot.h>
#include <kernel/dt.h>
#include <kernel/panic.h>
#include <libfdt.h>

static unsigned long freq;

static TEE_Result get_freq_from_dt(void)
{
	int node;
	struct clk *clk;
	const void *fdt = get_embedded_dt();

	if (!fdt)
		panic();

	if (IS_ENABLED(CFG_SAMA7G5))
		node = fdt_node_offset_by_compatible(fdt, -1, "arm,cortex-a7");
	else
		node = fdt_node_offset_by_compatible(fdt, -1, "arm,cortex-a5");

	if (!node)
		panic();

	if (clk_dt_get_by_name(fdt, node, "cpu", &clk))
		panic();

	freq = clk_get_rate(clk);

	return TEE_SUCCESS;
}
early_init_late(get_freq_from_dt);

unsigned long plat_get_freq(void)
{
	assert(freq);

	return freq;
}
