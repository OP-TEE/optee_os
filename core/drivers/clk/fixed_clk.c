// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021, Bootlin
 */

#include <drivers/clk.h>
#include <drivers/clk_dt.h>
#include <libfdt.h>
#include <malloc.h>
#include <stdint.h>

struct fixed_clock_data {
	unsigned long rate;
};

static unsigned long fixed_clk_get_rate(struct clk *clk,
					unsigned long parent_rate __unused)
{
	struct fixed_clock_data *d = clk->priv;

	return d->rate;
}

static const struct clk_ops fixed_clk_clk_ops = {
	.get_rate = fixed_clk_get_rate,
};

static TEE_Result fixed_clock_probe(const void *fdt, int offs,
				    const void *compat_data __unused)
{
	const uint32_t *freq = NULL;
	const char *name = NULL;
	struct clk *clk = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;
	struct fixed_clock_data *fcd = NULL;

	name = fdt_get_name(fdt, offs, NULL);
	if (!name)
		name = "fixed-clock";

	clk = clk_alloc(name, &fixed_clk_clk_ops, NULL, 0);
	if (!clk)
		return TEE_ERROR_OUT_OF_MEMORY;

	fcd = calloc(1, sizeof(struct fixed_clock_data));
	if (!fcd) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto free_clk;
	}

	freq = fdt_getprop(fdt, offs, "clock-frequency", NULL);
	if (!freq) {
		res = TEE_ERROR_BAD_FORMAT;
		goto free_fcd;
	}

	fcd->rate = fdt32_to_cpu(*freq);
	clk->priv = fcd;

	res = clk_register(clk);
	if (res)
		goto free_fcd;

	res = clk_dt_register_clk_provider(fdt, offs, clk_dt_get_simple_clk,
					   clk);
	if (!res)
		return TEE_SUCCESS;

free_fcd:
	free(fcd);
free_clk:
	clk_free(clk);

	return res;
}

CLK_DT_DECLARE(fixed_clock, "fixed-clock", fixed_clock_probe);
