// SPDX-License-Identifier: BSD-2-Clause
/*
 *  Copyright (C) 2024 Microchip Technology Inc.
 */

#include <at91_clk.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <malloc.h>
#include <libfdt.h>
#include <trace.h>

#define OPP_RATES_MAX 8

/* the clock rates for CPU OPP */
struct clk_rates {
	size_t rate_num; /* the number of valid clock rates in @rates */
	unsigned long rates[OPP_RATES_MAX];
};

static struct clk_rates *opp_rates;

static TEE_Result dt_get_opp_hz(const void *fdt, int node, unsigned long *value)
{
	const char *property = "opp-hz";
	const fdt64_t *p = NULL;
	int len = 0;

	p = fdt_getprop(fdt, node, property, &len);
	if (!p)
		return TEE_ERROR_ITEM_NOT_FOUND;

	if (len != sizeof(*p))
		return TEE_ERROR_BAD_FORMAT;

	*value = fdt64_ld(p);

	return TEE_SUCCESS;
}

static TEE_Result opp_rates_setup(const void *fdt, int node)
{
	const char *compatible = "operating-points-v2";
	const fdt32_t *cuint = NULL;
	size_t rate_num = 0;
	int opp_table = 0;
	int offset = 0;

	cuint = fdt_getprop(fdt, node, compatible, NULL);
	if (!cuint)
		return TEE_ERROR_NOT_SUPPORTED;

	opp_rates = calloc(1, sizeof(*opp_rates));
	if (!opp_rates) {
		EMSG("Fail to alloc opp_rates");

		return TEE_ERROR_OUT_OF_MEMORY;
	}

	offset = fdt_node_offset_by_phandle(fdt, fdt32_to_cpu(*cuint));
	if (offset < 0)
		panic("Invalid offset of opp-table");

	if (fdt_node_check_compatible(fdt, offset, compatible))
		panic("Invalid opp-table");

	fdt_for_each_subnode(opp_table, fdt, offset) {
		if (rate_num >= OPP_RATES_MAX)
			panic("CPU OPP rate array shortage");

		if (dt_get_opp_hz(fdt, opp_table, opp_rates->rates + rate_num))
			panic("Get opp-hz failed");

		rate_num++;
	}
	opp_rates->rate_num = rate_num;

	return TEE_SUCCESS;
}

TEE_Result at91_clk_register_cpu_opp(const void *fdt, int node,
				     struct clk *clk __unused)
{
	return opp_rates_setup(fdt, node);
}
