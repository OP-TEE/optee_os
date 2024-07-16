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

static TEE_Result get_rates_array(struct clk *clk __unused, size_t start_index,
				  unsigned long *rates, size_t *nb_elts)
{
	if (!opp_rates)
		panic("Invalid CPU OPP Rates Array");

	if (!rates) {
		*nb_elts = opp_rates->rate_num;

		return TEE_SUCCESS;
	}

	if (start_index + *nb_elts > opp_rates->rate_num) {
		EMSG("Bad parameter(s): start_index %zu, nb_elts %zu",
		     start_index, *nb_elts);

		return TEE_ERROR_BAD_PARAMETERS;
	}
	memcpy(rates, &opp_rates->rates[start_index],
	       *nb_elts * sizeof(*rates));

	return TEE_SUCCESS;
}

static TEE_Result cpu_opp_clk_set_rate(struct clk *clk, unsigned long rate,
				       unsigned long parent_rate)
{
	size_t n = 0;

	assert(clk->parent);

	for (n = 0; n < opp_rates->rate_num; n++)
		if (rate == opp_rates->rates[n])
			break;
	if (n == opp_rates->rate_num)
		return TEE_ERROR_BAD_PARAMETERS;

	return clk->parent->ops->set_rate(clk->parent, rate, parent_rate);
}

static const struct clk_ops cpu_opp_clk_ops = {
	.set_rate = cpu_opp_clk_set_rate,
	.get_rates_array = get_rates_array,
};

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

	/* Ensure rates are in ascending order */
	qsort_ul(opp_rates->rates, rate_num);

	opp_rates->rate_num = rate_num;

	return TEE_SUCCESS;
}

static struct clk *cpu_opp_clk;

struct clk *at91_cpu_opp_clk_get(void)
{
	return cpu_opp_clk;
}

TEE_Result at91_clk_register_cpu_opp(const void *fdt, int node, struct clk *clk)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	res = opp_rates_setup(fdt, node);
	if (res == TEE_ERROR_NOT_SUPPORTED)
		return TEE_SUCCESS;
	if (res)
		return res;

	cpu_opp_clk = clk_alloc("cpu-opp", &cpu_opp_clk_ops, &clk, 1);
	if (!cpu_opp_clk)
		panic("CPU OPP clock alloc failed");

	res = clk_register(cpu_opp_clk);
	if (res) {
		clk_free(cpu_opp_clk);
		return res;
	}

	/* CPU clock is likely always enabled so set its refcount */
	if (clk_enable(cpu_opp_clk))
		panic("CPU clock should always enabled");

	return TEE_SUCCESS;
}
