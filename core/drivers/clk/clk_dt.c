// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021, Bootlin
 */

#include <assert.h>
#include <drivers/clk.h>
#include <drivers/clk_dt.h>
#include <initcall.h>
#include <kernel/boot.h>
#include <kernel/dt_driver.h>
#include <kernel/panic.h>
#include <libfdt.h>
#include <stddef.h>

TEE_Result clk_dt_get_by_name(const void *fdt, int nodeoffset,
			      const char *name, struct clk **clk)
{
	int clk_id = 0;

	clk_id = fdt_stringlist_search(fdt, nodeoffset, "clock-names", name);
	if (clk_id < 0) {
		*clk = NULL;
		return TEE_ERROR_GENERIC;
	}

	return clk_dt_get_by_index(fdt, nodeoffset, clk_id, clk);
}

static TEE_Result clk_dt_get_by_idx_prop(const char *prop_name, const void *fdt,
					 int nodeoffset, unsigned int clk_idx,
					 struct clk **clk)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	*clk = dt_driver_device_from_node_idx_prop(prop_name, fdt, nodeoffset,
						   clk_idx, DT_DRIVER_CLK,
						   &res);
	return res;
}

TEE_Result clk_dt_get_by_index(const void *fdt, int nodeoffset,
			       unsigned int clk_idx, struct clk **clk)
{
	return clk_dt_get_by_idx_prop("clocks", fdt, nodeoffset, clk_idx, clk);
}

#ifdef CFG_DRIVERS_CLK_EARLY_PROBE
/* Recursively called from parse_clock_property() */
static TEE_Result clk_probe_clock_provider_node(const void *fdt, int node);

static TEE_Result parse_clock_property(const void *fdt, int node)
{
	int len = 0;
	int idx = 0;
	int parent_node = 0;
	int clock_cells = 0;
	uint32_t phandle = 0;
	const uint32_t *prop = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;

	prop = fdt_getprop(fdt, node, "clocks", &len);
	if (!prop)
		return TEE_SUCCESS;

	len /= sizeof(uint32_t);
	while (idx < len) {
		phandle = fdt32_to_cpu(prop[idx]);

		parent_node = fdt_node_offset_by_phandle(fdt, phandle);
		if (parent_node < 0)
			return TEE_ERROR_GENERIC;

		/* Parent probe should not fail or clock won't be available */
		res = clk_probe_clock_provider_node(fdt, parent_node);
		if (res) {
			EMSG("Probe parent clock node %s on node %s: %#"PRIx32,
			     fdt_get_name(fdt, parent_node, NULL),
			     fdt_get_name(fdt, node, NULL), res);
			panic();
		}

		clock_cells = fdt_get_dt_driver_cells(fdt, parent_node,
						      DT_DRIVER_CLK);
		if (clock_cells < 0)
			return TEE_ERROR_GENERIC;

		idx += 1 + clock_cells;
	}

	return TEE_SUCCESS;
}

static TEE_Result clk_probe_clock_provider_node(const void *fdt, int node)
{
	int len = 0;
	int status = 0;
	TEE_Result res = TEE_ERROR_GENERIC;

	status = _fdt_get_status(fdt, node);
	if (!(status & DT_STATUS_OK_SEC))
		return TEE_ERROR_ITEM_NOT_FOUND;

	/* Check if the node is a clock provider */
	if (!fdt_getprop(fdt, node, "#clock-cells", &len))
		return TEE_ERROR_ITEM_NOT_FOUND;

	/* Check if node has already been probed */
	if (dt_driver_get_provider_by_node(node, DT_DRIVER_CLK))
		return TEE_SUCCESS;

	/* Check if the node has a clock property first to probe parent */
	res = parse_clock_property(fdt, node);
	if (res)
		return res;

	return dt_driver_probe_device_by_node(fdt, node, DT_DRIVER_CLK);
}

static void clk_probe_node(const void *fdt, int parent_node)
{
	int child = 0;
	int status = 0;
	__maybe_unused TEE_Result res = TEE_ERROR_GENERIC;

	fdt_for_each_subnode(child, fdt, parent_node) {
		status = _fdt_get_status(fdt, child);
		if (status == DT_STATUS_DISABLED)
			continue;

		res = clk_probe_clock_provider_node(fdt, child);
		assert(res == TEE_SUCCESS || res == TEE_ERROR_ITEM_NOT_FOUND);

		clk_probe_node(fdt, child);
	}
}

static void parse_assigned_clock(const void *fdt, int nodeoffset)
{
	int rate_len = 0;
	int clock_idx = 0;
	struct clk *clk = NULL;
	unsigned long rate = 0;
	struct clk *parent = NULL;
	const uint32_t *rate_prop = NULL;
	TEE_Result __maybe_unused res = TEE_ERROR_GENERIC;

	rate_prop = fdt_getprop(fdt, nodeoffset, "assigned-clock-rates",
				&rate_len);
	rate_len /= sizeof(uint32_t);

	while (true) {
		res = clk_dt_get_by_idx_prop("assigned-clocks", fdt, nodeoffset,
					     clock_idx, &clk);
		if (!clk)
			return;
		assert(!res);

		res = clk_dt_get_by_idx_prop("assigned-clock-parents", fdt,
					     nodeoffset, clock_idx, &parent);
		if (parent) {
			assert(!res);
			if (clk_set_parent(clk, parent)) {
				EMSG("Could not set clk %s parent to clock %s",
				     clk->name, parent->name);
				panic();
			}
		}

		if (rate_prop && clock_idx < rate_len) {
			rate = fdt32_to_cpu(rate_prop[clock_idx]);
			if (rate && clk_set_rate(clk, rate) != TEE_SUCCESS)
				panic();
		}

		clock_idx++;
	}
}

static void clk_probe_assigned(const void *fdt, int parent_node)
{
	int len = 0;
	int child = 0;
	int status = 0;

	fdt_for_each_subnode(child, fdt, parent_node) {
		clk_probe_assigned(fdt, child);

		status = _fdt_get_status(fdt, child);
		if (status == DT_STATUS_DISABLED)
			continue;

		if (fdt_getprop(fdt, child, "assigned-clocks", &len))
			parse_assigned_clock(fdt, child);
	}
}

static TEE_Result clk_dt_probe(void)
{
	const void *fdt = get_embedded_dt();

	DMSG("Probing clocks from devicetree");
	if (!fdt)
		panic();

	clk_probe_node(fdt, -1);

	clk_probe_assigned(fdt, -1);

	return TEE_SUCCESS;
}
early_init(clk_dt_probe);
#endif
