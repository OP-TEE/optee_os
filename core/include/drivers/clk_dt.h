/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2021, Bootlin
 */

#ifndef __DRIVERS_CLK_DT_H
#define __DRIVERS_CLK_DT_H

#include <kernel/dt.h>
#include <kernel/dt_driver.h>
#include <stdint.h>
#include <sys/queue.h>

/**
 * CLK_DT_DECLARE - Declare a clock driver
 * @__name: Clock driver name
 * @__compat: Compatible string
 * @__probe: Clock probe function
 */
#define CLK_DT_DECLARE(__name, __compat, __probe) \
	static const struct dt_device_match __name ## _match_table[] = { \
		{ .compatible = __compat }, \
		{ } \
	}; \
	const struct dt_driver __name ## _dt_driver __dt_driver = { \
		.name = # __name, \
		.type = DT_DRIVER_CLK, \
		.match_table = __name ## _match_table, \
		.probe = __probe, \
	}

/**
 * clk_dt_get_by_idx - Get a clock at a specific index in "clocks" property
 *
 * @fdt: Device tree to work on
 * @nodeoffset: Node offset of the subnode containing a clock property
 * @clk_idx: Clock index to get
 * Returns a clk struct pointer matching the clock at index clk_idx in clocks
 * property or NULL if no clock match the given index.
 */
struct clk *clk_dt_get_by_idx(const void *fdt, int nodeoffset,
			      unsigned int clk_idx);

/**
 * clk_dt_get_by_name - Get a clock matching a name in the "clock-names"
 * property
 *
 * @fdt: Device tree to work on
 * @nodeoffset: Node offset of the subnode containing a clock property
 * @name: Clock name to get
 * Returns a clk struct pointer matching the name in "clock-names" property or
 * NULL if no clock match the given name.
 */
struct clk *clk_dt_get_by_name(const void *fdt, int nodeoffset,
			       const char *name);

/**
 * clk_dt_get_func - Typedef of function to get clock from devicetree properties
 *
 * @args: Pointer to devicetree description of the clock to parse
 * @data: Pointer to data given at clk_dt_register_clk_provider() call
 *
 * Returns a clk struct pointer pointing to a clock matching the devicetree
 * description or NULL if invalid description.
 */
typedef struct clk *(*clk_dt_get_func)(struct dt_driver_phandle_args *args,
				       void *data);

/**
 * clk_dt_register_clk_provider - Register a clock provider
 *
 * @fdt: Device tree to work on
 * @nodeoffset: Node offset of the clock
 * @get_dt_clk: Callback to match the devicetree clock with a clock struct
 * @data: Data which will be passed to the get_dt_clk callback
 * Returns TEE_Result value
 */
static inline
TEE_Result clk_dt_register_clk_provider(const void *fdt, int nodeoffset,
					clk_dt_get_func get_dt_clk, void *data)
{
	return dt_driver_register_provider(fdt, nodeoffset,
					   (get_of_device_func)get_dt_clk,
					   data, DT_DRIVER_CLK);
}

/**
 * clk_dt_get_simple_clk: simple clock matching function for single clock
 * providers
 */
static inline
struct clk *clk_dt_get_simple_clk(struct dt_driver_phandle_args *args __unused,
				  void *data)
{
	return data;
}

#endif /* __DRIVERS_CLK_DT_H */
