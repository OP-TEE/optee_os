/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2021, Bootlin
 */

#ifndef __DRIVERS_CLK_DT_H
#define __DRIVERS_CLK_DT_H

#include <drivers/clk.h>
#include <kernel/dt_driver.h>
#include <scattered_array.h>
#include <stdint.h>
#include <sys/queue.h>

/**
 * CLK_DT_DECLARE() - Declare a clock driver
 * @__name: Clock driver name
 * @__compat: Compatible string
 * @__probe: Clock probe function
 */
#define CLK_DT_DECLARE(__name, __compat, __probe) \
	static const struct dt_device_match __name ## _match_table[] = { \
		{ .compatible = __compat }, \
		{ } \
	}; \
	DEFINE_DT_DRIVER(__name ## _dt_driver) = { \
		.name = # __name, \
		.type = DT_DRIVER_CLK, \
		.match_table = __name ## _match_table, \
		.probe = __probe, \
	}

/**
 * clk_dt_get_by_index() - Get a clock at a specific index in "clocks" property
 *
 * @fdt: Device tree to work on
 * @nodeoffset: Node offset of the subnode containing a clock property
 * @clk_idx: Clock index to get
 * @clk: Output clock reference upon success
 *
 * Return TEE_SUCCESS in case of success
 * Return TEE_ERROR_DEFER_DRIVER_INIT if clock is not initialized
 * Return TEE_ERROR_ITEM_NOT_FOUND if the DT does not provide a clock reference
 * Return any other TEE_Result compliant code in case of error
 */
TEE_Result clk_dt_get_by_index(const void *fdt, int nodeoffset,
			       unsigned int clk_idx, struct clk **clk);

/**
 * clk_dt_get_by_name() - Get a clock matching a name in "clock-names" property
 *
 * @fdt: Device tree to work on
 * @nodeoffset: Node offset of the subnode containing a clock property
 * @name: Clock name to get
 * @clk: Output clock reference upon success
 *
 * Return TEE_SUCCESS in case of success
 * Return TEE_ERROR_DEFER_DRIVER_INIT if clock is not initialized
 * Return TEE_ERROR_ITEM_NOT_FOUND if the DT does not provide a clock reference
 * Return any other TEE_Result compliant code in case of error
 */
TEE_Result clk_dt_get_by_name(const void *fdt, int nodeoffset,
			      const char *name, struct clk **clk);

/**
 * clk_dt_get_func - Typedef of function to get clock from devicetree properties
 *
 * @args: Pointer to devicetree description of the clock to parse
 * @data: Pointer to data given at clk_dt_register_clk_provider() call
 * @clk: Output clock reference upon success
 */
typedef TEE_Result (*clk_dt_get_func)(struct dt_pargs *args, void *data,
				      struct clk **out_clk);

/**
 * clk_dt_register_clk_provider() - Register a clock provider
 *
 * @fdt: Device tree to work on
 * @nodeoffset: Node offset of the clock
 * @func: Callback to match the devicetree clock with a clock struct
 * @data: Data which will be passed to the get_dt_clk callback
 * Returns TEE_Result value
 */
static inline TEE_Result clk_dt_register_clk_provider(const void *fdt,
						      int nodeoffset,
						      clk_dt_get_func func,
						      void *data)
{
	return dt_driver_register_provider(fdt, nodeoffset,
					   (get_of_device_func)func, data,
					   DT_DRIVER_CLK);
}

/**
 * clk_dt_get_simple_clk() - Simple clock matching function for single clock
 * providers
 *
 * @args: Unused argument as there is no description to parse
 * @data: Pointer to data given at clk_dt_register_clk_provider() call
 * @out_clk: Output clock reference filled with @data
 */
static inline TEE_Result clk_dt_get_simple_clk(struct dt_pargs *args __unused,
					       void *data, struct clk **out_clk)
{
	*out_clk = data;

	return TEE_SUCCESS;
}

#endif /* __DRIVERS_CLK_DT_H */
