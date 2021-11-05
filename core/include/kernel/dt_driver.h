/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2021, Linaro Limited
 * Copyright (c) 2021, Bootlin
 */

#ifndef __DT_DRIVER_H
#define __DT_DRIVER_H

#include <kernel/dt.h>
#include <stdint.h>
#include <sys/queue.h>
#include <tee_api_types.h>

/**
 * struct dt_driver_phandle_args - Devicetree phandle arguments
 * @args_count: Count of cells for the device
 * @args: Device consumer specifiers
 */
struct dt_driver_phandle_args {
	int args_count;
	uint32_t args[];
};

/*
 * get_of_device_func - Callback function for returning a driver private
 *	instance based on a FDT phandle with possible arguments and the
 *	registered dt_driver private data reference.
 *
 * @parg: phandle argument(s) referencing the device in the FDT.
 * @data: driver private data registered in struct dt_driver.
 *
 * Return a device opaque reference, e.g. a struct clk pointer for a clock
 * driver, or NULL if not found.
 */
typedef void *(*get_of_device_func)(struct dt_driver_phandle_args *parg,
				    void *data);

/*
 * struct dt_driver_provider - DT related info on probed device
 *
 * Saves information on the probed device so that device
 * drivers can get resources from DT phandle and related arguments.
 *
 * @nodeoffset: Node offset of device referenced in the FDT
 * @type: One of DT_DRIVER_* or DT_DRIVER_NOTYPE.
 * @provider_cells: Cells count in the FDT used by the driver's references
 * @get_of_device: Function to get driver's device ref from phandle data
 * @priv_data: Driver private data passed as @get_of_device argument
 * @link: Reference in DT driver providers list
 */
struct dt_driver_provider {
	int nodeoffset;
	enum dt_driver_type type;
	unsigned int provider_cells;
	uint32_t phandle;
	get_of_device_func get_of_device;
	void *priv_data;
	SLIST_ENTRY(dt_driver_provider) link;
};

SLIST_HEAD(dt_driver_prov_list, dt_driver_provider);
extern struct dt_driver_prov_list dt_driver_provider_list;

/**
 * dt_driver_register_provider - Register a driver provider
 *
 * @fdt: Device tree to work on
 * @nodeoffset: Node offset in the FDT
 * @get_of_device: Function to match the devicetree with a device instance
 * @data: Data which will be passed to the @get_of_device callback
 * @type: Driver type
 *
 * @get_of_device returns a void *. Driver provider is expected to
 * include a shim helper to cast to device reference into provider driver
 * target structure reference (e.g (struct clk *) for clock devices).
 */
TEE_Result dt_driver_register_provider(const void *fdt, int nodeoffset,
				       get_of_device_func get_of_device,
				       void *data, enum dt_driver_type type);

/*
 * dt_driver_device_from_node_idx_prop - Return a device instance based on a
 *	property name and FDT information
 *
 * @prop_name: DT property name, e.g. "clocks" for clock resources
 * @fdt: FDT base address
 * @nodeoffset: node offset in the FDT
 * @prop_idx: index of the phandle data in the property
 *
 * Return a device opaque reference, e.g. a struct clk pointer for a clock
 * driver, or NULL if not found.
 */
void *dt_driver_device_from_node_idx_prop(const char *prop_name,
					  const void *fdt, int nodeoffset,
					  unsigned int prop_idx);

/*
 * Return driver provider reference from its node offset value in the FDT
 */
struct dt_driver_provider *dt_driver_get_provider_by_node(int nodeoffset);

/*
 * Return driver provider reference from its phandle value in the FDT
 */
struct dt_driver_provider *dt_driver_get_provider_by_phandle(uint32_t phandle);

/*
 * Return number cells used for phandle arguments by a driver provider
 */
unsigned int dt_driver_provider_cells(struct dt_driver_provider *prv);

/*
 * dt_driver_probe_device_by_node - Probe matching driver to create a device
 *	from a FDT node
 *
 * @fdt: FDT base address
 * @nodeoffset: Node byte offset from FDT base
 * @type: Target driver to match or DT_DRIVER_ANY
 *
 * Read the dt_driver database. Compatible list is looked up in the order
 * of the FDT "compatible" property list. @type can be used to probe only
 * specific drivers.
 *
 */
TEE_Result dt_driver_probe_device_by_node(const void *fdt, int nodeoffset,
					  enum dt_driver_type type);

/*
 * Get cells count of a device node given its dt_driver type
 *
 * @fdt: FDT base address
 * @nodeoffset: Node offset on the FDT for the device
 * @type: One of the supported DT_DRIVER_* value.
 *
 * Currently supports type DT_DRIVER_CLK.
 * Return a positive cell count value (>= 0) or a negative FDT_ error code
 */
int fdt_get_dt_driver_cells(const void *fdt, int nodeoffset,
			    enum dt_driver_type type);
#endif /* __DT_DRIVER_H */
