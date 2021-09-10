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
#endif /* __DT_DRIVER_H */
