/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2021, Linaro Limited
 * Copyright (c) 2021, Bootlin
 * Copyright (c) 2021, Linaro Limited
 * Copyright (c) 2021, STMicroelectronics
 */

#ifndef __DT_DRIVER_H
#define __DT_DRIVER_H

#include <kernel/dt.h>
#include <stdint.h>
#include <sys/queue.h>
#include <tee_api_types.h>

/* Opaque reference to DT driver device provider instance */
struct dt_driver_provider;

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
 * @res: Output result code of the operation:
 *	TEE_SUCCESS in case of success
 *	TEE_ERROR_DEFER_DRIVER_INIT if clock is not initialized
 *	Any TEE_Result compliant code in case of error.
 *
 * Return a device opaque reference, e.g. a struct clk pointer for a clock
 * driver, or NULL if not found in which case @res provides the error code.
 */
typedef void *(*get_of_device_func)(struct dt_driver_phandle_args *parg,
				    void *data, TEE_Result *res);

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
 * @type: Driver type
 * @res: Output result code of the operation:
 *	TEE_SUCCESS in case of success
 *	TEE_ERROR_DEFER_DRIVER_INIT if clock is not initialized
 *	Any TEE_Result compliant code in case of error.
 *
 * Return a device opaque reference, e.g. a struct clk pointer for a clock
 * driver, or NULL if not found in which case @res provides the error code.
 */
void *dt_driver_device_from_node_idx_prop(const char *prop_name,
					  const void *fdt, int nodeoffset,
					  unsigned int prop_idx,
					  enum dt_driver_type type,
					  TEE_Result *res);

/*
 * dt_driver_get_crypto() - Request crypto support for driver initialization
 *
 * Return TEE_SUCCESS if cryptography services are initialized, otherwise return
 * TEE_ERROR_DEFER_DRIVER_INIT.
 */
TEE_Result dt_driver_get_crypto(void);

#ifdef CFG_DT
/* Inform DT driver probe sequence that core crypto support is initialized */
void dt_driver_crypt_init_complete(void);
#else
static inline void dt_driver_crypt_init_complete(void) {}
#endif

/*
 * Return driver provider reference from its node offset value in the FDT
 */
struct dt_driver_provider *
dt_driver_get_provider_by_node(int nodeoffset, enum dt_driver_type type);

/*
 * Return driver provider reference from its phandle value in the FDT
 */
struct dt_driver_provider *
dt_driver_get_provider_by_phandle(uint32_t phandle, enum dt_driver_type type);

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

/*
 * Called by bus like nodes to propose a node for dt_driver probing
 *
 * @fdt: FDT base address
 * @nodeoffset: Node offset on the FDT for the device
 */
TEE_Result dt_driver_maybe_add_probe_node(const void *fdt, int nodeoffset);

#ifdef CFG_DT_DRIVER_EMBEDDED_TEST
/*
 * Return TEE_ERROR_NOT_IMPLEMENTED if test are not implemented
 * otherwise return TEE_ERROR_GENERIC if some test has failed
 * otherwise return TEE_SUCCESS (tests succeed or skipped)
 */
TEE_Result dt_driver_test_status(void);
#else
static inline TEE_Result dt_driver_test_status(void)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}
#endif

#endif /* __DT_DRIVER_H */
