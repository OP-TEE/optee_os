/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2021, Linaro Limited
 * Copyright (c) 2021, Bootlin
 * Copyright (c) 2021, STMicroelectronics
 */

#ifndef __KERNEL_DT_DRIVER_H
#define __KERNEL_DT_DRIVER_H

#include <kernel/dt.h>
#include <stdint.h>
#include <sys/queue.h>
#include <tee_api_types.h>

/*
 * Type indentifiers for registered device drivers consumer can query
 *
 * DT_DRIVER_NOTYPE Generic type for when no generic FDT parsing is supported
 * DT_DRIVER_UART   UART driver currently designed for console means
 * DT_DRIVER_CLK    Clock controller using generic clock DT bindings
 * DT_DRIVER_RSTCTRL Reset controller using generic reset DT bindings
 * DT_DRIVER_I2C    I2C bus controller using generic I2C bus DT bindings
 * DT_DRIVER_GPIO   GPIO controller using generic GPIO DT bindings
 * DT_DRIVER_PINCTRL Pin controller using generic reset DT bindings
 * DT_DRIVER_INTERRUPT Interrupt controller using generic DT bindings
 * DT_DRIVER_REGULATOR Voltage regulator controller using generic DT bindings
 * DT_DRIVER_NVMEM NVMEM controller using generic NVMEM DT bindings
 */
enum dt_driver_type {
	DT_DRIVER_NOTYPE,
	DT_DRIVER_UART,
	DT_DRIVER_CLK,
	DT_DRIVER_RSTCTRL,
	DT_DRIVER_I2C,
	DT_DRIVER_GPIO,
	DT_DRIVER_PINCTRL,
	DT_DRIVER_INTERRUPT,
	DT_DRIVER_REGULATOR,
	DT_DRIVER_NVMEM,
};

/*
 * dt_driver_probe_func - Callback probe function for a driver.
 *
 * @fdt: FDT base address
 * @nodeoffset: Offset of the node in the FDT
 * @compat_data: Data registered for the compatible that probed the device
 *
 * Return TEE_SUCCESS on successful probe,
 *	TEE_ERROR_DEFER_DRIVER_INIT if probe must be deferred
 *	TEE_ERROR_ITEM_NOT_FOUND when no driver matched node's compatible string
 *	Any other TEE_ERROR_* compliant code.
 */
typedef TEE_Result (*dt_driver_probe_func)(const void *fdt, int nodeoffset,
					   const void *compat_data);

/*
 * Driver instance registered to be probed on compatible node found in the DT.
 *
 * @name: Driver name
 * @type: Drive type
 * @match_table: Compatible matching identifiers, null terminated
 * @driver: Driver private reference or NULL
 * @probe: Probe callback (see dt_driver_probe_func) or NULL
 */
struct dt_driver {
	const char *name;
	enum dt_driver_type type;
	const struct dt_device_match *match_table; /* null-terminated */
	const void *driver;
	TEE_Result (*probe)(const void *fdt, int node, const void *compat_data);
};

#define DEFINE_DT_DRIVER(name) \
		SCATTERED_ARRAY_DEFINE_PG_ITEM(dt_drivers, struct dt_driver)

#define for_each_dt_driver(drv) \
	for (drv = SCATTERED_ARRAY_BEGIN(dt_drivers, struct dt_driver); \
	     drv < SCATTERED_ARRAY_END(dt_drivers, struct dt_driver); \
	     drv++)

/* Opaque reference to DT driver device provider instance */
struct dt_driver_provider;

/**
 * struct dt_pargs - Devicetree phandle arguments
 * @fdt: Device-tree to work on
 * @phandle_node: Node pointed by the specifier phandle
 * @args_count: Count of cells for the device
 * @args: Device consumer specifiers
 */
struct dt_pargs {
	const void *fdt;
	int phandle_node;
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
 * @device_ref: output device reference upon success, e.g. a struct clk
 *	pointer for a clock driver.
 *
 * Return code:
 * TEE_SUCCESS in case of success
 * TEE_ERROR_DEFER_DRIVER_INIT if device driver is not yet initialized
 * Any TEE_Result compliant code in case of error.
 */
typedef TEE_Result (*get_of_device_func)(struct dt_pargs *parg, void *data,
					 void *device_ref);

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
 * @device_ref: output device opaque reference upon support, for example
 *	a struct clk pointer for a clock driver.

 * Return code:
 * TEE_SUCCESS in case of success,
 * TEE_ERROR_DEFER_DRIVER_INIT if device driver is not yet initialized
 * TEE_ERROR_ITEM_NOT_FOUND if @prop_name does not match a property's name
 *	or @prop_idx does not match any index in @prop_name phandle list
 * Any TEE_Result compliant code in case of error.
 */
TEE_Result dt_driver_device_from_node_idx_prop(const char *prop_name,
					       const void *fdt, int nodeoffset,
					       unsigned int prop_idx,
					       enum dt_driver_type type,
					       void *device_ref);

/*
 * dt_driver_device_from_parent - Return a device instance based on the parent.
 *	This is mainly used for the devices that are children of a controller
 *	such as I2C, SPI and so on.
 *
 * @fdt: FDT base address
 * @nodeoffset: node offset in the FDT
 * @type: Driver type
 * @device_ref: output device opaque reference upon success, for example
 *	a struct i2c_dev pointer for a I2C bus driver
 *
 * Return code:
 * TEE_SUCCESS in case of success,
 * TEE_ERROR_DEFER_DRIVER_INIT if device driver is not yet initialized
 * Any TEE_Result compliant code in case of error.
 */
TEE_Result dt_driver_device_from_parent(const void *fdt, int nodeoffset,
					enum dt_driver_type type,
					void *device_ref);

/*
 * dt_driver_device_from_node_idx_prop_phandle() - Same as
 *	dt_driver_device_from_node_idx_prop() but phandle is not the first
 *	cells in property @prop_name but is passed as an argument.
 *
 * This function is used for DT bindings as "interrupts" property where the
 * property carries the interrupt information but not the interrupt controller
 * phandle which is found in a specific property (here "interrupt-parent").
 */
TEE_Result dt_driver_device_from_node_idx_prop_phandle(const char *prop_name,
						       const void *fdt,
						       int nodeoffs,
						       unsigned int prop_index,
						       enum dt_driver_type type,
						       uint32_t phandle,
						       void *device_ref);

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
 * Return provider private data registered by dt_driver_register_provider()
 */
void *dt_driver_provider_priv_data(struct dt_driver_provider *prv);

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
#endif /* __KERNEL_DT_DRIVER_H */
