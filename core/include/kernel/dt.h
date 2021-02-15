/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016-2021, Linaro Limited
 */

#ifndef KERNEL_DT_H
#define KERNEL_DT_H

#include <compiler.h>
#include <kernel/interrupt.h>
#include <kernel/panic.h>
#include <scattered_array.h>
#include <stdint.h>
#include <tee_api_types.h>
#include <types_ext.h>
#include <util.h>

/*
 * Bitfield to reflect status and secure-status values ("okay", "disabled"
 * or not present)
 */
#define DT_STATUS_DISABLED		U(0)
#define DT_STATUS_OK_NSEC		BIT(0)
#define DT_STATUS_OK_SEC		BIT(1)

#define DT_INFO_INVALID_REG		((paddr_t)-1)
#define DT_INFO_INVALID_REG_SIZE	((size_t)-1)
#define DT_INFO_INVALID_CLOCK		-1
#define DT_INFO_INVALID_RESET		-1
#define DT_INFO_INVALID_INTERRUPT	-1

/*
 * @status: Bit mask for DT_STATUS_*
 * @reg: Device register physical base address or DT_INFO_INVALID_REG
 * @reg_size: Device register size or DT_INFO_INVALID_REG_SIZE
 * @clock: Device identifier (positive value) or DT_INFO_INVALID_CLOCK
 * @reset: Device reset identifier (positive value) or DT_INFO_INVALID_CLOCK
 * @interrupt: Device interrupt identifier (positive value) or
 * DT_INFO_INVALID_INTERRUPT
 * @type: IRQ_TYPE_* value parsed from interrupts properties or IRQ_TYPE_NONE if
 * not present
 * @prio: interrupt priority parsed from interrupts properties or 0 if not
 * present
 */
struct dt_node_info {
	unsigned int status;
	paddr_t reg;
	size_t reg_size;
	int clock;
	int reset;
	int interrupt;
	uint32_t type;
	uint32_t prio;
};

/*
 * DT-aware drivers
 */

struct dt_device_match {
	const char *compatible;
	const void *compat_data;
};

enum dt_driver_type {
	DT_DRIVER_NOTYPE,
	DT_DRIVER_UART,
	DT_DRIVER_CLK,
	DT_DRIVER_RSTCTRL,
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

#if defined(CFG_DT)
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

/*
 * Find a driver that is suitable for the given DT node, that is, with
 * a matching "compatible" property.
 *
 * @fdt: pointer to the device tree
 * @offs: node offset
 */
const struct dt_driver *dt_find_compatible_driver(const void *fdt, int offs);

/*
 * Map a device into secure or non-secure memory and return the base VA and
 * the mapping size. The mapping is done with type MEM_AREA_IO_SEC or
 * MEM_AREA_IO_NSEC, depending on the device status.
 * If the mapping already exists, the function simply returns the @vbase and
 * @size information.
 *
 * @offs is the offset of the node that describes the device in @fdt.
 * @base receives the base virtual address corresponding to the base physical
 * address of the "reg" property
 * @size receives the size of the mapping
 *
 * Returns 0 on success or -1 in case of error.
 */
int dt_map_dev(const void *fdt, int offs, vaddr_t *base, size_t *size);

/*
 * Check whether the node at @offs contains the property with propname or not.
 *
 * @offs is the offset of the node that describes the device in @fdt.
 * @propname is the property that need to check
 *
 * Returns true on success or false if no propname.
 */
bool dt_have_prop(const void *fdt, int offs, const char *propname);

/*
 * Modify or add "status" property to "disabled"
 *
 * @fdt reference to the Device Tree
 * @node is the node offset to modify
 *
 * Returns 0 on success or -1 on failure
 */
int dt_disable_status(void *fdt, int node);

/*
 * Force secure-status = "okay" and status="disabled" for the target node.
 *
 * @fdt reference to the Device Tree
 * @node is the node offset to modify
 *
 * Returns 0 on success or -1 on failure
 */
int dt_enable_secure_status(void *fdt, int node);

/*
 * FDT manipulation functions, not provided by <libfdt.h>
 */

/*
 * Return the base address for the "reg" property of the specified node or
 * (paddr_t)-1 in case of error
 */
paddr_t _fdt_reg_base_address(const void *fdt, int offs);

/*
 * Return the reg size for the reg property of the specified node or -1 in case
 * of error
 */
size_t _fdt_reg_size(const void *fdt, int offs);

/*
 * Read the status and secure-status properties into a bitfield.
 * Return -1 on failure, DT_STATUS_DISABLED if the node is disabled,
 * otherwise return a combination of DT_STATUS_OK_NSEC and DT_STATUS_OK_SEC.
 */
int _fdt_get_status(const void *fdt, int offs);

/*
 * fdt_fill_device_info - Get generic device info from a node
 *
 * This function fills the generic information from a given node.
 * Currently supports a single base register, a single clock,
 * a single reset ID line and a single interrupt ID.
 * Default DT_INFO_* macros are used when the relate property is not found.
 */
void _fdt_fill_device_info(const void *fdt, struct dt_node_info *info,
			   int node);
/*
 * Read cells from a given property of the given node. Any number of 32-bit
 * cells of the property can be read. Returns 0 on success, or a negative
 * FDT error value otherwise.
 */
int _fdt_read_uint32_array(const void *fdt, int node, const char *prop_name,
			   uint32_t *array, size_t count);

/*
 * Read one cell from a given property of the given node.
 * Returns 0 on success, or a negative FDT error value otherwise.
 */
int _fdt_read_uint32(const void *fdt, int node, const char *prop_name,
		     uint32_t *value);

/*
 * Read one cell from a property of a cell or default to a given value
 * Returns the 32bit cell value or @dflt_value on failure.
 */
uint32_t _fdt_read_uint32_default(const void *fdt, int node,
				  const char *prop_name, uint32_t dflt_value);

/*
 * Check whether the node at @node has a reference name.
 *
 * @node is the offset of the node that describes the device in @fdt.
 *
 * Returns true on success or false if no property
 */
bool _fdt_check_node(const void *fdt, int node);

#else /* !CFG_DT */

static inline const struct dt_driver *dt_find_compatible_driver(
					const void *fdt __unused,
					int offs __unused)
{
	return NULL;
}

static inline int dt_map_dev(const void *fdt __unused, int offs __unused,
			     vaddr_t *vbase __unused, size_t *size __unused)
{
	return -1;
}

static inline paddr_t _fdt_reg_base_address(const void *fdt __unused,
					    int offs __unused)
{
	return (paddr_t)-1;
}

static inline size_t _fdt_reg_size(const void *fdt __unused,
				   int offs __unused)
{
	return (size_t)-1;
}

static inline int _fdt_get_status(const void *fdt __unused, int offs __unused)
{
	return -1;
}

__noreturn
static inline void _fdt_fill_device_info(const void *fdt __unused,
					 struct dt_node_info *info __unused,
					 int node __unused)
{
	panic();
}

static inline int _fdt_read_uint32_array(const void *fdt __unused,
					 int node __unused,
					 const char *prop_name __unused,
					 uint32_t *array __unused,
					 size_t count __unused)
{
	return -1;
}

static inline int _fdt_read_uint32(const void *fdt __unused,
				   int node __unused,
				   const char *prop_name __unused,
				   uint32_t *value __unused)
{
	return -1;
}

static inline uint32_t _fdt_read_uint32_default(const void *fdt __unused,
						int node __unused,
						const char *prop_name __unused,
						uint32_t dflt_value __unused)
{
	return dflt_value;
}

#endif /* !CFG_DT */

#define for_each_dt_driver(drv) \
	for (drv = SCATTERED_ARRAY_BEGIN(dt_drivers, struct dt_driver); \
	     drv < SCATTERED_ARRAY_END(dt_drivers, struct dt_driver); \
	     drv++)

#endif /* KERNEL_DT_H */
