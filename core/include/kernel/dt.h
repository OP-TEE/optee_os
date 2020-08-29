/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016, Linaro Limited
 */

#ifndef KERNEL_DT_H
#define KERNEL_DT_H

#include <compiler.h>
#include <kernel/panic.h>
#include <stdint.h>
#include <types_ext.h>
#include <util.h>

/*
 * Bitfield to reflect status and secure-status values ("okay", "disabled"
 * or not present)
 */
#define DT_STATUS_DISABLED		0
#define DT_STATUS_OK_NSEC		BIT(0)
#define DT_STATUS_OK_SEC		BIT(1)

#define DT_INFO_INVALID_REG		((paddr_t)-1)
#define DT_INFO_INVALID_REG_SIZE	((ssize_t)-1)
#define DT_INFO_INVALID_CLOCK		-1
#define DT_INFO_INVALID_RESET		-1
#define DT_INFO_INVALID_INTERRUPT	-1

/*
 * @status: Bit mask for DT_STATUS_*
 * @reg: Device register physical base address or DT_INFO_INVALID_REG
 * @clock: Device identifier (positive value) or DT_INFO_INVALID_CLOCK
 * @reset: Device reset identifier (positive value) or DT_INFO_INVALID_CLOCK
 */
struct dt_node_info {
	unsigned int status;
	paddr_t reg;
	int clock;
	int reset;
};

#if defined(CFG_DT)

/*
 * DT-aware drivers
 */

struct dt_device_match {
	const char *compatible;
};

struct dt_driver {
	const char *name;
	const struct dt_device_match *match_table; /* null-terminated */
	const void *driver;
};

#define __dt_driver __section(".rodata.dtdrv" __SECTION_FLAGS_RODATA)

/*
 * Find a driver that is suitable for the given DT node, that is, with
 * a matching "compatible" property.
 *
 * @fdt: pointer to the device tree
 * @offs: node offset
 */
const struct dt_driver *dt_find_compatible_driver(const void *fdt, int offs);

const struct dt_driver *__dt_driver_start(void);

const struct dt_driver *__dt_driver_end(void);

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
 * Get the DT interrupt property of the @node. In the DT an interrupt
 * is defined with at least 2x32 bits detailling the interrupt number and type.
 *
 * @fdt reference to the Device Tree
 * @node is the node offset to read
 *
 * Returns the interrupt number if value >= 0
 * otherwise DT_INFO_INVALID_INTERRUPT
 */
int dt_get_irq(void *fdt, int node);

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
ssize_t _fdt_reg_size(const void *fdt, int offs);

/*
 * Read the status and secure-status properties into a bitfield.
 * @status is set to DT_STATUS_DISABLED or a combination of DT_STATUS_OK_NSEC
 * and DT_STATUS_OK_SEC
 * Returns positive or null status value on success or -1 in case of error.
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
void _fdt_fill_device_info(void *fdt, struct dt_node_info *info, int node);

#else /* !CFG_DT */

static inline const struct dt_driver *__dt_driver_start(void)
{
	return NULL;
}

static inline const struct dt_driver *__dt_driver_end(void)
{
	return NULL;
}

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

static inline ssize_t _fdt_reg_size(const void *fdt __unused,
				    int offs __unused)
{
	return -1;
}

static inline int _fdt_get_status(const void *fdt __unused, int offs __unused)
{
	return -1;
}

__noreturn
static inline void _fdt_fill_device_info(void *fdt __unused,
					 struct dt_node_info *info __unused,
					 int node __unused)
{
	panic();
}
#endif /* !CFG_DT */

#define for_each_dt_driver(drv) \
	for (drv = __dt_driver_start(); drv < __dt_driver_end(); drv++)

#endif /* KERNEL_DT_H */
