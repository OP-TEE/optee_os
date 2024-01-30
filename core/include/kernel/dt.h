/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016-2021, Linaro Limited
 */

#ifndef __KERNEL_DT_H
#define __KERNEL_DT_H

#include <compiler.h>
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

/*
 * DT_MAP_AUTO: Uses status properties from device tree to determine mapping.
 * DT_MAP_SECURE: Force mapping for device to be secure.
 * DT_MAP_NON_SECURE: Force mapping for device to be non-secure.
 */
enum dt_map_dev_directive {
	DT_MAP_AUTO,
	DT_MAP_SECURE,
	DT_MAP_NON_SECURE
};

/*
 * struct dt_descriptor - Descriptor of the device tree
 * @blob: Pointer to the device tree binary
 * @frag_id: Used ID of fragments for device tree overlay
 */
struct dt_descriptor {
	void *blob;
#ifdef _CFG_USE_DTB_OVERLAY
	int frag_id;
#endif
};

extern uint8_t embedded_secure_dtb[];

#ifdef CFG_DT
/*
 * dt_getprop_as_number() - get a DT property a unsigned number
 * @fdt: DT base address
 * @nodeoffset: node offset
 * @name: property string name
 * @num: output number read
 * Return 0 on success and a negative FDT error value on error
 *
 * The size of the property determines if it is read as an unsigned 32-bit
 * or 64-bit integer.
 */
int dt_getprop_as_number(const void *fdt, int nodeoffset, const char *name,
			 uint64_t *num);

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
 * @mapping what kind of mapping is done for memory.
 *
 * Returns 0 on success or -1 in case of error.
 */
int dt_map_dev(const void *fdt, int offs, vaddr_t *base, size_t *size,
	       enum dt_map_dev_directive mapping);

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
paddr_t fdt_reg_base_address(const void *fdt, int offs);

/*
 * Return the reg size for the reg property of the specified node or -1 in case
 * of error
 */
size_t fdt_reg_size(const void *fdt, int offs);

/*
 * Read the status and secure-status properties into a bitfield.
 * Return -1 on failure, DT_STATUS_DISABLED if the node is disabled,
 * otherwise return a combination of DT_STATUS_OK_NSEC and DT_STATUS_OK_SEC.
 */
int fdt_get_status(const void *fdt, int offs);

/*
 * fdt_fill_device_info - Get generic device info from a node
 *
 * This function fills the generic information from a given node.
 * Currently supports a single base register, a single clock,
 * a single reset ID line and a single interrupt ID.
 * Default DT_INFO_* macros are used when the relate property is not found.
 */
void fdt_fill_device_info(const void *fdt, struct dt_node_info *info,
			  int node);
/*
 * Read cells from a given property of the given node. Any number of 32-bit
 * cells of the property can be read. Returns 0 on success, or a negative
 * FDT error value otherwise.
 */
int fdt_read_uint32_array(const void *fdt, int node, const char *prop_name,
			  uint32_t *array, size_t count);

/*
 * Read one cell from a given multi-value property of the given node.
 * Returns 0 on success, or a negative FDT error value otherwise.
 */
int fdt_read_uint32_index(const void *fdt, int node, const char *prop_name,
			  int index, uint32_t *value);

/*
 * Read one cell from a given property of the given node.
 * Returns 0 on success, or a negative FDT error value otherwise.
 */
int fdt_read_uint32(const void *fdt, int node, const char *prop_name,
		    uint32_t *value);

/*
 * Read one cell from a property of a cell or default to a given value
 * Returns the 32bit cell value or @dflt_value on failure.
 */
uint32_t fdt_read_uint32_default(const void *fdt, int node,
				 const char *prop_name, uint32_t dflt_value);

/*
 * This function fills reg node info (base & size) with an index.
 *
 * Returns 0 on success and a negative FDT error code on failure.
 */
int fdt_get_reg_props_by_index(const void *fdt, int node, int index,
			       paddr_t *base, size_t *size);

/*
 * This function fills reg node info (base & size) with an index found by
 * checking the reg-names node.
 *
 * Returns 0 on success and a negative FDT error code on failure.
 */
int fdt_get_reg_props_by_name(const void *fdt, int node, const char *name,
			      paddr_t *base, size_t *size);

/* Returns embedded DTB if present, then external DTB if found, then NULL */
void *get_dt(void);

/*
 * get_secure_dt() - returns secure DTB for drivers
 *
 * Returns device tree that is considered secure for drivers to use.
 *
 * 1. Returns embedded DTB if available,
 * 2. Secure external DTB if available,
 * 3. If neither then NULL
 */
void *get_secure_dt(void);

/* Returns embedded DTB location if present, otherwise NULL */
void *get_embedded_dt(void);

/* Returns true if passed DTB is same as Embedded DTB, otherwise false */
static inline bool is_embedded_dt(void *fdt)
{
	return fdt && fdt == get_embedded_dt();
}

/* Returns DTB descriptor of the external DTB if present, otherwise NULL */
struct dt_descriptor *get_external_dt_desc(void);

/*
 * init_external_dt() - Initialize the external DTB located at given address.
 * @phys_dt:	Physical address where the external DTB located.
 * @dt_sz:	Maximum size of the external DTB.
 *
 * Initialize the external DTB.
 *
 * 1. Add MMU mapping of the external DTB,
 * 2. Initialize device tree overlay
 */
void init_external_dt(unsigned long phys_dt, size_t dt_sz);

/* Returns external DTB if present, otherwise NULL */
void *get_external_dt(void);

/*
 * add_dt_path_subnode() - Add new child node into a parent node.
 * @dt:		Pointer to a device tree descriptor which has DTB.
 * @path:	Path to the parent node.
 * @subnode:	Name of the child node.
 *
 * Returns the offset of the child node in DTB on success or a negative libfdt
 * error number.
 */
int add_dt_path_subnode(struct dt_descriptor *dt, const char *path,
			const char *subnode);

/*
 * add_res_mem_dt_node() - Create "reserved-memory" parent and child nodes.
 * @dt:		Pointer to a device tree descriptor which has DTB.
 * @name:	Name of the child node.
 * @pa:		Physical address of specific reserved memory region.
 * @size:	Size of specific reserved memory region.
 *
 * Returns 0 if succeeds, otherwise a negative libfdt error number.
 */
int add_res_mem_dt_node(struct dt_descriptor *dt, const char *name,
			paddr_t pa, size_t size);

#else /* !CFG_DT */

static inline const struct dt_driver *dt_find_compatible_driver(
					const void *fdt __unused,
					int offs __unused)
{
	return NULL;
}

static inline int dt_map_dev(const void *fdt __unused, int offs __unused,
			     vaddr_t *vbase __unused, size_t *size __unused,
			     enum dt_map_dev_directive mapping __unused)
{
	return -1;
}

static inline paddr_t fdt_reg_base_address(const void *fdt __unused,
					   int offs __unused)
{
	return (paddr_t)-1;
}

static inline size_t fdt_reg_size(const void *fdt __unused,
				  int offs __unused)
{
	return (size_t)-1;
}

static inline int fdt_get_status(const void *fdt __unused, int offs __unused)
{
	return -1;
}

__noreturn
static inline void fdt_fill_device_info(const void *fdt __unused,
					struct dt_node_info *info __unused,
					int node __unused)
{
	panic();
}

static inline int fdt_read_uint32_array(const void *fdt __unused,
					int node __unused,
					const char *prop_name __unused,
					uint32_t *array __unused,
					size_t count __unused)
{
	return -1;
}

static inline int fdt_read_uint32(const void *fdt __unused,
				  int node __unused,
				  const char *prop_name __unused,
				  uint32_t *value __unused)
{
	return -1;
}

static inline uint32_t fdt_read_uint32_default(const void *fdt __unused,
					       int node __unused,
					       const char *prop_name __unused,
					       uint32_t dflt_value __unused)
{
	return dflt_value;
}

static inline int fdt_read_uint32_index(const void *fdt __unused,
					int node __unused,
					const char *prop_name __unused,
					int index __unused,
					uint32_t *value __unused)
{
	return -1;
}

static inline int fdt_get_reg_props_by_index(const void *fdt __unused,
					     int node __unused,
					     int index __unused,
					     paddr_t *base __unused,
					     size_t *size __unused)
{
	return -1;
}

static inline int fdt_get_reg_props_by_name(const void *fdt __unused,
					    int node __unused,
					    const char *name __unused,
					    paddr_t *base __unused,
					    size_t *size __unused)
{
	return -1;
}

static inline int dt_getprop_as_number(const void *fdt __unused,
				       int nodeoffset __unused,
				       const char *name __unused,
				       uint64_t *num __unused)
{
	return -1;
}

static inline void *get_dt(void)
{
	return NULL;
}

static inline void *get_secure_dt(void)
{
	return NULL;
}

static inline void *get_embedded_dt(void)
{
	return NULL;
}

static inline bool is_embedded_dt(void *fdt __unused)
{
	return false;
}

static inline struct dt_descriptor *get_external_dt_desc(void)
{
	return NULL;
}

static inline void init_external_dt(unsigned long phys_dt __unused,
				    size_t dt_sz __unused)
{
}

static inline void *get_external_dt(void)
{
	return NULL;
}

static inline int add_dt_path_subnode(struct dt_descriptor *dt __unused,
				      const char *path __unused,
				      const char *subnode __unused)
{
	return -1;
}

static inline int add_res_mem_dt_node(struct dt_descriptor *dt __unused,
				      const char *name __unused,
				      paddr_t pa __unused,
				      size_t size __unused)
{
	return -1;
}

#endif /* !CFG_DT */
#endif /* __KERNEL_DT_H */
