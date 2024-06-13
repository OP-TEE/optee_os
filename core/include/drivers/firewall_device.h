/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2024, STMicroelectronics
 */

#ifndef __DRIVERS_FIREWALL_DEVICE_H
#define __DRIVERS_FIREWALL_DEVICE_H

#include <stdint.h>
#include <tee_api.h>
#include <types_ext.h>
#include <util.h>

/* Opaque reference to firewall_controller */
struct firewall_controller;

/**
 * struct firewall_query - Information on a device's firewall.
 *
 * @ctrl: Pointer referencing a firewall controller of the device. It is opaque
 * so a device cannot manipulate the controller's ops or access the controller's
 * data
 * @args: Firewall arguments that are implementation dependent
 * @arg_count: Number of arguments
 */
struct firewall_query {
	struct firewall_controller *ctrl;
	uint32_t *args;
	size_t arg_count;
};

#ifdef CFG_DRIVERS_FIREWALL
/**
 * firewall_dt_get_by_index() - Get the firewall configuration associated to a
 * given index for a device node.
 *
 * @fdt: FDT to work on
 * @node: Device node to read from
 * @index: Index of the entry in the property
 * @out_fw: Firewall query reference
 *
 * Returns TEE_SUCCESS on success, TEE_ERROR_ITEM_NOT_FOUND if there's no match
 * with a firewall controller or appropriate TEE_Result error code if an
 * error occurred.
 */
TEE_Result firewall_dt_get_by_index(const void *fdt, int node,
				    unsigned int index,
				    struct firewall_query **out_fw);

/**
 * firewall_dt_get_by_name() - Get the firewall configuration associated to a
 * given name for a device node.
 *
 * @fdt: FDT to work on
 * @node: Device node to read from
 * @name: Name of the firewall configuration to search for
 * @out_fw: Firewall query reference
 *
 * Returns TEE_SUCCESS on success, TEE_ERROR_ITEM_NOT_FOUND if there's no match
 * with a firewall controller or appropriate TEE_Result error code if an
 * error occurred.
 */
TEE_Result firewall_dt_get_by_name(const void *fdt, int node, const char *name,
				   struct firewall_query **out_fw);

/**
 * firewall_set_configuration() - Reconfigure the firewall controller associated
 * to the given firewall configuration with it.
 *
 * @fw:	Firewall query containing the configuration to set
 */
TEE_Result firewall_set_configuration(struct firewall_query *fw);

/**
 * firewall_check_access() - Check if the access is authorized for a consumer
 * and the given firewall configuration according to the settings of its
 * firewall controller
 *
 * @fw:	Firewall query containing the configuration to check against its
 * firewall controller
 */
TEE_Result firewall_check_access(struct firewall_query *fw);

/**
 * firewall_acquire_access() - Check if OP-TEE can access the consumer and
 * acquire potential resources to allow the access
 *
 * @fw:	Firewall query containing the configuration to check against its
 * firewall controller
 */
TEE_Result firewall_acquire_access(struct firewall_query *fw);

/**
 * firewall_check_memory_access() - Check if a consumer can access the memory
 * address range, in read and/or write mode and given the firewall
 * configuration, against a firewall controller
 *
 * @fw: Firewall query containing the configuration to check against its
 * firewall controller
 * @paddr: Physical base address of the memory range to check
 * @size: Size of the memory range to check
 * @read: If true, check rights for a read access
 * @write: If true, check rights for a write access
 */
TEE_Result firewall_check_memory_access(struct firewall_query *fw,
					paddr_t paddr, size_t size, bool read,
					bool write);

/**
 * firewall_acquire_memory_access() - Request OP-TEE access, in read and/or
 * write mode, to the given memory address range against a firewall controller
 * and acquire potential resources to allow the access
 *
 * @fw: Firewall query containing the configuration to check against its
 * firewall controller
 * @paddr: Physical base address of the memory range to check
 * @size: Size of the memory range to check
 * @read: Check rights for a read access
 * @write: Check rights for a write access
 */
TEE_Result firewall_acquire_memory_access(struct firewall_query *fw,
					  paddr_t paddr, size_t size, bool read,
					  bool write);

/**
 * firewall_release_access() - Release resources obtained by a call to
 * firewall_acquire_access()
 *
 * @fw:	Firewall query containing the configuration to release
 */
void firewall_release_access(struct firewall_query *fw);

/**
 * firewall_release_memory_access() - Release resources obtained by a call to
 * firewall_acquire_memory_access()
 *
 * @fw:	Firewall configuration to release
 * @paddr: Physical base address of the memory range to release
 * @size: Size of the memory range to release
 * @read: Release rights for read accesses
 * @write: Release rights for write accesses
 */
void firewall_release_memory_access(struct firewall_query *fw, paddr_t paddr,
				    size_t size, bool read, bool write);

/**
 * firewall_set_memory_configuration() - Reconfigure a memory range with
 * the given firewall configuration
 *
 * @fw: Firewall query containing the configuration to set
 * @paddr: Physical base address of the memory range
 * @size: Size of the memory range
 */
TEE_Result firewall_set_memory_configuration(struct firewall_query *fw,
					     paddr_t paddr, size_t size);

/**
 * firewall_put() - Release a firewall_query structure allocated by
 * firewall_dt_get_by_index() or firewall_dt_get_by_name()
 *
 * @fw:	Firewall query to put
 */
void firewall_put(struct firewall_query *fw);

#else /* CFG_DRIVERS_FIREWALL */

static inline TEE_Result
firewall_dt_get_by_index(const void *fdt __unused, int node __unused,
			 unsigned int index __unused,
			 struct firewall_query **out_fw __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

static inline TEE_Result
firewall_dt_get_by_name(const void *fdt __unused, int node __unused,
			const char *name __unused,
			struct firewall_query **out_fw __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

static inline TEE_Result
firewall_check_access(struct firewall_query *fw __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

static inline TEE_Result
firewall_acquire_access(struct firewall_query *fw __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

static inline TEE_Result
firewall_check_memory_access(struct firewall_query *fw __unused,
			     paddr_t paddr __unused, size_t size __unused,
			     bool read __unused, bool write __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

static inline TEE_Result
firewall_acquire_memory_access(struct firewall_query *fw __unused,
			       paddr_t paddr __unused, size_t size __unused,
			       bool read __unused, bool write __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

static inline void
firewall_release_access(struct firewall_query *fw __unused)
{
}

static inline void
firewall_release_memory_access(struct firewall_query *fw __unused,
			       paddr_t paddr __unused, size_t size __unused,
			       bool read __unused, bool write __unused)
{
}

static inline TEE_Result
firewall_set_configuration(struct firewall_query *fw __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

static inline TEE_Result
firewall_set_memory_configuration(struct firewall_query *fw __unused,
				  paddr_t paddr __unused, size_t size __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

static inline void firewall_put(struct firewall_query *fw __unused)
{
}

#endif /* CFG_DRIVERS_FIREWALL */
#endif /* __DRIVERS_FIREWALL_DEVICE_H */
