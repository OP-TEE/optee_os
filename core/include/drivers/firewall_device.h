/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2024, STMicroelectronics
 */

#ifndef __DRIVERS_FIREWALL_DEVICE_H
#define __DRIVERS_FIREWALL_DEVICE_H

#include <compiler.h>
#include <stdint.h>
#include <tee_api_types.h>
#include <types_ext.h>
#include <util.h>

/* Opaque reference to firewall_controller */
struct firewall_controller;

/**
 * struct firewall_query - Information on a device's firewall. Each device can
 *			   have more than one firewall.
 *
 * @firewall_ctrl:	Pointer referencing a firewall controller of the device.
 *			It is opaque so a device cannot manipulate the
 *			controller's ops or access the controller's data
 * @args:		Firewall arguments that are implementation dependent
 * @arg_count:		Number of arguments
 */
struct firewall_query {
	struct firewall_controller *firewall_ctrl;
	uint32_t *args;
	size_t arg_count;
};

#ifdef CFG_DRIVERS_FIREWALL
/**
 * firewall_dt_get_by_index - Get the firewall configuration associated to a
 *			      given index for a device node.
 *
 * @fdt:		FDT to work on
 * @node:		Device node to read from
 * @index:		Index of the entry in the property
 * @out_firewall:	Firewall reference
 *
 * Returns TEE_SUCCESS on success, TEE_ERROR_ITEM_NOT_FOUND if there's no match
 * with a firewall controller or appropriate TEE_Result error code if an
 * error occurred.
 */
TEE_Result firewall_dt_get_by_index(const void *fdt, int node,
				    unsigned int index,
				    struct firewall_query **out_firewall);

/**
 * firewall_dt_get_by_name - Get the firewall configuration associated to a
 *			     given name for a device node.
 *
 * @fdt:		FDT to work on
 * @node:		Device node to read from
 * @name:		Name of the firewall configuration to search for
 * @out_firewall:	Firewall reference
 *
 * Returns TEE_SUCCESS on success, TEE_ERROR_ITEM_NOT_FOUND if there's no match
 * with a firewall controller or appropriate TEE_Result error code if an
 * error occurred.
 */
TEE_Result firewall_dt_get_by_name(const void *fdt, int node, const char *name,
				   struct firewall_query **out_firewall);

/**
 * firewall_set_configuration - Reconfigure the firewall controller associated
 *				to the given firewall configuration with it.
 *
 * @firewall:	Firewall query containing the configuration to set
 *
 * Returns TEE_SUCCESS if access is granted, TEE_ERROR_ITEM_NOT_FOUND if
 * firewall is null or appropriate TEE_Result error code if an error occurred.
 */
TEE_Result firewall_set_configuration(struct firewall_query *firewall);

/**
 * firewall_check_access - Check if the access is authorized for the consumer
 *			   and the given firewall settings according to the
 *			   configuration of its firewall controller
 *
 * @firewall:	Firewall query to check against its firewall controller
 *
 * Returns TEE_SUCCESS if access is authorized, TEE_ERROR_ACCESS_DENIED if it's
 * is denied or appropriate TEE_Result error code if an error occurred.
 */
TEE_Result firewall_check_access(struct firewall_query *firewall);

/**
 * firewall_acquire_access - Check if OP-TEE can access the consumer and
 *			     acquire potential resources to allow the access
 *
 * @firewall:	Firewall query to check against its firewall controller
 *
 * Returns TEE_SUCCESS if access is authorized, TEE_ERROR_ACCESS_DENIED if it's
 * is denied or appropriate TEE_Result error code if an error occurred.
 */
TEE_Result firewall_acquire_access(struct firewall_query *firewall);

/**
 * firewall_check_memory_access - Check if a consumer can access, in read or
 *				  write, the given memory range against a
 *				  firewall controller
 *
 * @firewall:	Firewall configuration to check against its firewall controller
 * @paddr:	Physical base address of the memory range to check
 * @size:	Size of the memory range to check
 * @read:	Check rights for a read access
 * @write:	Check rights for a write access
 *
 * Returns TEE_SUCCESS if access is authorized, TEE_ERROR_ACCESS_DENIED if it's
 * is denied or appropriate TEE_Result error code if an error occurred.
 */
TEE_Result firewall_check_memory_access(struct firewall_query *firewall,
					paddr_t paddr, size_t size, bool read,
					bool write);

/**
 * firewall_acquire_memory_access - Check if OP-TEE can access, in read or
 *				    write, the given memory range against a
 *				    firewall controller and acquire potential
 *				    resources to allow the access
 *
 * @firewall:	Firewall configuration to check against its firewall controller
 * @paddr:	Physical base address of the memory range to check
 * @size:	Size of the memory range to check
 * @read:	Check rights for a read access
 * @write:	Check rights for a write access
 *
 * Returns TEE_SUCCESS if access is authorized, TEE_ERROR_ACCESS_DENIED if it's
 * is denied or appropriate TEE_Result error code if an error occurred.
 */
TEE_Result firewall_acquire_memory_access(struct firewall_query *firewall,
					  paddr_t paddr, size_t size, bool read,
					  bool write);

/**
 * firewall_release_access - Release resources obtained by a call to
 *			     firewall_acquire_access()
 *
 * @firewall:	Firewall configuration to release
 */
void firewall_release_access(struct firewall_query *firewall);

/**
 * firewall_release_memory_access - Release resources obtained by a call to
 *				    firewall_acquire_memory_access()
 *
 * @firewall:	Firewall configuration to release
 * @paddr:	Physical base address of the memory range to release
 * @size:	Size of the memory range to release
 * @read:	Release rights for read accesses
 * @write:	Release rights for write accesses
 *
 * Returns TEE_SUCCESS if access is authorized, TEE_ERROR_ACCESS_DENIED if it's
 * is denied or appropriate TEE_Result error code if an error occurred.
 */
void firewall_release_memory_access(struct firewall_query *firewall,
				    paddr_t paddr, size_t size, bool read,
				    bool write);

/**
 * firewall_put - Release a firewall structure from memory
 *
 * @firewall:	Firewall configuration to put
 */
void firewall_put(struct firewall_query *firewall);

#else /* CFG_DRIVERS_FIREWALL */

static inline TEE_Result
firewall_dt_get_by_index(const void *fdt __unused, int node __unused,
			 unsigned int index __unused,
			 struct firewall_query **out_firewall __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

static inline TEE_Result
firewall_dt_get_by_name(const void *fdt __unused, int node __unused,
			const char *name __unused,
			struct firewall_query **out_firewall __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

static inline TEE_Result
firewall_check_access(struct firewall_query *firewall __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

static inline TEE_Result
firewall_acquire_access(struct firewall_query *firewall __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

static inline TEE_Result
firewall_check_memory_access(struct firewall_query *firewall __unused,
			     paddr_t paddr __unused, size_t size __unused,
			     bool read __unused, bool write __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

static inline TEE_Result
firewall_acquire_memory_access(struct firewall_query *firewall __unused,
			       paddr_t paddr __unused, size_t size __unused,
			       bool read __unused, bool write __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

static inline void
firewall_release_access(struct firewall_query *firewall __unused)
{
}

static inline void
firewall_release_memory_access(struct firewall_query *firewall __unused,
			       paddr_t paddr __unused, size_t size __unused,
			       bool read __unused, bool write __unused)
{
}

static inline TEE_Result
firewall_set_configuration(struct firewall_query *firewall __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

static inline void firewall_put(struct firewall_query *firewall __unused)
{
}

#endif /* CFG_DRIVERS_FIREWALL */
#endif /* __DRIVERS_FIREWALL_DEVICE_H */
