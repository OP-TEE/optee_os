/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2024, STMicroelectronics
 */

#ifndef __DRIVERS_FIREWALL_H
#define __DRIVERS_FIREWALL_H

#include <compiler.h>
#include <drivers/firewall_device.h>
#include <mm/core_memprot.h>
#include <stdbool.h>
#include <stddef.h>
#include <tee_api_defines.h>
#include <types_ext.h>

struct firewall_controller_ops;

/**
 * struct firewall_controller - Information on firewall controller supplying
 *				services
 *
 * @ops:			Operation handlers
 * @name:			Name of the firewall controller
 * @base:			Base address of the firewall controller
 * @priv:			Private data of the firewall controller
 */
struct firewall_controller {
	const struct firewall_controller_ops *ops;
	const char *name;
	struct io_pa_va *base;
	void *priv;
};

/**
 * struct firewall_controller_ops - Firewall controller operation handlers
 *
 * @set_conf:			Set given firewall configuration
 * @check_access:		Callback used to check access for a consumer
 *				on a resource against a firewall controller
 * @acquire_access:		Callback used to acquire access for OP-TEE
 *				on a resource against a firewall controller
 * @release_access:		Callback used to release resources taken by a
 *				consumer when the access was acquired with
 *				@acquire_access
 * @check_memory_access:	Callback used to check access for a consumer
 *				to a memory range covered by a firewall
 *				controller, in read or write access
 * @acquire_memory_access:	Callback used to acquire access for OP-TEE to a
 *				memory range covered by a firewall controller,
 *				in read or write access
 * @release_memory_access:	Callback used to release resources taken by a
 *				consumer when the memory access was acquired
 *				with @acquire_memory_access
 */
struct firewall_controller_ops {
	TEE_Result (*set_conf)(struct firewall_query *conf);
	TEE_Result (*check_access)(struct firewall_query *conf);
	TEE_Result (*acquire_access)(struct firewall_query *conf);
	void (*release_access)(struct firewall_query *conf);
	TEE_Result (*check_memory_access)(struct firewall_query *firewall,
					  paddr_t paddr, size_t size,
					  bool read, bool write);
	TEE_Result (*acquire_memory_access)(struct firewall_query *firewall,
					    paddr_t paddr, size_t size,
					    bool read, bool write);
	void (*release_memory_access)(struct firewall_query *firewall,
				      paddr_t paddr, size_t size, bool read,
				      bool write);
};

#ifdef CFG_DRIVERS_FIREWALL
/**
 * firewall_dt_controller_register - Register a firewall controller to the
 *				     firewall framework
 * @fdt:	FDT to work on
 * @node:	DT node of the controller
 * @ctrler:	Firewall controller to register
 *
 * Returns TEE_SUCCESS in case of success or TEE_ERROR_BAD_PARAMETERS if no
 * controller was given.
 */
TEE_Result firewall_dt_controller_register(const void *fdt, int node,
					   struct firewall_controller *ctrler);

/**
 * firewall_dt_probe_bus - Populate device tree nodes that have a correct
 *			   firewall configuration. This is used at boot time
 *			   only, as a sanity check between device tree and
 *			   firewalls hardware configurations to prevent
 *			   undesired accesses when access to a device is not
 *			   authorized. This function checks that every
 *			   peripheral entry listed in the access-controllers
 *			   property is accessible by OP-TEE.
 *
 * @fdt:		FDT to work on
 * @node:		Firewall controller node
 * @ctrler:		Firewall controller which subnodes will be populated or
 *			not
 *
 * Returns TEE_SUCCESS in case of success or appropriate TEE_Result if error
 * occurred.
 */
TEE_Result firewall_dt_probe_bus(const void *fdt, int node,
				 struct firewall_controller *ctrler);

#else /* CFG_DRIVERS_FIREWALL */

static inline TEE_Result
firewall_dt_controller_register(const void *fdt __unused, int node __unused,
				struct firewall_controller *ctrler __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

static inline TEE_Result
firewall_dt_probe_bus(const void *fdt __unused, int node __unused,
		      struct firewall_controller *ctrler __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}
#endif /* CFG_DRIVERS_FIREWALL */
#endif /* __DRIVERS_FIREWALL_H */
