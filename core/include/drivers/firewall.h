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
 * struct firewall_controller - Firewall controller supplying services
 *
 * @ops: Operation handlers
 * @name: Name of the firewall controller
 * @base: Base address of the firewall controller
 * @priv: Private data of the firewall controller
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
 * @set_conf: Callback used to set given firewall configuration
 * @check_access: Callback used to check access for a consumer on a resource
 * against a firewall controller
 * @acquire_access: Callback used to acquire access for OP-TEE on a resource
 * against a firewall controller
 * @release_access: Callback used to release resources taken by a consumer when
 * the access was acquired with @acquire_access
 * @check_memory_access: Callback used to check access for a consumer to a
 * memory range covered by a firewall controller, for read and/or write accesses
 * @acquire_memory_access: Callback used to acquire access for OP-TEE to a
 * memory range covered by a firewall controller, for read and/or write accesses
 * @release_memory_access: Callback used to release resources taken by a
 * consumer when the memory access was acquired with @acquire_memory_access
 * @set_memory_conf: Callback to set access rights to a physical memory range
 */
struct firewall_controller_ops {
	TEE_Result (*set_conf)(struct firewall_query *conf);
	TEE_Result (*check_access)(struct firewall_query *conf);
	TEE_Result (*acquire_access)(struct firewall_query *conf);
	void (*release_access)(struct firewall_query *conf);
	TEE_Result (*check_memory_access)(struct firewall_query *fw,
					  paddr_t paddr, size_t size,
					  bool read, bool write);
	TEE_Result (*acquire_memory_access)(struct firewall_query *fw,
					    paddr_t paddr, size_t size,
					    bool read, bool write);
	void (*release_memory_access)(struct firewall_query *fw,
				      paddr_t paddr, size_t size, bool read,
				      bool write);
	TEE_Result (*set_memory_conf)(struct firewall_query *fw, paddr_t paddr,
				      size_t size);
};

#ifdef CFG_DRIVERS_FIREWALL
/**
 * firewall_dt_controller_register() - Register a firewall controller to the
 * firewall framework
 * @fdt: FDT to work on
 * @node: DT node of the controller
 * @ctrl: Firewall controller to register
 */
TEE_Result firewall_dt_controller_register(const void *fdt, int node,
					   struct firewall_controller *ctrl);

#else /* CFG_DRIVERS_FIREWALL */

static inline TEE_Result
firewall_dt_controller_register(const void *fdt __unused, int node __unused,
				struct firewall_controller *ctrl __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}
#endif /* CFG_DRIVERS_FIREWALL */
#endif /* __DRIVERS_FIREWALL_H */
