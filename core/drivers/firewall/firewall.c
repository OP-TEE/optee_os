// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2024, STMicroelectronics
 */

#include <assert.h>
#include <config.h>
#include <drivers/firewall.h>
#include <kernel/boot.h>
#include <kernel/dt_driver.h>
#include <kernel/panic.h>
#include <kernel/spinlock.h>
#include <libfdt.h>
#include <malloc.h>
#include <trace.h>

/* The firewall framework requires a device tree file*/
static_assert(IS_ENABLED(CFG_EMBED_DTB));

static TEE_Result firewall_get(struct dt_pargs *parg, void *data,
			       struct firewall_query **out_firewall)
{
	struct firewall_query *firewall = NULL;
	unsigned int i = 0;

	assert(parg->args_count >= 0);

	firewall = calloc(1, sizeof(*firewall));
	if (!firewall)
		return TEE_ERROR_OUT_OF_MEMORY;

	firewall->firewall_ctrl = (struct firewall_controller *)data;
	firewall->arg_count = parg->args_count;

	assert(parg->args_count >= 0);

	if (firewall->arg_count) {
		firewall->args = calloc(firewall->arg_count,
					sizeof(*firewall->args));
		if (!firewall->args) {
			free(firewall);
			return TEE_ERROR_OUT_OF_MEMORY;
		}
	}

	for (i = 0; i < (unsigned int)parg->args_count; i++)
		firewall->args[i] = parg->args[i];

	*out_firewall = firewall;

	return TEE_SUCCESS;
}

/* Firewall device API */

void firewall_put(struct firewall_query *firewall)
{
	if (firewall) {
		free(firewall->args);
		free(firewall);
	}
}

TEE_Result firewall_dt_get_by_index(const void *fdt, int node, uint32_t index,
				    struct firewall_query **out_firewall)
{
	return dt_driver_device_from_node_idx_prop("access-controllers", fdt,
						   node, index,
						   DT_DRIVER_FIREWALL,
						   out_firewall);
}

TEE_Result firewall_dt_get_by_name(const void *fdt, int node, const char *name,
				   struct firewall_query **out_firewall)
{
	int index = 0;

	index = fdt_stringlist_search(fdt, node, "access-controllers-names",
				      name);
	if (index == -FDT_ERR_NOTFOUND)
		return TEE_ERROR_ITEM_NOT_FOUND;
	else if (index < 0)
		return TEE_ERROR_GENERIC;

	return firewall_dt_get_by_index(fdt, node, index, out_firewall);
}

TEE_Result firewall_set_configuration(struct firewall_query *firewall)
{
	assert(firewall && firewall->firewall_ctrl &&
	       firewall->firewall_ctrl->ops);

	if (!firewall->firewall_ctrl->ops->set_conf)
		return TEE_ERROR_NOT_SUPPORTED;

	return firewall->firewall_ctrl->ops->set_conf(firewall);
}

TEE_Result firewall_check_access(struct firewall_query *firewall)
{
	assert(firewall && firewall->firewall_ctrl &&
	       firewall->firewall_ctrl->ops);

	if (!firewall->firewall_ctrl->ops->check_access)
		return TEE_ERROR_NOT_SUPPORTED;

	return firewall->firewall_ctrl->ops->check_access(firewall);
}

TEE_Result firewall_acquire_access(struct firewall_query *firewall)
{
	assert(firewall && firewall->firewall_ctrl &&
	       firewall->firewall_ctrl->ops);

	if (!firewall->firewall_ctrl->ops->acquire_access)
		return TEE_ERROR_NOT_SUPPORTED;

	return firewall->firewall_ctrl->ops->acquire_access(firewall);
}

TEE_Result firewall_check_memory_access(struct firewall_query *firewall,
					paddr_t paddr, size_t size, bool read,
					bool write)
{
	assert(firewall && firewall->firewall_ctrl &&
	       firewall->firewall_ctrl->ops);

	if (!firewall->firewall_ctrl->ops->check_memory_access)
		return TEE_ERROR_NOT_SUPPORTED;

	return firewall->firewall_ctrl->ops->check_memory_access(firewall,
								 paddr, size,
								 read, write);
}

TEE_Result firewall_acquire_memory_access(struct firewall_query *firewall,
					  paddr_t paddr, size_t size, bool read,
					  bool write)
{
	assert(firewall && firewall->firewall_ctrl &&
	       firewall->firewall_ctrl->ops);

	if (!firewall->firewall_ctrl->ops->acquire_memory_access)
		return TEE_ERROR_NOT_SUPPORTED;

	return firewall->firewall_ctrl->ops->acquire_memory_access(firewall,
								   paddr, size,
								   read, write);
}

void firewall_release_access(struct firewall_query *firewall)
{
	assert(firewall && firewall->firewall_ctrl &&
	       firewall->firewall_ctrl->ops);

	if (firewall->firewall_ctrl->ops->release_access)
		firewall->firewall_ctrl->ops->release_access(firewall);
}

void firewall_release_memory_access(struct firewall_query *firewall,
				    paddr_t paddr, size_t size, bool read,
				    bool write)
{
	assert(firewall && firewall->firewall_ctrl &&
	       firewall->firewall_ctrl->ops);

	if (firewall->firewall_ctrl->ops->release_memory_access)
		firewall->firewall_ctrl->ops->release_memory_access(firewall,
								    paddr, size,
								    read,
								    write);
}

/* Firewall controller API */

TEE_Result firewall_dt_controller_register(const void *fdt, int node,
					   struct firewall_controller *ctrler)
{
	assert(ctrler);

	DMSG("Registering %s firewall controller", ctrler->name);

	return dt_driver_register_provider(fdt, node,
					   (get_of_device_func)firewall_get,
					   ctrler, DT_DRIVER_FIREWALL);
}

TEE_Result firewall_dt_probe_bus(const void *fdt, int node,
				 struct firewall_controller *controller)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct firewall_query *fw = NULL;
	int subnode = 0;

	DMSG("Populating %s firewall bus", controller->name);

	fdt_for_each_subnode(subnode, fdt, node) {
		unsigned int i = 0;

		if (fdt_get_status(fdt, subnode) == DT_STATUS_DISABLED)
			continue;

		DMSG("Checking firewall conf for %s", fdt_get_name(fdt, subnode,
								   NULL));

		do {
			/*
			 * The access-controllers property is mandatory for
			 * firewall bus devices
			 */
			res = firewall_dt_get_by_index(fdt, subnode, i, &fw);
			if (res == TEE_ERROR_ITEM_NOT_FOUND) {
				/* Stop when nothing more to parse */
				break;
			} else if (res) {
				EMSG("%s: Error when populating the bus on peripheral %s",
				     controller->name,
				     fdt_get_name(fdt, subnode, NULL));
				panic();
			}

			if (fw->firewall_ctrl->ops->acquire_access(fw)) {
				EMSG("%s: Peripheral %s not accessible",
				     controller->name,
				     fdt_get_name(fdt, subnode, NULL));
				panic();
			}

			firewall_put(fw);
			i++;
		} while (true);

		res = dt_driver_maybe_add_probe_node(fdt, subnode);
		if (res) {
			EMSG("Failed on node %s with %#"PRIx32,
			     fdt_get_name(fdt, subnode, NULL), res);
			panic();
		}
	}

	return TEE_SUCCESS;
}
