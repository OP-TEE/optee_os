// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2024, STMicroelectronics
 */

#include <assert.h>
#include <config.h>
#include <drivers/firewall.h>
#include <kernel/dt_driver.h>
#include <kernel/panic.h>
#include <libfdt.h>
#include <malloc.h>
#include <trace.h>

/* The firewall framework requires device tree support */
static_assert(IS_ENABLED(CFG_DT));

static TEE_Result firewall_get(struct dt_pargs *parg, void *data,
			       struct firewall_query **out_fw)
{
	struct firewall_query *fw = NULL;
	unsigned int i = 0;

	assert(parg->args_count >= 0);

	fw = calloc(1, sizeof(*fw));
	if (!fw)
		return TEE_ERROR_OUT_OF_MEMORY;

	fw->ctrl = (struct firewall_controller *)data;
	fw->arg_count = parg->args_count;

	if (fw->arg_count) {
		fw->args = calloc(fw->arg_count, sizeof(*fw->args));
		if (!fw->args) {
			free(fw);
			return TEE_ERROR_OUT_OF_MEMORY;
		}
	}

	for (i = 0; i < (unsigned int)parg->args_count; i++)
		fw->args[i] = parg->args[i];

	*out_fw = fw;

	return TEE_SUCCESS;
}

/* Firewall device API */

void firewall_put(struct firewall_query *fw)
{
	if (fw) {
		free(fw->args);
		free(fw);
	}
}

TEE_Result firewall_dt_get_by_index(const void *fdt, int node, uint32_t index,
				    struct firewall_query **out_fw)
{
	return dt_driver_device_from_node_idx_prop("access-controllers", fdt,
						   node, index,
						   DT_DRIVER_FIREWALL,
						   out_fw);
}

TEE_Result firewall_dt_get_by_name(const void *fdt, int node, const char *name,
				   struct firewall_query **out_fw)
{
	int index = 0;

	index = fdt_stringlist_search(fdt, node, "access-controllers-names",
				      name);
	if (index == -FDT_ERR_NOTFOUND)
		return TEE_ERROR_ITEM_NOT_FOUND;
	else if (index < 0)
		return TEE_ERROR_GENERIC;

	return firewall_dt_get_by_index(fdt, node, index, out_fw);
}

TEE_Result firewall_set_configuration(struct firewall_query *fw)
{
	assert(fw && fw->ctrl && fw->ctrl->ops);

	if (!fw->ctrl->ops->set_conf)
		return TEE_ERROR_NOT_SUPPORTED;

	return fw->ctrl->ops->set_conf(fw);
}

TEE_Result firewall_check_access(struct firewall_query *fw)
{
	assert(fw && fw->ctrl && fw->ctrl->ops);

	if (!fw->ctrl->ops->check_access)
		return TEE_ERROR_NOT_SUPPORTED;

	return fw->ctrl->ops->check_access(fw);
}

TEE_Result firewall_acquire_access(struct firewall_query *fw)
{
	assert(fw && fw->ctrl && fw->ctrl->ops);

	if (!fw->ctrl->ops->acquire_access)
		return TEE_ERROR_NOT_SUPPORTED;

	return fw->ctrl->ops->acquire_access(fw);
}

TEE_Result firewall_check_memory_access(struct firewall_query *fw,
					paddr_t paddr, size_t size, bool read,
					bool write)
{
	assert(fw && fw->ctrl && fw->ctrl->ops);

	if (!fw->ctrl->ops->check_memory_access)
		return TEE_ERROR_NOT_SUPPORTED;

	return fw->ctrl->ops->check_memory_access(fw, paddr, size, read, write);
}

TEE_Result firewall_acquire_memory_access(struct firewall_query *fw,
					  paddr_t paddr, size_t size, bool read,
					  bool write)
{
	assert(fw && fw->ctrl && fw->ctrl->ops);

	if (!fw->ctrl->ops->acquire_memory_access)
		return TEE_ERROR_NOT_SUPPORTED;

	return fw->ctrl->ops->acquire_memory_access(fw, paddr, size, read,
						    write);
}

void firewall_release_access(struct firewall_query *fw)
{
	assert(fw && fw->ctrl && fw->ctrl->ops);

	if (fw->ctrl->ops->release_access)
		fw->ctrl->ops->release_access(fw);
}

void firewall_release_memory_access(struct firewall_query *fw, paddr_t paddr,
				    size_t size, bool read, bool write)
{
	assert(fw && fw->ctrl && fw->ctrl->ops);

	if (fw->ctrl->ops->release_memory_access)
		fw->ctrl->ops->release_memory_access(fw, paddr, size, read,
						     write);
}

/* Firewall controller API */

TEE_Result firewall_dt_controller_register(const void *fdt, int node,
					   struct firewall_controller *ctrl)
{
	assert(ctrl);

	DMSG("Registering %s firewall controller", ctrl->name);

	return dt_driver_register_provider(fdt, node,
					   (get_of_device_func)firewall_get,
					   ctrl, DT_DRIVER_FIREWALL);
}

TEE_Result
firewall_dt_probe_bus(const void *fdt, int node,
		      struct firewall_controller *ctrl __maybe_unused)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct firewall_query *fw = NULL;
	int subnode = 0;

	DMSG("Populating %s firewall bus", ctrl->name);

	fdt_for_each_subnode(subnode, fdt, node) {
		unsigned int i = 0;

		if (fdt_get_status(fdt, subnode) == DT_STATUS_DISABLED)
			continue;

		DMSG("Acquiring firewall access for %s when probing bus",
		     fdt_get_name(fdt, subnode, NULL));

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
				EMSG("%s: Error on node %s: %#"PRIx32,
				     ctrl->name,
				     fdt_get_name(fdt, subnode, NULL), res);
				panic();
			}

			res = firewall_acquire_access(fw);
			if (res) {
				EMSG("%s: %s not accessible: %#"PRIx32,
				     ctrl->name,
				     fdt_get_name(fdt, subnode, NULL), res);
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
