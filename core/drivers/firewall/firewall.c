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
#include <stdio.h>
#include <trace.h>

/* The firewall framework requires device tree support */
static_assert(IS_ENABLED(CFG_DT));

static TEE_Result firewall_get(struct dt_pargs *parg, void *data,
			       struct firewall_query *out_fw)
{
	unsigned int i = 0;

	assert((parg->args_count >= 0) && out_fw);

	out_fw->ctrl = (struct firewall_controller *)data;
	out_fw->arg_count = parg->args_count;

	if (out_fw->arg_count) {
		out_fw->args = calloc(out_fw->arg_count, sizeof(*out_fw->args));
		if (!out_fw->args)
			return TEE_ERROR_OUT_OF_MEMORY;
	}

	for (i = 0; i < (unsigned int)parg->args_count; i++)
		out_fw->args[i] = parg->args[i];

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

void firewall_conf_put(struct firewall_conf *conf)
{
	if (conf) {
		size_t i = 0;

		for (i = 0; i < conf->nb_queries; i++)
			free(conf->queries[i].args);

		free(conf->queries);
		free(conf);
	}
}

TEE_Result firewall_dt_get_by_index(const void *fdt, int node, uint32_t index,
				    struct firewall_query **out_fw)

{
	struct firewall_query *query = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;

	query = calloc(1, sizeof(*query));
	if (!query)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = dt_driver_device_from_node_idx_prop("access-controllers", fdt,
						  node, index,
						  DT_DRIVER_FIREWALL, query);
	if (res)
		free(query);
	else
		*out_fw = query;

	return res;
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

TEE_Result firewall_dt_get_conf(const void *fdt, int node,
				const char *conf_name,
				struct firewall_conf **out_conf)
{
	struct firewall_conf *conf = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;
	char *prop_name = NULL;
	size_t nb_element = 0;
	int max_len = 0;
	size_t i = 0;

	assert(conf_name && out_conf);

	max_len = strlen(conf_name) + strlen("-access-conf") + 1;
	prop_name = calloc(1, max_len);
	if (!prop_name)
		return TEE_ERROR_OUT_OF_MEMORY;

	snprintf(prop_name, max_len, "%s-access-conf", conf_name);
	res = dt_driver_count_devices(prop_name, fdt, node, DT_DRIVER_FIREWALL,
				      &nb_element);
	if (res) {
		if (res != TEE_ERROR_DEFER_DRIVER_INIT)
			EMSG("Could not count devices for %s in node %s",
			     prop_name, fdt_get_name(fdt, node, NULL));
		goto out;
	}

	if (!nb_element) {
		EMSG("No firewall alternate configuration: %s in node %s",
		     prop_name, fdt_get_name(fdt, node, NULL));
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	conf = calloc(1, sizeof(*conf));
	if (!conf) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	conf->nb_queries = nb_element;
	conf->queries = calloc(nb_element, sizeof(*conf->queries));
	if (!conf->queries) {
		free(conf);
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	for (i = 0; i < nb_element; i++) {
		res = dt_driver_device_from_node_idx_prop(prop_name, fdt, node,
							  i, DT_DRIVER_FIREWALL,
							  conf->queries + i);
		if (res) {
			firewall_conf_put(conf);
			goto out;
		}
	}

	*out_conf = conf;
	res = TEE_SUCCESS;

out:
	free(prop_name);

	return res;
}

static TEE_Result firewall_set_configuration_query(struct firewall_query *fw)
{
	assert(fw && fw->ctrl && fw->ctrl->ops);

	if (!fw->ctrl->ops->set_conf)
		return TEE_ERROR_NOT_SUPPORTED;

	return fw->ctrl->ops->set_conf(fw);
}

TEE_Result firewall_set_configuration(struct firewall_conf *conf)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	size_t i = 0;

	assert(conf && conf->nb_queries);

	for (i = 0; i < conf->nb_queries; i++) {
		/*
		 * In case of error, report it to the caller. Note that
		 * the firewall configurations may be partially loaded. In such
		 * case, it is the caller responsibility to decide what to do.
		 */
		res = firewall_set_configuration_query(conf->queries + i);
		if (res)
			return res;
	}

	return TEE_SUCCESS;
}

static TEE_Result
firewall_set_memory_configuration_query(struct firewall_query *fw,
					paddr_t paddr, size_t size)
{
	assert(fw && fw->ctrl && fw->ctrl->ops);

	if (!fw->ctrl->ops->set_memory_conf)
		return TEE_ERROR_NOT_SUPPORTED;

	return fw->ctrl->ops->set_memory_conf(fw, paddr, size);
}

TEE_Result firewall_set_memory_configuration(struct firewall_conf *conf,
					     paddr_t paddr, size_t size)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	size_t i = 0;

	assert(conf && conf->nb_queries);

	for (i = 0; i < conf->nb_queries; i++) {
		res = firewall_set_memory_configuration_query(conf->queries + i,
							      paddr, size);
		if (res)
			return res;
	}

	return TEE_SUCCESS;
}

TEE_Result firewall_acquire_access(struct firewall_query *fw)
{
	assert(fw && fw->ctrl && fw->ctrl->ops);

	if (!fw->ctrl->ops->acquire_access)
		return TEE_ERROR_NOT_SUPPORTED;

	return fw->ctrl->ops->acquire_access(fw);
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
