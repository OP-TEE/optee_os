// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021, Linaro Limited
 * Copyright (c) 2021, Bootlin
 */

#include <initcall.h>
#include <kernel/dt.h>
#include <kernel/dt_driver.h>
#include <libfdt.h>
#include <malloc.h>
#include <sys/queue.h>
#include <tee_api_types.h>

/*
 * struct dt_driver_provider - DT related info on probed device
 *
 * Saves information on the probed device so that device
 * drivers can get resources from DT phandle and related arguments.
 *
 * @nodeoffset: Node offset of device referenced in the FDT
 * @type: One of DT_DRIVER_* or DT_DRIVER_NOTYPE.
 * @provider_cells: Cells count in the FDT used by the driver's references
 * @get_of_device: Function to get driver's device ref from phandle data
 * @priv_data: Driver private data passed as @get_of_device argument
 * @link: Reference in DT driver providers list
 */
struct dt_driver_provider {
	int nodeoffset;
	enum dt_driver_type type;
	unsigned int provider_cells;
	uint32_t phandle;
	get_of_device_func get_of_device;
	void *priv_data;
	SLIST_ENTRY(dt_driver_provider) link;
};

static SLIST_HEAD(, dt_driver_provider) dt_driver_provider_list =
	SLIST_HEAD_INITIALIZER(dt_driver_provider_list);

/*
 * Driver provider registering API functions
 */

TEE_Result dt_driver_register_provider(const void *fdt, int nodeoffset,
				       get_of_device_func get_of_device,
				       void *priv, enum dt_driver_type type)
{
	struct dt_driver_provider *prv = NULL;
	int provider_cells = 0;
	uint32_t phandle = 0;

	provider_cells = fdt_get_dt_driver_cells(fdt, nodeoffset, type);
	if (provider_cells < 0) {
		DMSG("Failed to find provider cells: %d", provider_cells);
		return TEE_ERROR_GENERIC;
	}

	phandle = fdt_get_phandle(fdt, nodeoffset);
	if (!phandle || phandle == (uint32_t)-1) {
		DMSG("Failed to find provide phandle");
		return TEE_ERROR_GENERIC;
	}

	prv = calloc(1, sizeof(*prv));
	if (!prv)
		return TEE_ERROR_OUT_OF_MEMORY;

	prv->nodeoffset = nodeoffset;
	prv->type = type;
	prv->provider_cells = provider_cells;
	prv->phandle = phandle;
	prv->get_of_device = get_of_device;
	prv->priv_data = priv;

	SLIST_INSERT_HEAD(&dt_driver_provider_list, prv, link);

	return TEE_SUCCESS;
}

/* Release driver provider references once all dt_drivers are initialized */
static TEE_Result dt_driver_release_provider(void)
{
	struct dt_driver_provider *prv = NULL;

	while (!SLIST_EMPTY(&dt_driver_provider_list)) {
		prv = SLIST_FIRST(&dt_driver_provider_list);
		SLIST_REMOVE_HEAD(&dt_driver_provider_list, link);
		free(prv);
	}

	return TEE_SUCCESS;
}

driver_init_late(dt_driver_release_provider);

/*
 * Helper functions for dt_drivers querying driver provider information
 */

int fdt_get_dt_driver_cells(const void *fdt, int nodeoffset,
			    enum dt_driver_type type)
{
	const char *cells_name = NULL;
	const fdt32_t *c = NULL;
	int len = 0;

	switch (type) {
	case DT_DRIVER_CLK:
		cells_name = "#clock-cells";
		break;
	default:
		panic();
	}

	c = fdt_getprop(fdt, nodeoffset, cells_name, &len);
	if (!c)
		return len;

	if (len != sizeof(*c))
		return -FDT_ERR_BADNCELLS;

	return fdt32_to_cpu(*c);
}

unsigned int dt_driver_provider_cells(struct dt_driver_provider *prv)
{
	return prv->provider_cells;
}

struct dt_driver_provider *dt_driver_get_provider_by_node(int nodeoffset)
{
	struct dt_driver_provider *prv = NULL;

	SLIST_FOREACH(prv, &dt_driver_provider_list, link)
		if (prv->nodeoffset == nodeoffset)
			return prv;

	return NULL;
}

struct dt_driver_provider *dt_driver_get_provider_by_phandle(uint32_t phandle)
{
	struct dt_driver_provider *prv = NULL;

	SLIST_FOREACH(prv, &dt_driver_provider_list, link)
		if (prv->phandle == phandle)
			return prv;

	return NULL;
}

static void *device_from_provider_prop(struct dt_driver_provider *prv,
					  const uint32_t *prop,
					  TEE_Result *res)
{
	struct dt_driver_phandle_args *pargs = NULL;
	unsigned int n = 0;
	void *device = NULL;

	pargs = calloc(1, prv->provider_cells * sizeof(uint32_t *) +
		       sizeof(*pargs));
	if (!pargs) {
		*res = TEE_ERROR_OUT_OF_MEMORY;
		return NULL;
	}

	pargs->args_count = prv->provider_cells;
	for (n = 0; n < prv->provider_cells; n++)
		pargs->args[n] = fdt32_to_cpu(prop[n + 1]);

	device = prv->get_of_device(pargs, prv->priv_data, res);

	free(pargs);

	return device;
}

void *dt_driver_device_from_node_idx_prop(const char *prop_name,
					  const void *fdt, int nodeoffset,
					  unsigned int prop_idx,
					  TEE_Result *res)
{
	int len = 0;
	int idx = 0;
	int idx32 = 0;
	int prv_cells = 0;
	uint32_t phandle = 0;
	const uint32_t *prop = NULL;
	struct dt_driver_provider *prv = NULL;

	prop = fdt_getprop(fdt, nodeoffset, prop_name, &len);
	if (!prop) {
		*res = TEE_ERROR_GENERIC;
		return NULL;
	}

	while (idx < len) {
		idx32 = idx / sizeof(uint32_t);
		phandle = fdt32_to_cpu(prop[idx32]);

		prv = dt_driver_get_provider_by_phandle(phandle);
		if (!prv) {
			*res = TEE_ERROR_GENERIC;
			return NULL;
		}

		prv_cells = dt_driver_provider_cells(prv);
		if (prop_idx) {
			prop_idx--;
			idx += sizeof(phandle) + prv_cells * sizeof(uint32_t);
			continue;
		}

		return device_from_provider_prop(prv, prop + idx32, res);
	}

	*res = TEE_ERROR_GENERIC;
	return NULL;
}

/* Lookup a compatible driver, possibly of a specific @type, for the FDT node */
static TEE_Result probe_device_by_compat(const void *fdt, int node,
					 const char *compat,
					 enum dt_driver_type type)
{
	const struct dt_driver *drv = NULL;
	const struct dt_device_match *dm = NULL;

	for_each_dt_driver(drv) {
		if (drv->type != type)
			continue;

		for (dm = drv->match_table; dm && dm->compatible; dm++)
			if (strcmp(dm->compatible, compat) == 0)
				return drv->probe(fdt, node, dm->compat_data);
	}

	return TEE_ERROR_ITEM_NOT_FOUND;
}

TEE_Result dt_driver_probe_device_by_node(const void *fdt, int nodeoffset,
					  enum dt_driver_type type)
{
	int idx = 0;
	int len = 0;
	int count = 0;
	const char *compat = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;

	count = fdt_stringlist_count(fdt, nodeoffset, "compatible");
	if (count < 0)
		return TEE_ERROR_ITEM_NOT_FOUND;

	for (idx = 0; idx < count; idx++) {
		compat = fdt_stringlist_get(fdt, nodeoffset, "compatible",
					    idx, &len);
		if (!compat)
			return TEE_ERROR_GENERIC;

		res = probe_device_by_compat(fdt, nodeoffset, compat, type);

		if (res != TEE_ERROR_ITEM_NOT_FOUND)
			return res;
	}

	return TEE_ERROR_ITEM_NOT_FOUND;
}
