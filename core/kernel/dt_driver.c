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

struct dt_driver_prov_list dt_driver_provider_list =
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
				       const uint32_t *prop)
{
	struct dt_driver_phandle_args *pargs = NULL;
	unsigned int n = 0;
	void *device = NULL;

	pargs = calloc(1, prv->provider_cells * sizeof(uint32_t *) +
		       sizeof(*pargs));
	if (!pargs)
		return NULL;

	pargs->args_count = prv->provider_cells;
	for (n = 0; n < prv->provider_cells; n++)
		pargs->args[n] = fdt32_to_cpu(prop[n + 1]);

	device = prv->get_of_device(pargs, prv->priv_data);

	free(pargs);

	return device;
}

void *dt_driver_device_from_node_idx_prop(const char *prop_name,
					  const void *fdt, int nodeoffset,
					  unsigned int prop_idx)
{
	int len = 0;
	int idx = 0;
	int idx32 = 0;
	int prv_cells = 0;
	uint32_t phandle = 0;
	const uint32_t *prop = NULL;
	struct dt_driver_provider *prv = NULL;

	prop = fdt_getprop(fdt, nodeoffset, prop_name, &len);
	if (!prop)
		return NULL;

	while (idx < len) {
		idx32 = idx / sizeof(uint32_t);
		phandle = fdt32_to_cpu(prop[idx32]);

		prv = dt_driver_get_provider_by_phandle(phandle);
		if (!prv)
			return NULL;

		prv_cells = dt_driver_provider_cells(prv);
		if (prop_idx) {
			prop_idx--;
			idx += sizeof(phandle) + prv_cells * sizeof(uint32_t);
			continue;
		}

		return device_from_provider_prop(prv, prop + idx32);
	}

	return NULL;
}
