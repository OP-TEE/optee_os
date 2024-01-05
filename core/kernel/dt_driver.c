// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021, Linaro Limited
 * Copyright (c) 2021, Bootlin
 * Copyright (c) 2021, Linaro Limited
 * Copyright (c) 2021, STMicroelectronics
 */

#include <assert.h>
#include <config.h>
#include <initcall.h>
#include <kernel/boot.h>
#include <kernel/dt.h>
#include <kernel/dt_driver.h>
#include <libfdt.h>
#include <malloc.h>
#include <sys/queue.h>
#include <tee_api_defines_extensions.h>
#include <tee_api_types.h>

/*
 * struct dt_driver_probe - Node instance in secure FDT to probe a driver for
 *
 * @link: List hook
 * @nodeoffset: Node offset of device referenced in the FDT
 * @type: One of DT_DRIVER_* or DT_DRIVER_NOTYPE.
 * @deferrals: Driver probe deferrals count
 * @dt_drv: Matching driver to probe if found or NULL
 * @dm: Matching reference if applicable or NULL
 */
struct dt_driver_probe {
	int nodeoffset;
	enum dt_driver_type type;
	unsigned int deferrals;
	const struct dt_driver *dt_drv;
	const struct dt_device_match *dm;
	TAILQ_ENTRY(dt_driver_probe) link;
};

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

/*
 * Device driver providers are able to provide a driver specific instance
 * related to device phandle arguments found in the secure embedded FDT.
 */
static SLIST_HEAD(, dt_driver_provider) dt_driver_provider_list =
	SLIST_HEAD_INITIALIZER(dt_driver_provider_list);

/* FDT nodes for which a matching driver is to be probed */
static TAILQ_HEAD(dt_driver_probe_head, dt_driver_probe) dt_driver_probe_list =
	TAILQ_HEAD_INITIALIZER(dt_driver_probe_list);

/* FDT nodes for which a matching driver has been successfully probed */
static TAILQ_HEAD(, dt_driver_probe) dt_driver_ready_list =
	TAILQ_HEAD_INITIALIZER(dt_driver_ready_list);

/* List of the nodes for which a compatible driver but reported a failure */
static TAILQ_HEAD(, dt_driver_probe) dt_driver_failed_list =
	TAILQ_HEAD_INITIALIZER(dt_driver_failed_list);

/* Flag enabled when a new node (possibly typed) is added in the probe list */
static bool added_node;

/* Resolve drivers dependencies on core crypto layer */
static bool tee_crypt_is_ready;

void dt_driver_crypt_init_complete(void)
{
	assert(!tee_crypt_is_ready);
	tee_crypt_is_ready = true;
}

TEE_Result dt_driver_get_crypto(void)
{
	if (tee_crypt_is_ready)
		return TEE_SUCCESS;
	else
		return TEE_ERROR_DEFER_DRIVER_INIT;
}

static void assert_type_is_valid(enum dt_driver_type type)
{
	switch (type) {
	case DT_DRIVER_NOTYPE:
	case DT_DRIVER_CLK:
	case DT_DRIVER_RSTCTRL:
	case DT_DRIVER_UART:
	case DT_DRIVER_GPIO:
	case DT_DRIVER_I2C:
	case DT_DRIVER_PINCTRL:
	case DT_DRIVER_INTERRUPT:
	case DT_DRIVER_REGULATOR:
	case DT_DRIVER_NVMEM:
		return;
	default:
		assert(0);
	}
}

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

	assert_type_is_valid(type);

	provider_cells = fdt_get_dt_driver_cells(fdt, nodeoffset, type);
	if (provider_cells < 0) {
		DMSG("Failed to find provider cells: %d", provider_cells);
		return TEE_ERROR_GENERIC;
	}

	phandle = fdt_get_phandle(fdt, nodeoffset);
	if (phandle == (uint32_t)-1) {
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

static bool dt_driver_use_parent_controller(enum dt_driver_type type)
{
	switch (type) {
	case DT_DRIVER_PINCTRL:
	case DT_DRIVER_NVMEM:
		return true;
	default:
		return false;
	}
}

/*
 * Helper functions for dt_drivers querying driver provider information
 */

int fdt_get_dt_driver_cells(const void *fdt, int nodeoffset,
			    enum dt_driver_type type)
{
	const char *cells_name = NULL;
	const fdt32_t *c = NULL;
	int len = 0;

	if (dt_driver_use_parent_controller(type))
		return 0;

	switch (type) {
	case DT_DRIVER_CLK:
		cells_name = "#clock-cells";
		break;
	case DT_DRIVER_INTERRUPT:
		cells_name = "#interrupt-cells";
		break;
	case DT_DRIVER_RSTCTRL:
		cells_name = "#reset-cells";
		break;
	case DT_DRIVER_GPIO:
		cells_name = "#gpio-cells";
		break;
	case DT_DRIVER_I2C:
	case DT_DRIVER_REGULATOR:
		return 0;
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

void *dt_driver_provider_priv_data(struct dt_driver_provider *prv)
{
	return prv->priv_data;
}

struct dt_driver_provider *
dt_driver_get_provider_by_node(int nodeoffset, enum dt_driver_type type)
{
	struct dt_driver_provider *prv = NULL;

	SLIST_FOREACH(prv, &dt_driver_provider_list, link)
		if (prv->nodeoffset == nodeoffset && prv->type == type)
			return prv;

	return NULL;
}

struct dt_driver_provider *
dt_driver_get_provider_by_phandle(uint32_t phandle, enum dt_driver_type type)
{
	struct dt_driver_provider *prv = NULL;

	SLIST_FOREACH(prv, &dt_driver_provider_list, link)
		if (prv->phandle == phandle && prv->type == type)
			return prv;

	return NULL;
}

static TEE_Result device_from_provider_prop(struct dt_driver_provider *prv,
					    const void *fdt, int phandle_node,
					    const uint32_t *prop,
					    void *device_ref)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct dt_pargs *pargs = NULL;
	unsigned int n = 0;

	pargs = calloc(1, prv->provider_cells * sizeof(uint32_t *) +
		       sizeof(*pargs));
	if (!pargs)
		return TEE_ERROR_OUT_OF_MEMORY;

	pargs->fdt = fdt;
	pargs->phandle_node = phandle_node;
	pargs->args_count = prv->provider_cells;
	for (n = 0; n < prv->provider_cells; n++) {
		assert(prop);
		pargs->args[n] = fdt32_to_cpu(prop[n]);
	}

	res = prv->get_of_device(pargs, prv->priv_data, device_ref);

	free(pargs);

	return res;
}

TEE_Result dt_driver_device_from_parent(const void *fdt, int nodeoffset,
					enum dt_driver_type type,
					void *device_ref)
{
	int parent = -1;
	struct dt_driver_provider *prv = NULL;

	assert(fdt == get_secure_dt());

	parent = fdt_parent_offset(fdt, nodeoffset);
	if (parent < 0)
		return TEE_ERROR_GENERIC;

	prv = dt_driver_get_provider_by_node(parent, type);
	if (!prv) {
		/* No provider registered yet */
		return TEE_ERROR_DEFER_DRIVER_INIT;
	}

	return device_from_provider_prop(prv, fdt, nodeoffset, NULL,
					 device_ref);
}

TEE_Result dt_driver_device_from_node_idx_prop_phandle(const char *prop_name,
						       const void *fdt,
						       int nodeoffs,
						       unsigned int prop_index,
						       enum dt_driver_type type,
						       uint32_t phandle,
						       void *device_ref)
{
	int len = 0;
	const uint32_t *prop = NULL;
	int phandle_node_unused = -1;
	struct dt_driver_provider *prv = NULL;

	prop = fdt_getprop(fdt, nodeoffs, prop_name, &len);
	if (!prop) {
		if (len != -FDT_ERR_NOTFOUND) {
			DMSG("Corrupted node %s", prop_name);
			return TEE_ERROR_GENERIC;
		} else {
			DMSG("Property %s missing in node %s", prop_name,
			     fdt_get_name(fdt, nodeoffs, NULL));
			return TEE_ERROR_ITEM_NOT_FOUND;
		}
	}

	prv = dt_driver_get_provider_by_phandle(phandle, type);
	if (!prv)
		return TEE_ERROR_DEFER_DRIVER_INIT;

	prop_index *= dt_driver_provider_cells(prv);
	if ((prop_index + 1) * sizeof(*prop) > (size_t)len)
		return TEE_ERROR_ITEM_NOT_FOUND;

	return device_from_provider_prop(prv, fdt, phandle_node_unused,
					 prop + prop_index, device_ref);
}

TEE_Result dt_driver_device_from_node_idx_prop(const char *prop_name,
					       const void *fdt, int nodeoffset,
					       unsigned int prop_idx,
					       enum dt_driver_type type,
					       void *device_ref)
{
	int len = 0;
	int idx = 0;
	int idx32 = 0;
	int prv_cells = 0;
	int phandle_node = -1;
	uint32_t phandle = 0;
	const uint32_t *prop = NULL;
	struct dt_driver_provider *prv = NULL;

	prop = fdt_getprop(fdt, nodeoffset, prop_name, &len);
	if (!prop) {
		DMSG("Property %s missing in node %s", prop_name,
		     fdt_get_name(fdt, nodeoffset, NULL));
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	while (idx < len) {
		idx32 = idx / sizeof(uint32_t);
		phandle = fdt32_to_cpu(prop[idx32]);
		if (!phandle) {
			if (!prop_idx)
				break;
			idx += sizeof(phandle);
			prop_idx--;
			continue;
		}

		/*
		 * In some cases, pinctrl, i2c, nvmem, etc, the consumer phandle
		 * points directly to a subnode of the parent. In such cases,
		 * the provider does not have any "-cells" property and
		 * potentially no "phandle" property.
		 */
		if (dt_driver_use_parent_controller(type)) {
			phandle_node = fdt_node_offset_by_phandle(fdt, phandle);
			if (phandle_node < 0)
				return TEE_ERROR_GENERIC;

			nodeoffset = fdt_parent_offset(fdt, phandle_node);
			if (nodeoffset < 0)
				return TEE_ERROR_GENERIC;

			prv = dt_driver_get_provider_by_node(nodeoffset, type);
		} else {
			prv = dt_driver_get_provider_by_phandle(phandle, type);
		}

		if (prv) {
			prv_cells = dt_driver_provider_cells(prv);
		} else if (prop_idx) {
			/*
			 * When we need to skip another provider phandle
			 * arguments cells (aka when prop_idx != 0), we don't
			 * really need the skipped provider to be already
			 * registered, we can look straight in its DT node.
			 */
			phandle_node = fdt_node_offset_by_phandle(fdt, phandle);
			if (phandle_node < 0) {
				DMSG("Can't find node for phandle %"PRIu32,
				     phandle);
				return TEE_ERROR_GENERIC;
			}

			prv_cells = fdt_get_dt_driver_cells(fdt, phandle_node,
							    type);
			if (prv_cells < 0) {
				DMSG("Can't find cells count on node %s: %d",
				     fdt_get_name(fdt, phandle_node, NULL),
				     prv_cells);
				return TEE_ERROR_GENERIC;
			}
		}

		if (prop_idx) {
			prop_idx--;
			idx += sizeof(phandle) + prv_cells * sizeof(uint32_t);
			continue;
		}

		if (!prv)
			return TEE_ERROR_DEFER_DRIVER_INIT;

		/* Skip property cell with the phandle, already handled */
		idx32++;

		return device_from_provider_prop(prv, fdt, phandle_node,
						 prop + idx32, device_ref);
	}

	return TEE_ERROR_ITEM_NOT_FOUND;
}

static void __maybe_unused print_probe_list(const void *fdt __maybe_unused)
{
	struct dt_driver_probe *elt = NULL;
	unsigned int count = 0;

	TAILQ_FOREACH(elt, &dt_driver_probe_list, link)
		count++;

	DMSG("Probe list: %u elements", count);
	TAILQ_FOREACH(elt, &dt_driver_probe_list, link)
		DMSG("|- Driver %s probes on node %s",
		     elt->dt_drv->name,
		     fdt_get_name(fdt, elt->nodeoffset, NULL));

	DMSG("`- Probe list end");

	count = 0;
	TAILQ_FOREACH(elt, &dt_driver_failed_list, link)
		count++;

	DMSG("Failed list: %u elements", count);
	TAILQ_FOREACH(elt, &dt_driver_failed_list, link)
		EMSG("|- Driver %s on node %s failed", elt->dt_drv->name,
		     fdt_get_name(fdt, elt->nodeoffset, NULL));

	DMSG("`- Failed list end");
}

/*
 * Probe element: push to ready list if succeeds, push to probe list if probe
 * if deferred, panic with an error trace otherwise.
 */
static TEE_Result probe_driver_node(const void *fdt,
				    struct dt_driver_probe *elt)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	const char __maybe_unused *drv_name = NULL;
	const char __maybe_unused *node_name = NULL;

	node_name = fdt_get_name(fdt, elt->nodeoffset, NULL);
	drv_name = elt->dt_drv->name;

	if (!elt->dt_drv->probe) {
		DMSG("No probe operator for driver %s, skipped", drv_name);
		return TEE_SUCCESS;
	}

	FMSG("Probing %s on node %s", drv_name, node_name);

	res = elt->dt_drv->probe(fdt, elt->nodeoffset, elt->dm->compat_data);
	switch (res) {
	case TEE_SUCCESS:
		TAILQ_INSERT_HEAD(&dt_driver_ready_list, elt, link);

		DMSG("element: %s on node %s initialized", drv_name, node_name);
		break;
	case TEE_ERROR_DEFER_DRIVER_INIT:
		elt->deferrals++;
		TAILQ_INSERT_TAIL(&dt_driver_probe_list, elt, link);

		DMSG("element: %s on node %s deferred %u time(s)", drv_name,
		     node_name, elt->deferrals);
		break;
	case TEE_ERROR_NODE_DISABLED:
		DMSG("element: %s on node %s is disabled", drv_name, node_name);
		break;
	default:
		TAILQ_INSERT_HEAD(&dt_driver_failed_list, elt, link);

		EMSG("Failed to probe %s on node %s: %#"PRIx32,
		     drv_name, node_name, res);
		break;
	}

	return res;
}

static TEE_Result alloc_elt_and_probe(const void *fdt, int node,
				      const struct dt_driver *dt_drv,
				      const struct dt_device_match *dm)
{
	struct dt_driver_probe *elt = NULL;

	/* Will be freed when lists are released */
	elt = calloc(1, sizeof(*elt));
	if (!elt)
		return TEE_ERROR_OUT_OF_MEMORY;

	elt->nodeoffset = node;
	elt->dt_drv = dt_drv;
	elt->dm = dm;
	elt->type = dt_drv->type;

	return probe_driver_node(fdt, elt);
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
				return alloc_elt_and_probe(fdt, node, drv, dm);
	}

	return TEE_ERROR_ITEM_NOT_FOUND;
}

/*
 * Lookup the best matching compatible driver, possibly of a specific @type,
 * for the FDT node.
 */
TEE_Result dt_driver_probe_device_by_node(const void *fdt, int nodeoffset,
					  enum dt_driver_type type)
{
	int idx = 0;
	int len = 0;
	int count = 0;
	const char *compat = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;

	assert_type_is_valid(type);

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

static TEE_Result process_probe_list(const void *fdt)
{
	struct dt_driver_probe *elt = NULL;
	struct dt_driver_probe *prev = NULL;
	static unsigned int __maybe_unused loop_count;
	static unsigned int __maybe_unused deferral_loop_count;
	bool __maybe_unused one_deferred = false;
	bool one_probed_ok = false;

	do {
		loop_count++;
		FMSG("Probe loop %u after %u for deferral(s)", loop_count,
		     deferral_loop_count);

		/* Hack here for TRACE_DEBUG messages on probe list elements */
		if (TRACE_LEVEL >= TRACE_FLOW)
			print_probe_list(fdt);

		if (TAILQ_EMPTY(&dt_driver_probe_list))
			return TEE_SUCCESS;

		/*
		 * Probe from current end to top. Deferred probed node are
		 * pushed back after current tail for the next probe round.
		 * Reset probe result flags and see status after probe round.
		 */
		one_deferred = false;
		one_probed_ok = false;
		added_node = false;

		TAILQ_FOREACH_REVERSE_SAFE(elt, &dt_driver_probe_list,
					   dt_driver_probe_head, link, prev) {
			TAILQ_REMOVE(&dt_driver_probe_list, elt, link);

			switch (probe_driver_node(fdt, elt)) {
			case TEE_SUCCESS:
				one_probed_ok = true;
				break;
			case TEE_ERROR_DEFER_DRIVER_INIT:
				one_deferred = true;
				break;
			default:
				break;
			}
		}

		if (one_deferred)
			deferral_loop_count++;

	} while (added_node || one_probed_ok);

	DMSG("Unresolved dependencies after %u rounds, %u deferred",
	     loop_count, deferral_loop_count);

	if (one_deferred)
		return TEE_ERROR_DEFER_DRIVER_INIT;
	else
		return TEE_ERROR_GENERIC;
}

static int driver_probe_compare(struct dt_driver_probe *candidate,
				struct dt_driver_probe *elt)
{
	if (candidate->nodeoffset != elt->nodeoffset ||
	    candidate->type != elt->type)
		return 1;

	assert(elt->dt_drv == candidate->dt_drv);
	return 0;
}

/*
 * Return TEE_SUCCESS if compatible found
 *	  TEE_ERROR_OUT_OF_MEMORY if heap is exhausted
 */
static TEE_Result add_node_to_probe(const void *fdt, int node,
				    const struct dt_driver *dt_drv,
				    const struct dt_device_match *dm)
{
	const char __maybe_unused *node_name = fdt_get_name(fdt, node, NULL);
	const char __maybe_unused *drv_name = dt_drv->name;
	struct dt_driver_probe *elt = NULL;
	struct dt_driver_probe elt_new = {
		.dm = dm,
		.dt_drv = dt_drv,
		.nodeoffset = node,
		.type = dt_drv->type,
	};

	/* If node/type found in probe list or ready list, nothing to do */
	TAILQ_FOREACH(elt, &dt_driver_probe_list, link)
		if (!driver_probe_compare(&elt_new, elt))
			return TEE_SUCCESS;

	TAILQ_FOREACH(elt, &dt_driver_ready_list, link)
		if (!driver_probe_compare(&elt_new, elt))
			return TEE_SUCCESS;

	elt = malloc(sizeof(*elt));
	if (!elt)
		return TEE_ERROR_OUT_OF_MEMORY;

	DMSG("element: %s on node %s", drv_name, node_name);

	memcpy(elt, &elt_new, sizeof(*elt));

	added_node = true;

	TAILQ_INSERT_TAIL(&dt_driver_probe_list, elt, link);

	/* Hack here for TRACE_DEBUG messages on current probe list elements */
	if (TRACE_LEVEL >= TRACE_FLOW)
		print_probe_list(fdt);

	return TEE_SUCCESS;
}

/*
 * Add a node to the probe list if a dt_driver matches target compatible.
 *
 * If @type is DT_DRIVER_ANY, probe list can hold only 1 driver to probe for
 * the node. A node may probe several drivers if have a unique driver type.
 *
 * Return TEE_SUCCESS if compatible found
 *	  TEE_ERROR_ITEM_NOT_FOUND if no matching driver
 *	  TEE_ERROR_OUT_OF_MEMORY if heap is exhausted
 */
static TEE_Result add_probe_node_by_compat(const void *fdt, int node,
					   const char *compat)
{
	TEE_Result res = TEE_ERROR_ITEM_NOT_FOUND;
	const struct dt_driver *dt_drv = NULL;
	const struct dt_device_match *dm = NULL;
	uint32_t found_types = 0;

	for_each_dt_driver(dt_drv) {
		for (dm = dt_drv->match_table; dm && dm->compatible; dm++) {
			if (strcmp(dm->compatible, compat) == 0) {
				assert(dt_drv->type < 32);

				res = add_node_to_probe(fdt, node, dt_drv, dm);
				if (res)
					return res;

				if (found_types & BIT(dt_drv->type)) {
					EMSG("Driver %s multi hit on type %u",
					     dt_drv->name, dt_drv->type);
					panic();
				}
				found_types |= BIT(dt_drv->type);

				/* Matching found for this driver, try next */
				break;
			}
		}
	}

	return res;
}

/*
 * Add the node to the probe list if matching compatible drivers are found.
 * Follow node's compatible property list ordering to find matching driver.
 */
TEE_Result dt_driver_maybe_add_probe_node(const void *fdt, int node)
{
	int idx = 0;
	int len = 0;
	int count = 0;
	const char *compat = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (fdt_get_status(fdt, node) == DT_STATUS_DISABLED)
		return TEE_SUCCESS;

	count = fdt_stringlist_count(fdt, node, "compatible");
	if (count < 0)
		return TEE_SUCCESS;

	for (idx = 0; idx < count; idx++) {
		compat = fdt_stringlist_get(fdt, node, "compatible", idx, &len);
		assert(compat && len > 0);

		res = add_probe_node_by_compat(fdt, node, compat);

		/* Stop lookup if something was found */
		if (res != TEE_ERROR_ITEM_NOT_FOUND)
			return res;
	}

	return TEE_SUCCESS;
}

static void parse_node(const void *fdt, int node)
{
	TEE_Result __maybe_unused res = TEE_ERROR_GENERIC;
	int subnode = 0;

	fdt_for_each_subnode(subnode, fdt, node) {
		res = dt_driver_maybe_add_probe_node(fdt, subnode);
		if (res) {
			EMSG("Failed on node %s with %#"PRIx32,
			     fdt_get_name(fdt, subnode, NULL), res);
			panic();
		}

		/*
		 * Rescursively parse the FDT, skipping disabled nodes.
		 * FDT is expected reliable and core shall have sufficient
		 * stack depth to possibly parse all DT nodes.
		 */
		if (IS_ENABLED(CFG_DRIVERS_DT_RECURSIVE_PROBE)) {
			if (fdt_get_status(fdt, subnode) == DT_STATUS_DISABLED)
				continue;

			parse_node(fdt, subnode);
		}
	}
}

/*
 * Parse FDT for nodes and save in probe list the node for which a dt_driver
 * matches node's compatible property.
 */
static TEE_Result probe_dt_drivers_early(void)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	const void *fdt = NULL;

	fdt = get_secure_dt();
	if (!fdt)
		return TEE_SUCCESS;

	parse_node(fdt, fdt_path_offset(fdt, "/"));

	res = process_probe_list(fdt);
	if (res == TEE_ERROR_DEFER_DRIVER_INIT) {
		DMSG("Deferred drivers probing");
		print_probe_list(fdt);
		res = TEE_SUCCESS;
	}

	return res;
}

static TEE_Result probe_dt_drivers(void)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	const void *fdt = NULL;

	fdt = get_secure_dt();
	if (!fdt)
		return TEE_SUCCESS;

	res = process_probe_list(fdt);
	if (res || !TAILQ_EMPTY(&dt_driver_failed_list)) {
		EMSG("Probe sequence result: %#"PRIx32, res);
		print_probe_list(fdt);
		panic();
	}

	return TEE_SUCCESS;
}

early_init_late(probe_dt_drivers_early);
driver_init(probe_dt_drivers);

static TEE_Result release_probe_lists(void)
{
	struct dt_driver_probe *elt = NULL;
	struct dt_driver_probe *next = NULL;
	struct dt_driver_provider *prov = NULL;
	struct dt_driver_provider *next_prov = NULL;
	const void *fdt = NULL;

	fdt = get_secure_dt();
	if (!fdt)
		return TEE_SUCCESS;

	assert(fdt && TAILQ_EMPTY(&dt_driver_probe_list));

	TAILQ_FOREACH_SAFE(elt, &dt_driver_ready_list, link, next)
		free(elt);

	TAILQ_FOREACH_SAFE(elt, &dt_driver_failed_list, link, next)
	       free(elt);

	SLIST_FOREACH_SAFE(prov, &dt_driver_provider_list, link, next_prov)
	       free(prov);

	return TEE_SUCCESS;
}

release_init_resource(release_probe_lists);

/*
 * Simple bus support: handy to parse subnodes
 */
static TEE_Result simple_bus_probe(const void *fdt, int node,
				   const void *compat_data __unused)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	int subnode = 0;

	fdt_for_each_subnode(subnode, fdt, node) {
		res = dt_driver_maybe_add_probe_node(fdt, subnode);
		if (res) {
			EMSG("Failed on node %s with %#"PRIx32,
			     fdt_get_name(fdt, subnode, NULL), res);
			panic();
		}
	}

	return TEE_SUCCESS;
}

static const struct dt_device_match simple_bus_match_table[] = {
	{ .compatible = "simple-bus" },
	{ }
};

DEFINE_DT_DRIVER(simple_bus_dt_driver) = {
	.name = "simple-bus",
	.match_table = simple_bus_match_table,
	.probe = simple_bus_probe,
};
