// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2022-2023, STMicroelectronics
 */

#include <assert.h>
#include <compiler.h>
#include <drivers/regulator.h>
#include <initcall.h>
#include <kernel/dt_driver.h>
#include <kernel/panic.h>
#include <libfdt.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <tee_api_defines_extensions.h>
#include <util.h>

/*
 * struct regulator_property - DT binding boolean property names
 * @name: Property name in the regulator DT node
 * @flag: Mask of the related REGULATOR_* boolean property
 */
struct regulator_property {
	const char *name;
	unsigned int flag;
};

static struct regulator_property flag_prop[] = {
	{
		.name = "regulator-always-on",
		.flag = REGULATOR_ALWAYS_ON,
	},
	{
		.name = "regulator-pull-down",
		.flag = REGULATOR_PULL_DOWN,
	},
	{
		.name = "regulator-boot-on",
		.flag = REGULATOR_BOOT_ON,
	},
};

/*
 * struct pending_regu - Regulators waiting for their supply to be ready
 *
 * @fdt: DT to work on
 * @node: Node of the regulator in @fdt
 * @supply_phandle: Phandle in @fdt of the regulator supply, or 0 if no supply
 * @regulator_allocated: True if framework allocates and frees @regulator
 * @regulator: Regulator device instance
 * @link: Link in pending regulators list
 *
 * When calling regulator_dt_register(), either the regulator depends on a
 * supply that is not initialized, or this dependency is resolved (there is
 * no supply or the supply is ready to use).
 *
 * In the former case, the regulator is placed in a pending regulator list.
 * Each time a new regulator is successfully registered, we process the
 * pending regulator list in case some pending regulators find their
 * supply and finalize their registration and initialization.
 *
 * In the latter case, the regulator registration and initialization
 * are processed.
 */
struct pending_regu {
	const void *fdt;
	int node;
	int supply_phandle;
	bool regulator_allocated;
	struct regulator *regulator;
	SLIST_ENTRY(pending_regu) link;
};

static SLIST_HEAD(, pending_regu) pending_regu_list =
	SLIST_HEAD_INITIALIZER(pending_regu);

/* Helper to find the phandle of a regulator supply */
static TEE_Result get_supply_phandle(const void *fdt, int node,
				     const char *supply_name,
				     uint32_t *supply_phandle)
{
	char *supply_prop = NULL;
	size_t prop_len = 0;
	const fdt32_t *cuint = NULL;
	int len = 0;

	prop_len = strlen(supply_name) + strlen("-supply") + 1;
	supply_prop = calloc(1, prop_len);
	if (!supply_prop)
		return TEE_ERROR_OUT_OF_MEMORY;

	len = snprintf(supply_prop, prop_len, "%s-supply", supply_name);
	assert(len > 0 && (size_t)len == prop_len - 1);

	cuint = fdt_getprop(fdt, node, supply_prop, &len);
	free(supply_prop);
	if (!cuint || (size_t)len != sizeof(*cuint)) {
		if (len != -FDT_ERR_NOTFOUND)
			return TEE_ERROR_GENERIC;

		*supply_phandle = 0;

		return TEE_SUCCESS;
	}

	*supply_phandle = fdt32_to_cpu(*cuint);
	assert(*supply_phandle);

	return TEE_SUCCESS;
}

TEE_Result regulator_dt_get_supply(const void *fdt, int node,
				   const char *supply_name,
				   struct regulator **regulator)
{
	struct dt_driver_provider *provider = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t supply_phandle = 0;

	res = get_supply_phandle(fdt, node, supply_name, &supply_phandle);
	if (res)
		return res;

	provider = dt_driver_get_provider_by_phandle(supply_phandle,
						     DT_DRIVER_REGULATOR);
	if (!provider)
		return TEE_ERROR_DEFER_DRIVER_INIT;

	*regulator = dt_driver_provider_priv_data(provider);
	assert(*regulator);

	return TEE_SUCCESS;
}

/* Helper function to register a regulator provider instance */
static TEE_Result regulator_register_provider(const void *fdt, int node,
					      struct regulator *regulator)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t phandle = 0;

	phandle = fdt_get_phandle(fdt, node);
	switch (phandle) {
	case 0:
		/* We can ignore regulators without any phandle */
		return TEE_SUCCESS;
	case (uint32_t)-1:
		DMSG("Failed to find provider phandle");
		return TEE_ERROR_GENERIC;
	default:
		res = dt_driver_register_provider(fdt, node, NULL, regulator,
						  DT_DRIVER_REGULATOR);
		if (res)
			EMSG("Can't register regulator provider %s: %#"PRIx32,
			     regulator_name(regulator), res);

		return res;
	}
}

static TEE_Result register_final(const void *fdt, int node,
				 struct regulator *regulator)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	FMSG("Regulator: finalize %s registering", regulator_name(regulator));

	res = regulator_register(regulator);
	if (res)
		return res;

	if (regulator->ops->supplied_init) {
		res = regulator->ops->supplied_init(regulator, fdt, node);
		if (res)
			return res;
	}

	return regulator_register_provider(fdt, node, regulator);
}

/*
 * Pending regulators list: stores all regulator devices registered by their
 * driver but not yet available to consumers as their dependency on their
 * regulator supply is not yet resolved (supply has not been initialized yet).
 */

static void __maybe_unused print_pending_regulators(void)
{
	struct pending_regu *pending = NULL;

	SLIST_FOREACH(pending, &pending_regu_list, link)
		DMSG("Pending regulator %s",
		     regulator_name(pending->regulator));
}

/*
 * Returns true if at least 1 regulator found its supply and finalized its
 * registration.
 */
static bool process_pending_list(void)
{
	struct dt_driver_provider *p = NULL;
	struct pending_regu *pending = NULL;
	struct pending_regu *next = NULL;
	bool supplied = false;

	SLIST_FOREACH_SAFE(pending, &pending_regu_list, link, next) {
		p = dt_driver_get_provider_by_phandle(pending->supply_phandle,
						      DT_DRIVER_REGULATOR);
		if (!p)
			continue;

		pending->regulator->supply = dt_driver_provider_priv_data(p);

		if (register_final(pending->fdt, pending->node,
				   pending->regulator))
			panic();

		SLIST_REMOVE(&pending_regu_list, pending, pending_regu, link);
		free(pending);

		supplied = true;
	}

	return supplied;
}

/*
 * Attempt to register pending regulators once their supply is found.
 * Return true if pending regulator list is empty upon processing.
 */
static bool resolve_pending_list(void)
{
	while (process_pending_list())
		;

	return SLIST_EMPTY(&pending_regu_list);
}

/* Adds a regulator to the pending list: those waiting for their supply */
static TEE_Result add_to_pending_list(const void *fdt, int node,
				      struct regulator *regulator,
				      uint32_t supply_phandle,
				      bool regulator_allocated)
{
	struct pending_regu *pending = NULL;

	pending = calloc(1, sizeof(*pending));
	if (!pending)
		return TEE_ERROR_OUT_OF_MEMORY;

	*pending = (struct pending_regu){
		.fdt = fdt,
		.node = node,
		.supply_phandle = supply_phandle,
		.regulator = regulator,
		.regulator_allocated = regulator_allocated,
	};

	SLIST_INSERT_HEAD(&pending_regu_list, pending, link);

	return TEE_SUCCESS;
}

static TEE_Result parse_dt(const void *fdt, int node,
			   struct regulator *regulator)
{
	struct regulator_property *fp = NULL;
	const fdt32_t *cuint = NULL;
	int len = 0;

	FMSG("Regulator: parse DT node %s", fdt_get_name(fdt, node, NULL));

	cuint = fdt_getprop(fdt, node, "regulator-name", NULL);
	if (cuint) {
		/* Replace name with the one found from the DT node */
		char *name = (char *)cuint;

		free(regulator->name);
		regulator->name = strdup(name);
		if (!regulator->name)
			return TEE_ERROR_OUT_OF_MEMORY;
	}

	for (fp = flag_prop; fp < (flag_prop + ARRAY_SIZE(flag_prop)); fp++)
		if (fdt_getprop(fdt, node, fp->name, NULL))
			regulator->flags |= fp->flag;

	cuint = fdt_getprop(fdt, node, "regulator-min-microvolt", &len);
	if (cuint && len == sizeof(*cuint))
		regulator->min_uv = fdt32_to_cpu(*cuint);
	else if (cuint || len != -FDT_ERR_NOTFOUND)
		panic();

	cuint = fdt_getprop(fdt, node, "regulator-max-microvolt", &len);
	if (cuint && len == sizeof(*cuint)) {
		regulator->max_uv = fdt32_to_cpu(*cuint);

		if (regulator->max_uv < regulator->min_uv) {
			EMSG("Regulator %s max_uv %d < %d",
			     regulator_name(regulator), regulator->max_uv,
			     regulator->min_uv);

			return TEE_ERROR_GENERIC;
		}
	} else if (cuint || len != -FDT_ERR_NOTFOUND) {
		panic();
	} else {
		regulator->max_uv = INT_MAX;
	}

	return TEE_SUCCESS;
}

/*
 * API function to register a DRIVER_REGULATOR provider instance.
 * The registration can be deferred if the regulator supply (if any)
 * is not yet registered, in which case the regulator is placed in
 * a regulator pending list.
 */
TEE_Result regulator_dt_register(const void *fdt, int node, int provider_node,
				 const struct regu_dt_desc *desc)
{
	TEE_Result res = TEE_ERROR_OUT_OF_MEMORY;
	struct regulator *regulator = NULL;
	uint32_t supply_phandle = 0;
	char *name = NULL;

	assert(desc);

	if (!desc->regulator) {
		regulator = calloc(1, sizeof(*regulator));
		if (!regulator)
			return TEE_ERROR_OUT_OF_MEMORY;
	} else {
		regulator = desc->regulator;
		memset(regulator, 0, sizeof(*regulator));
	}

	if (desc->name) {
		/* Will be freed if overridden by DT node content */
		name = strdup(desc->name);
		if (!name)
			goto err_free;
	}

	*regulator = (struct regulator){
		.name = name,
		.ops = desc->ops,
		.priv = desc->priv,
	};

	res = parse_dt(fdt, node, regulator);
	if (res)
		goto err_free;

	if (desc->supply_name) {
		res = get_supply_phandle(fdt, provider_node, desc->supply_name,
					 &supply_phandle);
		if (res)
			goto err_free;
	}

	if (supply_phandle) {
		res = add_to_pending_list(fdt, node, regulator, supply_phandle,
					  !desc->regulator);
		if (res)
			goto err_free;
	} else {
		res = register_final(fdt, node, regulator);
		if (res)
			goto err_free;
	}

	resolve_pending_list();

	return TEE_SUCCESS;

err_free:
	/* This function cannot return TEE_ERROR_DEFER_DRIVER_INIT */
	assert(res != TEE_ERROR_DEFER_DRIVER_INIT);

	free(regulator->name);
	if (!desc->regulator)
		free(regulator);

	return res;
}

static TEE_Result release_regulator_pending_lists(void)
{
	struct pending_regu *pending = NULL;
	struct pending_regu *next = NULL;

	if (!SLIST_EMPTY(&pending_regu_list))
		DMSG("Some regulators were not supplied:");

	SLIST_FOREACH_SAFE(pending, &pending_regu_list, link, next) {
		DMSG(" Unsupplied regulator %s",
		     regulator_name(pending->regulator));

		SLIST_REMOVE(&pending_regu_list, pending, pending_regu, link);
		if (pending->regulator_allocated)
			free(pending->regulator);
		free(pending);
	}

	return TEE_SUCCESS;
}

release_init_resource(release_regulator_pending_lists);
