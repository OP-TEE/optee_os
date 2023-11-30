// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2017-2023, STMicroelectronics
 */

#include <assert.h>
#include <drivers/i2c.h>
#include <drivers/regulator.h>
#include <drivers/stm32_i2c.h>
#include <drivers/stm32mp1_pmic.h>
#include <drivers/stpmic1.h>
#include <drivers/stpmic1_regulator.h>
#include <io.h>
#include <keep.h>
#include <kernel/boot.h>
#include <kernel/delay.h>
#include <kernel/dt.h>
#include <kernel/panic.h>
#include <kernel/pm.h>
#include <libfdt.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stm32_util.h>
#include <trace.h>
#include <util.h>

#define MODE_STANDBY                    8

#define PMIC_I2C_TRIALS			1
#define PMIC_I2C_TIMEOUT_BUSY_MS	5

#define PMIC_REGU_SUPPLY_NAME_LEN	12

#define PMIC_REGU_COUNT			14

enum {
	PMIC_REGU_FLAG_MASK_RESET = 0,
	PMIC_REGU_FLAG_COUNT
};

static_assert(IS_ENABLED(CFG_DRIVERS_REGULATOR));
static_assert(PMIC_REGU_FLAG_COUNT <= UINT_MAX);

/*
 * struct pmic_regulator_data - Platform specific data
 * @flags: Flags for platform property to apply
 * @regu_name: Regulator name ID in stpmic1 driver
 * @voltages_desc: Supported levels description
 * @voltages_level: Pointer to supported levels or NULL if not yet allocated
 */
struct pmic_regulator_data {
	unsigned int flags;
	char *regu_name;
	struct regulator_voltages_desc voltages_desc;
	int *voltages_level;
};

/* Expect a single PMIC instance */
static struct i2c_handle_s *i2c_handle;
static uint32_t pmic_i2c_addr;
static int pmic_status = -1;

/* CPU voltage supplier if found */
static char cpu_supply_name[PMIC_REGU_SUPPLY_NAME_LEN];

bool stm32mp_with_pmic(void)
{
	return pmic_status > 0;
}

static void init_pmic_state(const void *fdt, int pmic_node)
{
	pmic_status = fdt_get_status(fdt, pmic_node);
}

static bool dt_pmic_is_secure(void)
{
	return stm32mp_with_pmic() &&
	       i2c_handle->dt_status == DT_STATUS_OK_SEC;
}

static void priv_dt_properties(const void *fdt, int regu_node,
			       struct pmic_regulator_data *priv)
{
	const char *name = fdt_get_name(fdt, regu_node, NULL);

	assert(name);
	priv->regu_name = strdup(name);
	if (!priv->regu_name)
		panic();

	if (fdt_getprop(fdt, regu_node, "st,mask-reset", NULL))
		priv->flags |= PMIC_REGU_FLAG_MASK_RESET;
}

/*
 * @flags: Operations expected when entering a low power sequence
 * @voltage: Target voltage to apply during low power sequences
 */
struct regu_lp_config {
	uint8_t flags;
	struct stpmic1_lp_cfg cfg;
};

#define REGU_LP_FLAG_LOAD_PWRCTRL	BIT(0)
#define REGU_LP_FLAG_ON_IN_SUSPEND	BIT(1)
#define REGU_LP_FLAG_OFF_IN_SUSPEND	BIT(2)
#define REGU_LP_FLAG_SET_VOLTAGE	BIT(3)
#define REGU_LP_FLAG_MODE_STANDBY	BIT(4)

/*
 * struct regu_lp_state - Low power configuration for regulators
 * @name: low power state identifier string name
 * @cfg_count: number of regulator configuration instance in @cfg
 * @cfg: regulator configurations for low power state @name
 */
struct regu_lp_state {
	const char *name;
	size_t cfg_count;
	struct regu_lp_config *cfg;
};

enum regu_lp_state_id {
	REGU_LP_STATE_DISK = 0,
	REGU_LP_STATE_STANDBY,
	REGU_LP_STATE_MEM,
	REGU_LP_STATE_MEM_LOWVOLTAGE,
	REGU_LP_STATE_COUNT
};

static struct regu_lp_state regu_lp_state[REGU_LP_STATE_COUNT] = {
	[REGU_LP_STATE_DISK] = { .name = "standby-ddr-off", },
	[REGU_LP_STATE_STANDBY] = { .name = "standby-ddr-sr", },
	[REGU_LP_STATE_MEM] = { .name = "lp-stop", },
	[REGU_LP_STATE_MEM_LOWVOLTAGE] = { .name = "lplv-stop", },
};

static unsigned int regu_lp_state2idx(const char *name)
{
	unsigned int i = 0;

	for (i = 0; i < ARRAY_SIZE(regu_lp_state); i++)
		if (!strcmp(name, regu_lp_state[i].name))
			return i;

	panic();
}

static void dt_get_regu_low_power_config(const void *fdt, const char *regu_name,
					 int regu_node, const char *lp_state)
{
	unsigned int state_idx = regu_lp_state2idx(lp_state);
	struct regu_lp_state *state = regu_lp_state + state_idx;
	const fdt32_t *cuint = NULL;
	int regu_state_node = 0;
	struct regu_lp_config *regu_cfg = NULL;

	state->cfg_count++;
	state->cfg = realloc(state->cfg,
			     state->cfg_count * sizeof(*state->cfg));
	if (!state->cfg)
		panic();

	regu_cfg = &state->cfg[state->cfg_count - 1];

	memset(regu_cfg, 0, sizeof(*regu_cfg));

	if (stpmic1_regu_has_lp_cfg(regu_name)) {
		if (stpmic1_lp_cfg(regu_name, &regu_cfg->cfg)) {
			DMSG("Cannot setup low power for regu %s", regu_name);
			panic();
		}
		/*
		 * Always copy active configuration (Control register)
		 * to PWRCTRL Control register, even if regu_state_node
		 * does not exist.
		 */
		regu_cfg->flags |= REGU_LP_FLAG_LOAD_PWRCTRL;
	}

	/* Parse regulator stte node if any */
	regu_state_node = fdt_subnode_offset(fdt, regu_node, lp_state);
	if (regu_state_node <= 0)
		return;

	if (fdt_getprop(fdt, regu_state_node,
			"regulator-on-in-suspend", NULL))
		regu_cfg->flags |= REGU_LP_FLAG_ON_IN_SUSPEND;

	if (fdt_getprop(fdt, regu_state_node,
			"regulator-off-in-suspend", NULL))
		regu_cfg->flags |= REGU_LP_FLAG_OFF_IN_SUSPEND;

	cuint = fdt_getprop(fdt, regu_state_node,
			    "regulator-suspend-microvolt", NULL);
	if (cuint) {
		uint32_t mv = fdt32_to_cpu(*cuint) / 1000U;

		if (stpmic1_lp_voltage_cfg(regu_name, mv, &regu_cfg->cfg)) {
			DMSG("Cannot set voltage for %s", regu_name);
			panic();
		}
		regu_cfg->flags |= REGU_LP_FLAG_SET_VOLTAGE;
	}

	cuint = fdt_getprop(fdt, regu_state_node,
			    "regulator-mode", NULL);
	if (cuint && fdt32_to_cpu(*cuint) == MODE_STANDBY)
		regu_cfg->flags |= REGU_LP_FLAG_MODE_STANDBY;
}

/*
 * int stm32mp_pmic_set_lp_config(char *lp_state)
 *
 * Load the low power configuration stored in regu_lp_state[].
 */
void stm32mp_pmic_apply_lp_config(const char *lp_state)
{
	unsigned int state_idx = regu_lp_state2idx(lp_state);
	struct regu_lp_state *state = &regu_lp_state[state_idx];
	size_t i = 0;

	if (stpmic1_powerctrl_on())
		panic();

	for (i = 0; i < state->cfg_count; i++) {
		struct stpmic1_lp_cfg *cfg = &state->cfg[i].cfg;

		if ((state->cfg[i].flags & REGU_LP_FLAG_LOAD_PWRCTRL) &&
		    stpmic1_lp_load_unpg(cfg))
			panic();

		if ((state->cfg[i].flags & REGU_LP_FLAG_ON_IN_SUSPEND) &&
		    stpmic1_lp_on_off_unpg(cfg, 1))
			panic();

		if ((state->cfg[i].flags & REGU_LP_FLAG_OFF_IN_SUSPEND) &&
		    stpmic1_lp_on_off_unpg(cfg, 0))
			panic();

		if ((state->cfg[i].flags & REGU_LP_FLAG_SET_VOLTAGE) &&
		    stpmic1_lp_voltage_unpg(cfg))
			panic();

		if ((state->cfg[i].flags & REGU_LP_FLAG_MODE_STANDBY) &&
		    stpmic1_lp_mode_unpg(cfg, 1))
			panic();
	}
}

/* Return a libfdt compliant status value */
static int save_cpu_supply_name(void)
{
	void *fdt = NULL;
	int node = 0;
	const fdt32_t *cuint = NULL;
	const char *name = NULL;

	fdt = get_embedded_dt();
	if (!fdt)
		panic();

	node = fdt_path_offset(fdt, "/cpus/cpu@0");
	if (node < 0)
		return -FDT_ERR_NOTFOUND;

	cuint = fdt_getprop(fdt, node, "cpu-supply", NULL);
	if (!cuint)
		return -FDT_ERR_NOTFOUND;

	node = fdt_node_offset_by_phandle(fdt, fdt32_to_cpu(*cuint));
	if (node < 0)
		return -FDT_ERR_NOTFOUND;

	name = fdt_get_name(fdt, node, NULL);
	assert(strnlen(name, sizeof(cpu_supply_name)) <
	       sizeof(cpu_supply_name));

	strncpy(cpu_supply_name, name, sizeof(cpu_supply_name));

	return 0;
}

const char *stm32mp_pmic_get_cpu_supply_name(void)
{
	return cpu_supply_name;
}

/* Preallocate not that much regu references */
static char *nsec_access_regu_name[PMIC_REGU_COUNT];

bool stm32mp_nsec_can_access_pmic_regu(const char *name)
{
	size_t n = 0;

	for (n = 0; n < ARRAY_SIZE(nsec_access_regu_name); n++)
		if (nsec_access_regu_name[n] &&
		    !strcmp(nsec_access_regu_name[n], name))
			return true;

	return false;
}

static void register_nsec_regu(const char *name_ref)
{
	size_t n = 0;

	assert(!stm32mp_nsec_can_access_pmic_regu(name_ref));

	for (n = 0; n < ARRAY_SIZE(nsec_access_regu_name); n++) {
		if (!nsec_access_regu_name[n]) {
			nsec_access_regu_name[n] = strdup(name_ref);

			if (!nsec_access_regu_name[n])
				panic();
			break;
		}
	}

	assert(stm32mp_nsec_can_access_pmic_regu(name_ref));
}

static TEE_Result pmic_set_state(struct regulator *regulator, bool enable)
{
	struct pmic_regulator_data *priv = regulator->priv;
	int ret = 0;

	stm32mp_get_pmic();

	if (enable)
		ret = stpmic1_regulator_enable(priv->regu_name);
	else
		ret = stpmic1_regulator_disable(priv->regu_name);

	stm32mp_put_pmic();

	if (ret)
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

static TEE_Result pmic_get_state(struct regulator *regulator, bool *enabled)
{
	struct pmic_regulator_data *priv = regulator->priv;

	stm32mp_get_pmic();
	*enabled = stpmic1_is_regulator_enabled(priv->regu_name);
	stm32mp_put_pmic();

	return TEE_SUCCESS;
}

static TEE_Result pmic_get_voltage(struct regulator *regulator, int *level_uv)
{
	struct pmic_regulator_data *priv = regulator->priv;
	int rc = 0;

	stm32mp_get_pmic();
	rc = stpmic1_regulator_voltage_get(priv->regu_name);
	stm32mp_put_pmic();

	if (rc < 0)
		return TEE_ERROR_GENERIC;

	*level_uv = rc * 1000;

	return TEE_SUCCESS;
}

static TEE_Result pmic_set_voltage(struct regulator *regulator, int level_uv)
{
	struct pmic_regulator_data *priv = regulator->priv;
	unsigned int level_mv = level_uv / 1000;
	int rc = 0;

	if (level_mv > UINT16_MAX)
		return TEE_ERROR_BAD_PARAMETERS;

	stm32mp_get_pmic();
	rc = stpmic1_regulator_voltage_set(priv->regu_name, level_mv);
	stm32mp_put_pmic();

	if (rc)
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

static int cmp_int_value(const void *a, const void *b)
{
	const int *ia = a;
	const int *ib = b;

	return CMP_TRILEAN(*ia, *ib);
}

static size_t refine_levels_array(size_t count, int *levels_uv,
				  int min_uv, int max_uv)
{
	size_t n = 0;
	size_t m = 0;

	/* We need to sort the array has STPMIC1 driver does not */
	qsort(levels_uv, count, sizeof(*levels_uv), cmp_int_value);

	/* Remove duplicates and return optimized count */
	for (n = 1; n < count; n++) {
		if (levels_uv[m] != levels_uv[n]) {
			if (m + 1 != n)
				levels_uv[m + 1] = levels_uv[n];
			m++;
		}
	}
	count = m + 1;

	for (n = count; n; n--)
		if (levels_uv[n - 1] <= max_uv)
			break;
	count = n;

	for (n = 0; n < count; n++)
		if (levels_uv[n] >= min_uv)
			break;
	count -= n;

	memmove(levels_uv, levels_uv + n, count * sizeof(*levels_uv));

	return count;
}

static TEE_Result pmic_list_voltages(struct regulator *regulator,
				     struct regulator_voltages_desc **out_desc,
				     const int **out_levels)
{
	struct pmic_regulator_data *priv = regulator->priv;

	if (!priv->voltages_level) {
		const uint16_t *level_ref = NULL;
		size_t level_count = 0;
		int *levels2 = NULL;
		int *levels = NULL;
		size_t n = 0;

		/*
		 * Allocate and build a consised and ordered voltage list
		 * based on the voltage list provided by stpmic1 driver.
		 */
		stpmic1_regulator_levels_mv(priv->regu_name, &level_ref,
					    &level_count);

		levels = calloc(level_count, sizeof(*levels));
		if (!levels)
			return TEE_ERROR_OUT_OF_MEMORY;
		for (n = 0; n < level_count; n++)
			levels[n] = level_ref[n] * 1000;

		level_count = refine_levels_array(level_count, levels,
						  regulator->min_uv,
						  regulator->max_uv);

		/* Shrink levels array to not waste heap memory */
		levels2 = realloc(levels, sizeof(*levels) * level_count);
		if (!levels2) {
			free(levels);
			return TEE_ERROR_OUT_OF_MEMORY;
		}

		priv->voltages_desc.type = VOLTAGE_TYPE_FULL_LIST;
		priv->voltages_desc.num_levels = level_count;
		priv->voltages_level = levels2;
	}

	*out_desc = &priv->voltages_desc;
	*out_levels = priv->voltages_level;

	return TEE_SUCCESS;
}

static TEE_Result pmic_regu_init(struct regulator *regulator,
				 const void *fdt __unused, int node __unused)
{
	struct pmic_regulator_data *priv = regulator->priv;
	struct stpmic1_bo_cfg cfg = { };

	if (!priv->flags)
		return TEE_SUCCESS;

	stm32mp_get_pmic();

	if (priv->flags & PMIC_REGU_FLAG_MASK_RESET) {
		if (stpmic1_bo_mask_reset_cfg(priv->regu_name, &cfg) ||
		    stpmic1_bo_mask_reset_unpg(&cfg)) {
			EMSG("Mask reset failed for %s", priv->regu_name);
			return TEE_ERROR_GENERIC;
		}
	}

	if (regulator->flags & REGULATOR_PULL_DOWN) {
		if (stpmic1_bo_pull_down_cfg(priv->regu_name, &cfg) ||
		    stpmic1_bo_pull_down_unpg(&cfg)) {
			EMSG("Pull down failed for %s", priv->regu_name);
			return TEE_ERROR_GENERIC;
		}
	}

	stm32mp_put_pmic();

	return TEE_SUCCESS;
}

static const struct regulator_ops pmic_regu_ops = {
	.set_state = pmic_set_state,
	.get_state = pmic_get_state,
	.set_voltage = pmic_set_voltage,
	.get_voltage = pmic_get_voltage,
	.supported_voltages = pmic_list_voltages,
	.supplied_init = pmic_regu_init,
};
DECLARE_KEEP_PAGER(pmic_regu_ops);

static const struct regulator_ops pmic_sw_ops = {
	.set_state = pmic_set_state,
	.get_state = pmic_get_state,
	.supplied_init = pmic_regu_init,
};
DECLARE_KEEP_PAGER(pmic_sw_ops);

/*
 * STPMIC1 regulator names, used in the DT as regulator node name and
 * provider node <name>-supply property,
 */
static const char * const pmic_regu_name_ids[] = {
	"buck1", "buck2", "buck3", "buck4",
	"ldo1", "ldo2", "ldo3", "ldo4", "ldo5", "ldo6",
	"vref_ddr", "boost", "pwr_sw1", "pwr_sw2"
};

/* Preallocated regulator instances */
static struct regulator pmic_regulators[ARRAY_SIZE(pmic_regu_name_ids)];
static struct pmic_regulator_data pmic_regu_cfg[ARRAY_SIZE(pmic_regu_name_ids)];

static TEE_Result release_voltage_lists(void)
{
	size_t n = 0;

	/* Voltage list will be rebuilt at runtime if needed at least once */
	for (n = 0; n < ARRAY_SIZE(pmic_regulators); n++) {
		struct pmic_regulator_data *priv = pmic_regulators[n].priv;

		if (priv && priv->voltages_level)
			free(priv->voltages_level);
	}

	return TEE_SUCCESS;
}

release_init_resource(release_voltage_lists);

struct regulator *stm32mp_pmic_get_regulator(const char *name)
{
	size_t i = 0;

	if (!name)
		return NULL;

	for (i = 0; i < ARRAY_SIZE(pmic_regu_name_ids); i++)
		if (!strcmp(pmic_regu_name_ids[i], name) &&
		    pmic_regulators[i].ops)
			return pmic_regulators + i;

	return NULL;
}

static TEE_Result register_pmic_regulator(const void *fdt,
					  const char *regu_name, int regu_node,
					  int regulators_node)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct regu_dt_desc desc = { };
	size_t i = 0;

	for (i = 0; i < ARRAY_SIZE(pmic_regu_name_ids); i++)
		if (!strcmp(pmic_regu_name_ids[i], regu_name))
			break;
	if (i >= ARRAY_SIZE(pmic_regu_name_ids)) {
		EMSG("Unknown regulator name %s", regu_name);
		panic();
	}

	desc = (struct regu_dt_desc){
		.name = pmic_regu_name_ids[i],
		.supply_name = pmic_regu_name_ids[i],
		.regulator = pmic_regulators + i,
		.priv = pmic_regu_cfg + i,
	};

	priv_dt_properties(fdt, regu_node, pmic_regu_cfg + i);

	/*
	 * pwr_sw1 and pwr_sw2 are regulator switches hence have no
	 * set_voltage.get_voltage handler.
	 */
	if (!strncmp(regu_name, "pwr_sw", 6))
		desc.ops = &pmic_sw_ops;
	else
		desc.ops = &pmic_regu_ops;

	res = regulator_dt_register(fdt, regu_node, regulators_node, &desc);
	if (res)
		EMSG("Failed to register %s, error: %#"PRIx32, regu_name, res);

	return res;
}

static void parse_regulator_fdt_nodes(const void *fdt, int pmic_node)
{
	int regulators_node = 0;
	int regu_node = 0;

	regulators_node = fdt_subnode_offset(fdt, pmic_node, "regulators");
	if (regulators_node < 0)
		panic();

	fdt_for_each_subnode(regu_node, fdt, regulators_node) {
		int status = fdt_get_status(fdt, regu_node);
		const char *regu_name = NULL;
		size_t n = 0;

		assert(status >= 0);
		if (status == DT_STATUS_DISABLED)
			continue;

		regu_name = fdt_get_name(fdt, regu_node, NULL);

		assert(stpmic1_regulator_is_valid(regu_name));

		if (status & DT_STATUS_OK_NSEC)
			register_nsec_regu(regu_name);

		for (n = 0; n < ARRAY_SIZE(regu_lp_state); n++)
			dt_get_regu_low_power_config(fdt, regu_name, regu_node,
						     regu_lp_state[n].name);

		if (register_pmic_regulator(fdt, regu_name, regu_node,
					    regulators_node))
			panic();
	}

	if (save_cpu_supply_name())
		DMSG("No CPU supply provided");
}

/*
 * PMIC and resource initialization
 */

static void initialize_pmic_i2c(const void *fdt, int pmic_node)
{
	const fdt32_t *cuint = NULL;

	cuint = fdt_getprop(fdt, pmic_node, "reg", NULL);
	if (!cuint) {
		EMSG("PMIC configuration failed on reg property");
		panic();
	}

	pmic_i2c_addr = fdt32_to_cpu(*cuint) << 1;
	if (pmic_i2c_addr > UINT16_MAX) {
		EMSG("PMIC configuration failed on i2c address translation");
		panic();
	}

	stm32mp_get_pmic();

	if (!stm32_i2c_is_device_ready(i2c_handle, pmic_i2c_addr,
				       PMIC_I2C_TRIALS,
				       PMIC_I2C_TIMEOUT_BUSY_MS))
		panic();

	stpmic1_bind_i2c(i2c_handle, pmic_i2c_addr);

	stm32mp_put_pmic();
}

/*
 * Automated suspend/resume at system suspend/resume is expected
 * only when the PMIC is secure. If it is non secure, only atomic
 * execution context can get/put the PMIC resources.
 */
static TEE_Result pmic_pm(enum pm_op op, uint32_t pm_hint __unused,
			  const struct pm_callback_handle *pm_handle __unused)
{
	if (op == PM_OP_SUSPEND)
		stm32_i2c_suspend(i2c_handle);
	else
		stm32_i2c_resume(i2c_handle);

	return TEE_SUCCESS;
}
DECLARE_KEEP_PAGER(pmic_pm);

/* stm32mp_get/put_pmic allows secure atomic sequences to use non secure PMIC */
void stm32mp_get_pmic(void)
{
	stm32_i2c_resume(i2c_handle);
}

void stm32mp_put_pmic(void)
{
	stm32_i2c_suspend(i2c_handle);
}

static void register_non_secure_pmic(void)
{
	/* Allow this function to be called when STPMIC1 not used */
	if (!i2c_handle->base.pa)
		return;

	stm32mp_register_non_secure_pinctrl(i2c_handle->pinctrl);
	if (i2c_handle->pinctrl_sleep)
		stm32mp_register_non_secure_pinctrl(i2c_handle->pinctrl_sleep);

	stm32mp_register_non_secure_periph_iomem(i2c_handle->base.pa);
}

static void register_secure_pmic(void)
{
	stm32mp_register_secure_pinctrl(i2c_handle->pinctrl);
	if (i2c_handle->pinctrl_sleep)
		stm32mp_register_secure_pinctrl(i2c_handle->pinctrl_sleep);

	stm32mp_register_secure_periph_iomem(i2c_handle->base.pa);
	register_pm_driver_cb(pmic_pm, NULL, "stm32mp1-pmic");
}

static TEE_Result initialize_pmic(const void *fdt, int pmic_node)
{
	unsigned long pmic_version = 0;

	init_pmic_state(fdt, pmic_node);

	initialize_pmic_i2c(fdt, pmic_node);

	stm32mp_get_pmic();

	if (stpmic1_get_version(&pmic_version))
		panic("Failed to access PMIC");

	DMSG("PMIC version = 0x%02lx", pmic_version);
	stm32mp_put_pmic();

	if (dt_pmic_is_secure())
		register_secure_pmic();
	else
		register_non_secure_pmic();

	parse_regulator_fdt_nodes(fdt, pmic_node);

	return TEE_SUCCESS;
}

static TEE_Result stm32_pmic_probe(const void *fdt, int node,
				   const void *compat_data __unused)
{
	struct stm32_i2c_dev *stm32_i2c_dev = NULL;
	struct i2c_dev *i2c_dev = NULL;
	TEE_Result res = TEE_SUCCESS;

	res = i2c_dt_get_dev(fdt, node, &i2c_dev);
	if (res)
		return res;

	stm32_i2c_dev = container_of(i2c_dev, struct stm32_i2c_dev, i2c_dev);
	i2c_handle = stm32_i2c_dev->handle;

	res = initialize_pmic(fdt, node);
	if (res) {
		DMSG("Unexpectedly failed to get I2C bus: %#"PRIx32, res);
		panic();
	}

	return TEE_SUCCESS;
}

static const struct dt_device_match stm32_pmic_match_table[] = {
	{ .compatible = "st,stpmic1" },
	{ }
};

DEFINE_DT_DRIVER(stm32_pmic_dt_driver) = {
	.name = "st,stpmic1",
	.match_table = stm32_pmic_match_table,
	.probe = stm32_pmic_probe,
};
