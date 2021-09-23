// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2017-2020, STMicroelectronics
 */

#include <drivers/stm32_i2c.h>
#include <drivers/stm32mp1_pmic.h>
#include <drivers/stpmic1.h>
#include <io.h>
#include <keep.h>
#include <kernel/delay.h>
#include <kernel/dt.h>
#include <kernel/boot.h>
#include <kernel/panic.h>
#include <kernel/pm.h>
#include <libfdt.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <stdbool.h>
#include <stm32_util.h>
#include <trace.h>
#include <util.h>

#define MODE_STANDBY                    8

#define PMIC_I2C_TRIALS			1
#define PMIC_I2C_TIMEOUT_BUSY_MS	5

#define PMIC_REGU_SUPPLY_NAME_LEN	12

#define PMIC_REGU_COUNT			14

/* Expect a single PMIC instance */
static struct i2c_handle_s i2c_handle;
static uint32_t pmic_i2c_addr;

/* CPU voltage supplier if found */
static char cpu_supply_name[PMIC_REGU_SUPPLY_NAME_LEN];

bool stm32mp_with_pmic(void)
{
	return i2c_handle.dt_status & DT_STATUS_OK_SEC;
}

static int dt_get_pmic_node(void *fdt)
{
	static int node = -FDT_ERR_BADOFFSET;

	if (node == -FDT_ERR_BADOFFSET)
		node = fdt_node_offset_by_compatible(fdt, -1, "st,stpmic1");

	return node;
}

static int dt_pmic_status(void)
{
	void *fdt = get_embedded_dt();

	if (fdt) {
		int node = dt_get_pmic_node(fdt);

		if (node > 0)
			return _fdt_get_status(fdt, node);
	}

	return -1;
}

int stm32mp_dt_pmic_status(void)
{
	return dt_pmic_status();
}

static bool dt_pmic_is_secure(void)
{
	int status = dt_pmic_status();

	return status == DT_STATUS_OK_SEC &&
	       i2c_handle.dt_status == DT_STATUS_OK_SEC;
}

/*
 * struct regu_bo_config - Boot on configuration for a regulator
 * @flags: Operations expected when entering a low power sequence
 * @cfg: Boot-on configuration to apply during low power sequences
 */
struct regu_bo_config {
	uint8_t flags;
	struct stpmic1_bo_cfg cfg;
};

#define REGU_BO_FLAG_ENABLE_REGU		BIT(0)
#define REGU_BO_FLAG_SET_VOLTAGE		BIT(1)
#define REGU_BO_FLAG_PULL_DOWN			BIT(2)
#define REGU_BO_FLAG_MASK_RESET			BIT(3)

static struct regu_bo_config *regu_bo_config;
static size_t regu_bo_count;

/* boot-on mandatory? if so: caller panic() on error status */
static void dt_get_regu_boot_on_config(void *fdt, const char *regu_name,
				       int regu_node)
{
	const fdt32_t *cuint = NULL;
	struct regu_bo_config regu_cfg = { };
	uint16_t mv = 0;

	if ((!fdt_getprop(fdt, regu_node, "regulator-boot-on", NULL)) &&
	    (!fdt_getprop(fdt, regu_node, "regulator-always-on", NULL)))
		return;

	regu_cfg.flags |= REGU_BO_FLAG_ENABLE_REGU;
	if (stpmic1_bo_enable_cfg(regu_name, &regu_cfg.cfg)) {
		EMSG("PMIC regulator %s not supported", regu_name);
		panic();
	}

	if (fdt_getprop(fdt, regu_node, "regulator-pull-down", NULL)) {
		if (stpmic1_bo_pull_down_cfg(regu_name, &regu_cfg.cfg)) {
			DMSG("No pull down mode for regu %s", regu_name);
			panic();
		}
		regu_cfg.flags |= REGU_BO_FLAG_PULL_DOWN;
	}

	if (fdt_getprop(fdt, regu_node, "st,mask-reset", NULL)) {
		if (stpmic1_bo_mask_reset_cfg(regu_name, &regu_cfg.cfg)) {
			DMSG("No reset mode for regu %s", regu_name);
			panic();
		}
		regu_cfg.flags |= REGU_BO_FLAG_MASK_RESET;
	}

	cuint = fdt_getprop(fdt, regu_node,
			    "regulator-min-microvolt", NULL);
	if (cuint) {
		/* DT uses microvolts and driver awaits millivolts */
		mv = fdt32_to_cpu(*cuint) / 1000;

		if (stpmic1_bo_voltage_cfg(regu_name, mv, &regu_cfg.cfg))
			DMSG("Ignore regulator-min-microvolt for %s",
			     regu_name);
		else
			regu_cfg.flags |= REGU_BO_FLAG_SET_VOLTAGE;
	}

	/* Save config in the Boot On configuration list */
	regu_bo_count++;
	regu_bo_config = realloc(regu_bo_config,
				 regu_bo_count * sizeof(regu_cfg));
	if (!regu_bo_config)
		panic();

	regu_bo_config[regu_bo_count - 1] = regu_cfg;
}

void stm32mp_pmic_apply_boot_on_config(void)
{
	size_t i = 0;

	for (i = 0; i < regu_bo_count; i++) {
		struct regu_bo_config *regu_cfg = &regu_bo_config[i];

		if (regu_cfg->flags & REGU_BO_FLAG_SET_VOLTAGE)
			if (stpmic1_bo_voltage_unpg(&regu_cfg->cfg))
				panic();

		if (regu_cfg->flags & REGU_BO_FLAG_ENABLE_REGU)
			if (stpmic1_bo_enable_unpg(&regu_cfg->cfg))
				panic();

		if (regu_cfg->flags & REGU_BO_FLAG_PULL_DOWN)
			if (stpmic1_bo_pull_down_unpg(&regu_cfg->cfg))
				panic();

		if (regu_cfg->flags & REGU_BO_FLAG_MASK_RESET)
			if (stpmic1_bo_mask_reset_unpg(&regu_cfg->cfg))
				panic();
	}
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

static void dt_get_regu_low_power_config(void *fdt, const char *regu_name,
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

static void parse_regulator_fdt_nodes(void)
{
	int pmic_node = 0;
	int regulators_node = 0;
	int regu_node = 0;
	void *fdt = NULL;

	/* Expected called once */
	assert(!regu_bo_config && !regu_bo_count);

	fdt = get_embedded_dt();
	if (!fdt)
		panic();

	pmic_node = dt_get_pmic_node(fdt);
	if (pmic_node < 0)
		panic();

	regulators_node = fdt_subnode_offset(fdt, pmic_node, "regulators");
	if (regulators_node < 0)
		panic();

	fdt_for_each_subnode(regu_node, fdt, regulators_node) {
		int status = _fdt_get_status(fdt, regu_node);
		const char *regu_name = NULL;
		size_t n = 0;

		if (status == DT_STATUS_DISABLED)
			continue;

		regu_name = fdt_get_name(fdt, regu_node, NULL);

		assert(stpmic1_regulator_is_valid(regu_name));

		if (status & DT_STATUS_OK_NSEC)
			register_nsec_regu(regu_name);

		dt_get_regu_boot_on_config(fdt, regu_name, regu_node);

		for (n = 0; n < ARRAY_SIZE(regu_lp_state); n++)
			dt_get_regu_low_power_config(fdt, regu_name, regu_node,
						     regu_lp_state[n].name);
	}

	if (save_cpu_supply_name())
		DMSG("No CPU supply provided");
}

/*
 * Get PMIC and its I2C bus configuration from the device tree.
 * Return 0 on success, 1 if no PMIC node found and a negative value otherwise
 */
static int dt_pmic_i2c_config(struct dt_node_info *i2c_info,
			      struct stm32_pinctrl **pinctrl,
			      size_t *pinctrl_count,
			      struct stm32_i2c_init_s *init)
{
	int pmic_node = 0;
	int i2c_node = 0;
	void *fdt = NULL;
	const fdt32_t *cuint = NULL;

	fdt = get_embedded_dt();
	if (!fdt)
		return -FDT_ERR_NOTFOUND;

	pmic_node = dt_get_pmic_node(fdt);
	if (pmic_node < 0)
		return 1;

	cuint = fdt_getprop(fdt, pmic_node, "reg", NULL);
	if (!cuint)
		return -FDT_ERR_NOTFOUND;

	pmic_i2c_addr = fdt32_to_cpu(*cuint) << 1;
	if (pmic_i2c_addr > UINT16_MAX)
		return -FDT_ERR_BADVALUE;

	i2c_node = fdt_parent_offset(fdt, pmic_node);
	if (i2c_node < 0)
		return -FDT_ERR_NOTFOUND;

	_fdt_fill_device_info(fdt, i2c_info, i2c_node);
	if (!i2c_info->reg)
		return -FDT_ERR_NOTFOUND;

	return stm32_i2c_get_setup_from_fdt(fdt, i2c_node, init,
					    pinctrl, pinctrl_count);
}

/*
 * PMIC and resource initialization
 */

/* Return true if PMIC is available, false if not found, panics on errors */
static bool initialize_pmic_i2c(void)
{
	int ret = 0;
	struct dt_node_info i2c_info = { };
	struct i2c_handle_s *i2c = &i2c_handle;
	struct stm32_pinctrl *pinctrl = NULL;
	size_t pin_count = 0;
	struct stm32_i2c_init_s i2c_init = { };

	ret = dt_pmic_i2c_config(&i2c_info, &pinctrl, &pin_count, &i2c_init);
	if (ret < 0) {
		EMSG("I2C configuration failed %d", ret);
		panic();
	}
	if (ret)
		return false;

	/* Initialize PMIC I2C */
	i2c->base.pa = i2c_info.reg;
	i2c->base.va = (vaddr_t)phys_to_virt(i2c->base.pa, MEM_AREA_IO_SEC, 1);
	assert(i2c->base.va);
	i2c->dt_status = i2c_info.status;
	i2c->clock = i2c_info.clock;
	i2c->i2c_state = I2C_STATE_RESET;
	i2c_init.own_address1 = pmic_i2c_addr;
	i2c_init.analog_filter = true;
	i2c_init.digital_filter_coef = 0;

	i2c->pinctrl = pinctrl;
	i2c->pinctrl_count = pin_count;

	stm32mp_get_pmic();

	ret = stm32_i2c_init(i2c, &i2c_init);
	if (ret) {
		EMSG("I2C init 0x%" PRIxPA ": %d", i2c_info.reg, ret);
		panic();
	}

	if (!stm32_i2c_is_device_ready(i2c, pmic_i2c_addr,
				       PMIC_I2C_TRIALS,
				       PMIC_I2C_TIMEOUT_BUSY_MS))
		panic();

	stpmic1_bind_i2c(i2c, pmic_i2c_addr);

	stm32mp_put_pmic();

	return true;
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
		stm32_i2c_suspend(&i2c_handle);
	else
		stm32_i2c_resume(&i2c_handle);

	return TEE_SUCCESS;
}
DECLARE_KEEP_PAGER(pmic_pm);

/* stm32mp_get/put_pmic allows secure atomic sequences to use non secure PMIC */
void stm32mp_get_pmic(void)
{
	stm32_i2c_resume(&i2c_handle);
}

void stm32mp_put_pmic(void)
{
	stm32_i2c_suspend(&i2c_handle);
}

static void register_non_secure_pmic(void)
{
	size_t n = 0;

	/* Allow this function to be called when STPMIC1 not used */
	if (!i2c_handle.base.pa)
		return;

	for (n = 0; n < i2c_handle.pinctrl_count; n++)
		stm32mp_register_non_secure_gpio(i2c_handle.pinctrl[n].bank,
						 i2c_handle.pinctrl[n].pin);

	stm32mp_register_non_secure_periph_iomem(i2c_handle.base.pa);
}

static void register_secure_pmic(void)
{
	size_t n = 0;

	for (n = 0; n < i2c_handle.pinctrl_count; n++)
		stm32mp_register_secure_gpio(i2c_handle.pinctrl[n].bank,
					     i2c_handle.pinctrl[n].pin);

	stm32mp_register_secure_periph_iomem(i2c_handle.base.pa);
	register_pm_driver_cb(pmic_pm, NULL);
}

static TEE_Result initialize_pmic(void)
{
	unsigned long pmic_version = 0;

	if (!initialize_pmic_i2c()) {
		DMSG("No PMIC");
		register_non_secure_pmic();
		return TEE_SUCCESS;
	}

	stm32mp_get_pmic();

	if (stpmic1_get_version(&pmic_version))
		panic("Failed to access PMIC");

	DMSG("PMIC version = 0x%02lx", pmic_version);
	stpmic1_dump_regulators();

	if (dt_pmic_is_secure())
		register_secure_pmic();
	else
		register_non_secure_pmic();

	parse_regulator_fdt_nodes();

	stm32mp_put_pmic();

	return TEE_SUCCESS;
}
driver_init(initialize_pmic);
