// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2016-2020, STMicroelectronics - All Rights Reserved
 */

#include <assert.h>
#include <drivers/stpmic1.h>
#include <drivers/stpmic1_regulator.h>
#include <kernel/panic.h>
#include <platform_config.h>
#include <stdint.h>
#include <string.h>
#include <trace.h>
#include <util.h>

#define VOLTAGE_INDEX_INVALID		((unsigned int)~0)

struct regul_struct {
	const char *dt_node_name;
	const uint16_t *voltage_table;
	uint8_t voltage_table_size;
	uint8_t control_reg;
	uint8_t low_power_reg;
	uint8_t enable_pos;
	uint8_t pull_down_reg;
	uint8_t pull_down_pos;
	uint8_t mask_reset_reg;
	uint8_t mask_reset_pos;
};

static struct i2c_handle_s *pmic_i2c_handle;
static uint16_t pmic_i2c_addr;

/* Voltage tables in mV */
static const uint16_t buck1_voltage_table[] = {
	725,
	725,
	725,
	725,
	725,
	725,
	750,
	775,
	800,
	825,
	850,
	875,
	900,
	925,
	950,
	975,
	1000,
	1025,
	1050,
	1075,
	1100,
	1125,
	1150,
	1175,
	1200,
	1225,
	1250,
	1275,
	1300,
	1325,
	1350,
	1375,
	1400,
	1425,
	1450,
	1475,
	1500,
	1500,
	1500,
	1500,
	1500,
	1500,
	1500,
	1500,
	1500,
	1500,
	1500,
	1500,
	1500,
	1500,
	1500,
	1500,
	1500,
	1500,
	1500,
	1500,
	1500,
	1500,
	1500,
	1500,
	1500,
	1500,
	1500,
	1500,
};

static const uint16_t buck2_voltage_table[] = {
	1000,
	1000,
	1000,
	1000,
	1000,
	1000,
	1000,
	1000,
	1000,
	1000,
	1000,
	1000,
	1000,
	1000,
	1000,
	1000,
	1000,
	1000,
	1050,
	1050,
	1100,
	1100,
	1150,
	1150,
	1200,
	1200,
	1250,
	1250,
	1300,
	1300,
	1350,
	1350,
	1400,
	1400,
	1450,
	1450,
	1500,
};

static const uint16_t buck3_voltage_table[] = {
	1000,
	1000,
	1000,
	1000,
	1000,
	1000,
	1000,
	1000,
	1000,
	1000,
	1000,
	1000,
	1000,
	1000,
	1000,
	1000,
	1000,
	1000,
	1000,
	1000,
	1100,
	1100,
	1100,
	1100,
	1200,
	1200,
	1200,
	1200,
	1300,
	1300,
	1300,
	1300,
	1400,
	1400,
	1400,
	1400,
	1500,
	1600,
	1700,
	1800,
	1900,
	2000,
	2100,
	2200,
	2300,
	2400,
	2500,
	2600,
	2700,
	2800,
	2900,
	3000,
	3100,
	3200,
	3300,
	3400,
};

static const uint16_t buck4_voltage_table[] = {
	600,
	625,
	650,
	675,
	700,
	725,
	750,
	775,
	800,
	825,
	850,
	875,
	900,
	925,
	950,
	975,
	1000,
	1025,
	1050,
	1075,
	1100,
	1125,
	1150,
	1175,
	1200,
	1225,
	1250,
	1275,
	1300,
	1300,
	1350,
	1350,
	1400,
	1400,
	1450,
	1450,
	1500,
	1600,
	1700,
	1800,
	1900,
	2000,
	2100,
	2200,
	2300,
	2400,
	2500,
	2600,
	2700,
	2800,
	2900,
	3000,
	3100,
	3200,
	3300,
	3400,
	3500,
	3600,
	3700,
	3800,
	3900,
};

static const uint16_t ldo1_voltage_table[] = {
	1700,
	1700,
	1700,
	1700,
	1700,
	1700,
	1700,
	1700,
	1700,
	1800,
	1900,
	2000,
	2100,
	2200,
	2300,
	2400,
	2500,
	2600,
	2700,
	2800,
	2900,
	3000,
	3100,
	3200,
	3300,
};

static const uint16_t ldo2_voltage_table[] = {
	1700,
	1700,
	1700,
	1700,
	1700,
	1700,
	1700,
	1700,
	1700,
	1800,
	1900,
	2000,
	2100,
	2200,
	2300,
	2400,
	2500,
	2600,
	2700,
	2800,
	2900,
	3000,
	3100,
	3200,
	3300,
};

static const uint16_t ldo3_voltage_table[] = {
	1700,
	1700,
	1700,
	1700,
	1700,
	1700,
	1700,
	1700,
	1700,
	1800,
	1900,
	2000,
	2100,
	2200,
	2300,
	2400,
	2500,
	2600,
	2700,
	2800,
	2900,
	3000,
	3100,
	3200,
	3300,
	3300,
	3300,
	3300,
	3300,
	3300,
	3300,
	500,	/* VOUT2/2 (Sink/source mode) */
	0xFFFF, /* VREFDDR */
};

static const uint16_t ldo5_voltage_table[] = {
	1700,
	1700,
	1700,
	1700,
	1700,
	1700,
	1700,
	1700,
	1700,
	1800,
	1900,
	2000,
	2100,
	2200,
	2300,
	2400,
	2500,
	2600,
	2700,
	2800,
	2900,
	3000,
	3100,
	3200,
	3300,
	3400,
	3500,
	3600,
	3700,
	3800,
	3900,
};

static const uint16_t ldo6_voltage_table[] = {
	900,
	1000,
	1100,
	1200,
	1300,
	1400,
	1500,
	1600,
	1700,
	1800,
	1900,
	2000,
	2100,
	2200,
	2300,
	2400,
	2500,
	2600,
	2700,
	2800,
	2900,
	3000,
	3100,
	3200,
	3300,
};

static const uint16_t ldo4_voltage_table[] = {
	3300,
};

static const uint16_t vref_ddr_voltage_table[] = {
	3300,
};

static const uint16_t fixed_5v_voltage_table[] = {
	5000,
};

/* Table of Regulators in PMIC SoC */
static const struct regul_struct regulators_table[] = {
	{
		.dt_node_name	= "buck1",
		.voltage_table	= buck1_voltage_table,
		.voltage_table_size = ARRAY_SIZE(buck1_voltage_table),
		.control_reg	= BUCK1_CONTROL_REG,
		.low_power_reg	= BUCK1_PWRCTRL_REG,
		.enable_pos	= LDO_BUCK_ENABLE_POS,
		.pull_down_reg	= BUCK_PULL_DOWN_REG,
		.pull_down_pos	= BUCK1_PULL_DOWN_SHIFT,
		.mask_reset_reg = MASK_RESET_BUCK_REG,
		.mask_reset_pos = BUCK1_MASK_RESET_SHIFT,
	},
	{
		.dt_node_name	= "buck2",
		.voltage_table	= buck2_voltage_table,
		.voltage_table_size = ARRAY_SIZE(buck2_voltage_table),
		.control_reg	= BUCK2_CONTROL_REG,
		.low_power_reg	= BUCK2_PWRCTRL_REG,
		.enable_pos	= LDO_BUCK_ENABLE_POS,
		.pull_down_reg	= BUCK_PULL_DOWN_REG,
		.pull_down_pos	= BUCK2_PULL_DOWN_SHIFT,
		.mask_reset_reg = MASK_RESET_BUCK_REG,
		.mask_reset_pos = BUCK2_MASK_RESET_SHIFT,
	},
	{
		.dt_node_name	= "buck3",
		.voltage_table	= buck3_voltage_table,
		.voltage_table_size = ARRAY_SIZE(buck3_voltage_table),
		.control_reg	= BUCK3_CONTROL_REG,
		.low_power_reg	= BUCK3_PWRCTRL_REG,
		.enable_pos	= LDO_BUCK_ENABLE_POS,
		.pull_down_reg	= BUCK_PULL_DOWN_REG,
		.pull_down_pos	= BUCK3_PULL_DOWN_SHIFT,
		.mask_reset_reg = MASK_RESET_BUCK_REG,
		.mask_reset_pos = BUCK3_MASK_RESET_SHIFT,
	},
	{
		.dt_node_name	= "buck4",
		.voltage_table	= buck4_voltage_table,
		.voltage_table_size = ARRAY_SIZE(buck4_voltage_table),
		.control_reg	= BUCK4_CONTROL_REG,
		.low_power_reg	= BUCK4_PWRCTRL_REG,
		.enable_pos	= LDO_BUCK_ENABLE_POS,
		.pull_down_reg	= BUCK_PULL_DOWN_REG,
		.pull_down_pos	= BUCK4_PULL_DOWN_SHIFT,
		.mask_reset_reg = MASK_RESET_BUCK_REG,
		.mask_reset_pos = BUCK4_MASK_RESET_SHIFT,
	},
	{
		.dt_node_name	= "ldo1",
		.voltage_table	= ldo1_voltage_table,
		.voltage_table_size = ARRAY_SIZE(ldo1_voltage_table),
		.control_reg	= LDO1_CONTROL_REG,
		.low_power_reg	= LDO1_PWRCTRL_REG,
		.enable_pos	= LDO_BUCK_ENABLE_POS,
		.mask_reset_reg = MASK_RESET_LDO_REG,
		.mask_reset_pos = LDO1_MASK_RESET_SHIFT,
	},
	{
		.dt_node_name	= "ldo2",
		.voltage_table	= ldo2_voltage_table,
		.voltage_table_size = ARRAY_SIZE(ldo2_voltage_table),
		.control_reg	= LDO2_CONTROL_REG,
		.low_power_reg	= LDO2_PWRCTRL_REG,
		.enable_pos	= LDO_BUCK_ENABLE_POS,
		.mask_reset_reg = MASK_RESET_LDO_REG,
		.mask_reset_pos = LDO2_MASK_RESET_SHIFT,
	},
	{
		.dt_node_name	= "ldo3",
		.voltage_table	= ldo3_voltage_table,
		.voltage_table_size = ARRAY_SIZE(ldo3_voltage_table),
		.control_reg	= LDO3_CONTROL_REG,
		.low_power_reg	= LDO3_PWRCTRL_REG,
		.enable_pos	= LDO_BUCK_ENABLE_POS,
		.mask_reset_reg = MASK_RESET_LDO_REG,
		.mask_reset_pos = LDO3_MASK_RESET_SHIFT,
	},
	{
		.dt_node_name	= "ldo4",
		.voltage_table	= ldo4_voltage_table,
		.voltage_table_size = ARRAY_SIZE(ldo4_voltage_table),
		.control_reg	= LDO4_CONTROL_REG,
		.low_power_reg	= LDO4_PWRCTRL_REG,
		.enable_pos	= LDO_BUCK_ENABLE_POS,
		.mask_reset_reg = MASK_RESET_LDO_REG,
		.mask_reset_pos = LDO4_MASK_RESET_SHIFT,
	},
	{
		.dt_node_name	= "ldo5",
		.voltage_table	= ldo5_voltage_table,
		.voltage_table_size = ARRAY_SIZE(ldo5_voltage_table),
		.control_reg	= LDO5_CONTROL_REG,
		.low_power_reg	= LDO5_PWRCTRL_REG,
		.enable_pos	= LDO_BUCK_ENABLE_POS,
		.mask_reset_reg = MASK_RESET_LDO_REG,
		.mask_reset_pos = LDO5_MASK_RESET_SHIFT,
	},
	{
		.dt_node_name	= "ldo6",
		.voltage_table	= ldo6_voltage_table,
		.voltage_table_size = ARRAY_SIZE(ldo6_voltage_table),
		.control_reg	= LDO6_CONTROL_REG,
		.low_power_reg	= LDO6_PWRCTRL_REG,
		.enable_pos	= LDO_BUCK_ENABLE_POS,
		.mask_reset_reg = MASK_RESET_LDO_REG,
		.mask_reset_pos = LDO6_MASK_RESET_SHIFT,
	},
	{
		.dt_node_name	= "vref_ddr",
		.voltage_table	= vref_ddr_voltage_table,
		.voltage_table_size = ARRAY_SIZE(vref_ddr_voltage_table),
		.control_reg	= VREF_DDR_CONTROL_REG,
		.low_power_reg	= VREF_DDR_PWRCTRL_REG,
		.enable_pos	= LDO_BUCK_ENABLE_POS,
		.mask_reset_reg = MASK_RESET_LDO_REG,
		.mask_reset_pos = VREF_DDR_MASK_RESET_SHIFT,
	},
	{
		.dt_node_name = "boost",
		.voltage_table	= fixed_5v_voltage_table,
		.voltage_table_size = ARRAY_SIZE(fixed_5v_voltage_table),
		.control_reg	= USB_CONTROL_REG,
		.enable_pos	= BOOST_ENABLED_POS,
	},
	{
		.dt_node_name	= "pwr_sw1",
		.voltage_table	= fixed_5v_voltage_table,
		.voltage_table_size = ARRAY_SIZE(fixed_5v_voltage_table),
		.control_reg	= USB_CONTROL_REG,
		.enable_pos	= USBSW_OTG_SWITCH_ENABLED_POS,
	},
	{
		.dt_node_name	= "pwr_sw2",
		.voltage_table	= fixed_5v_voltage_table,
		.voltage_table_size = ARRAY_SIZE(fixed_5v_voltage_table),
		.control_reg	= USB_CONTROL_REG,
		.enable_pos	= SWIN_SWOUT_ENABLED_POS,
	},
};

static const struct regul_struct *get_regulator_data(const char *name)
{
	unsigned int i = 0;

	for (i = 0; i < ARRAY_SIZE(regulators_table); i++)
		if (strcmp(name, regulators_table[i].dt_node_name) == 0)
			return &regulators_table[i];

	DMSG("Regulator %s not found", name);
	return NULL;
}

bool stpmic1_regulator_is_valid(const char *name)
{
	return get_regulator_data(name);
}

void stpmic1_regulator_levels_mv(const char *name,
				 const uint16_t **levels,
				 size_t *levels_count)
{
	const struct regul_struct *regul = get_regulator_data(name);

	assert(regul);

	if (levels_count)
		*levels_count = regul->voltage_table_size;

	if (levels)
		*levels = regul->voltage_table;
}

static size_t voltage_to_index(const char *name, uint16_t millivolts)
{
	const struct regul_struct *regul = get_regulator_data(name);
	unsigned int i = 0;

	assert(regul->voltage_table);
	for (i = 0; i < regul->voltage_table_size; i++)
		if (regul->voltage_table[i] == millivolts)
			return i;

	return VOLTAGE_INDEX_INVALID;
}

int stpmic1_powerctrl_on(void)
{
	return stpmic1_register_update(MAIN_CONTROL_REG, PWRCTRL_PIN_VALID,
				       PWRCTRL_PIN_VALID);
}

int stpmic1_switch_off(void)
{
	return stpmic1_register_update(MAIN_CONTROL_REG, 1,
				       SOFTWARE_SWITCH_OFF_ENABLED);
}

int stpmic1_regulator_enable(const char *name)
{
	const struct regul_struct *regul = get_regulator_data(name);

	return stpmic1_register_update(regul->control_reg,
				       BIT(regul->enable_pos),
				       BIT(regul->enable_pos));
}

int stpmic1_regulator_disable(const char *name)
{
	const struct regul_struct *regul = get_regulator_data(name);

	return stpmic1_register_update(regul->control_reg, 0,
				       BIT(regul->enable_pos));
}

bool stpmic1_is_regulator_enabled(const char *name)
{
	const struct regul_struct *regul = get_regulator_data(name);
	uint8_t val = 0;

	if (stpmic1_register_read(regul->control_reg, &val))
		panic();

	return val & BIT(regul->enable_pos);
}

/* Voltage can be set for buck<N> or ldo<N> (except ldo4) regulators */
static uint8_t find_plat_mask(const char *name)
{
	if (!strncmp(name, "buck", 4))
		return BUCK_VOLTAGE_MASK;

	if (!strncmp(name, "ldo", 3) && strcmp(name, "ldo4"))
		return LDO_VOLTAGE_MASK;

	return 0;
}

int stpmic1_regulator_voltage_set(const char *name, uint16_t millivolts)
{
	size_t voltage_index = voltage_to_index(name, millivolts);
	const struct regul_struct *regul = get_regulator_data(name);
	uint8_t mask = 0;

	if (voltage_index == VOLTAGE_INDEX_INVALID)
		return -1;

	mask = find_plat_mask(name);
	if (!mask)
		return 0;

	return stpmic1_register_update(regul->control_reg,
				       voltage_index << LDO_BUCK_VOLTAGE_SHIFT,
				       mask);
}

int stpmic1_regulator_mask_reset_set(const char *name)
{
	const struct regul_struct *regul = get_regulator_data(name);

	if (regul->control_reg == USB_CONTROL_REG) {
		DMSG("No reset for USB control");
		return -1;
	}

	return stpmic1_register_update(regul->mask_reset_reg,
				       BIT(regul->mask_reset_pos),
				       LDO_BUCK_RESET_MASK <<
				       regul->mask_reset_pos);
}

int stpmic1_bo_enable_cfg(const char *name, struct stpmic1_bo_cfg *cfg)
{
	const struct regul_struct *regul = get_regulator_data(name);

	cfg->ctrl_reg = regul->control_reg;
	cfg->enable_pos = regul->enable_pos;

	return 0;
}

int stpmic1_bo_enable_unpg(struct stpmic1_bo_cfg *cfg)
{
	return stpmic1_register_update(cfg->ctrl_reg,
				       BIT(cfg->enable_pos),
				       BIT(cfg->enable_pos));
}

/* Returns 1 if no configuration are expected applied at runtime, 0 otherwise */
int stpmic1_bo_voltage_cfg(const char *name, uint16_t min_millivolt,
			   struct stpmic1_bo_cfg *cfg)
{
	size_t min_index = voltage_to_index(name, min_millivolt);
	const struct regul_struct *regul = get_regulator_data(name);
	uint8_t mask = 0;

	if (min_index == VOLTAGE_INDEX_INVALID)
		panic();

	mask = find_plat_mask(name);
	if (!mask)
		return 1;

	cfg->ctrl_reg = regul->control_reg;
	cfg->min_value = min_index << LDO_BUCK_VOLTAGE_SHIFT;
	cfg->mask = mask;

	return 0;
}

int stpmic1_bo_voltage_unpg(struct stpmic1_bo_cfg *cfg)
{
	uint8_t value = 0;

	assert(cfg->ctrl_reg);

	if (stpmic1_register_read(cfg->ctrl_reg, &value))
		return -1;

	if ((value & cfg->mask) >= cfg->min_value)
		return 0;

	return stpmic1_register_update(cfg->ctrl_reg, cfg->min_value,
				       cfg->mask);
}

int stpmic1_bo_pull_down_cfg(const char *name, struct stpmic1_bo_cfg *cfg)
{
	const struct regul_struct *regul = get_regulator_data(name);

	if (!regul->pull_down_reg) {
		DMSG("No pull down for regu %s", name);
		panic();
	}

	cfg->pd_reg = regul->pull_down_reg;
	cfg->pd_value = BIT(regul->pull_down_pos);
	cfg->pd_mask = LDO_BUCK_PULL_DOWN_MASK << regul->pull_down_pos;

	return 0;
}

int stpmic1_bo_pull_down_unpg(struct stpmic1_bo_cfg *cfg)
{
	assert(cfg->pd_reg);

	return stpmic1_register_update(cfg->pd_reg, cfg->pd_value,
				       cfg->pd_mask);
}

int stpmic1_bo_mask_reset_cfg(const char *name, struct stpmic1_bo_cfg *cfg)
{
	const struct regul_struct *regul = get_regulator_data(name);

	if (!regul->mask_reset_reg) {
		DMSG("No reset mask for regu %s", name);
		panic();
	}

	cfg->mrst_reg = regul->mask_reset_reg;
	cfg->mrst_value = BIT(regul->mask_reset_pos);
	cfg->mrst_mask = LDO_BUCK_RESET_MASK << regul->mask_reset_pos;

	return 0;
}

int stpmic1_bo_mask_reset_unpg(struct stpmic1_bo_cfg *cfg)
{
	assert(cfg->mrst_reg);

	return stpmic1_register_update(cfg->mrst_reg, cfg->mrst_value,
				       cfg->mrst_mask);
}

int stpmic1_regulator_voltage_get(const char *name)
{
	const struct regul_struct *regul = get_regulator_data(name);
	uint8_t value = 0;
	uint8_t mask = 0;

	mask = find_plat_mask(name);
	if (!mask)
		return 0;

	if (stpmic1_register_read(regul->control_reg, &value))
		return -1;

	value = (value & mask) >> LDO_BUCK_VOLTAGE_SHIFT;

	if (value > regul->voltage_table_size)
		return -1;

	return regul->voltage_table[value];
}

int stpmic1_lp_copy_reg(const char *name)
{
	const struct regul_struct *regul = get_regulator_data(name);
	uint8_t val = 0;
	int status = 0;

	if (!regul->low_power_reg)
		return -1;

	status = stpmic1_register_read(regul->control_reg, &val);
	if (status)
		return status;

	return stpmic1_register_write(regul->low_power_reg, val);
}

bool stpmic1_regu_has_lp_cfg(const char *name)
{
	return get_regulator_data(name)->low_power_reg;
}

int stpmic1_lp_cfg(const char *name, struct stpmic1_lp_cfg *cfg)
{
	const struct regul_struct *regul = get_regulator_data(name);

	if (!regul->low_power_reg)
		return -1;

	cfg->ctrl_reg = regul->control_reg;
	cfg->lp_reg = regul->low_power_reg;

	return 0;
}

int stpmic1_lp_load_unpg(struct stpmic1_lp_cfg *cfg)
{
	uint8_t val = 0;
	int status = 0;

	assert(cfg->lp_reg);

	status = stpmic1_register_read(cfg->ctrl_reg, &val);
	if (!status)
		status = stpmic1_register_write(cfg->lp_reg, val);

	return status;
}

int stpmic1_lp_reg_on_off(const char *name, uint8_t enable)
{
	const struct regul_struct *regul = get_regulator_data(name);

	if (!regul->low_power_reg)
		return -1;

	return stpmic1_register_update(regul->low_power_reg, enable,
				       LDO_BUCK_ENABLE_MASK);
}

int stpmic1_lp_on_off_unpg(struct stpmic1_lp_cfg *cfg, int enable)
{
	assert(cfg->lp_reg && (enable == 0 || enable == 1));

	return stpmic1_register_update(cfg->lp_reg, enable,
				       LDO_BUCK_ENABLE_MASK);
}

int stpmic1_lp_set_mode(const char *name, uint8_t hplp)
{
	const struct regul_struct *regul = get_regulator_data(name);

	assert(regul->low_power_reg && (hplp == 0 || hplp == 1));

	return stpmic1_register_update(regul->low_power_reg,
				       hplp << LDO_BUCK_HPLP_POS,
				       BIT(LDO_BUCK_HPLP_POS));
}

int stpmic1_lp_mode_unpg(struct stpmic1_lp_cfg *cfg, unsigned int mode)
{
	assert(cfg->lp_reg && (mode == 0 || mode == 1));
	return stpmic1_register_update(cfg->lp_reg,
				       mode << LDO_BUCK_HPLP_POS,
				       BIT(LDO_BUCK_HPLP_POS));
}

int stpmic1_lp_set_voltage(const char *name, uint16_t millivolts)
{
	size_t voltage_index = voltage_to_index(name, millivolts);
	const struct regul_struct *regul = get_regulator_data(name);
	uint8_t mask = 0;

	assert(voltage_index != VOLTAGE_INDEX_INVALID);

	mask = find_plat_mask(name);
	if (!mask)
		return 0;

	return stpmic1_register_update(regul->low_power_reg, voltage_index << 2,
				       mask);
}

/* Returns 1 if no configuration are expected applied at runtime, 0 otherwise */
int stpmic1_lp_voltage_cfg(const char *name, uint16_t millivolts,
			   struct stpmic1_lp_cfg *cfg)

{
	size_t voltage_index = voltage_to_index(name, millivolts);
	uint8_t mask = 0;

	mask = find_plat_mask(name);
	if (!mask)
		return 1;

	assert(voltage_index != VOLTAGE_INDEX_INVALID &&
	       cfg->lp_reg == get_regulator_data(name)->low_power_reg);

	cfg->value = voltage_index << 2;
	cfg->mask = mask;

	return 0;
}

int stpmic1_lp_voltage_unpg(struct stpmic1_lp_cfg *cfg)
{
	assert(cfg->lp_reg);

	return stpmic1_register_update(cfg->lp_reg, cfg->value,	cfg->mask);
}

int stpmic1_register_read(uint8_t register_id,  uint8_t *value)
{
	struct i2c_handle_s *i2c = pmic_i2c_handle;

	return stm32_i2c_read_write_membyte(i2c, pmic_i2c_addr,
					    register_id, value,
					    false /* !write */);
}

int stpmic1_register_write(uint8_t register_id, uint8_t value)
{
	struct i2c_handle_s *i2c = pmic_i2c_handle;
	uint8_t val = value;

	return stm32_i2c_read_write_membyte(i2c, pmic_i2c_addr,
					    register_id, &val,
					    true /* write */);
}

int stpmic1_register_update(uint8_t register_id, uint8_t value, uint8_t mask)
{
	int status = 0;
	uint8_t val = 0;

	status = stpmic1_register_read(register_id, &val);
	if (status)
		return status;

	val = (val & ~mask) | (value & mask);

	return stpmic1_register_write(register_id, val);
}

void stpmic1_bind_i2c(struct i2c_handle_s *i2c_handle, uint16_t i2c_addr)
{
	pmic_i2c_handle = i2c_handle;
	pmic_i2c_addr = i2c_addr;
}

void stpmic1_dump_regulators(void)
{
	size_t i = 0;
	char __maybe_unused const *name = NULL;

	for (i = 0; i < ARRAY_SIZE(regulators_table); i++) {
		if (!regulators_table[i].control_reg)
			continue;

		name = regulators_table[i].dt_node_name;
		DMSG("PMIC regul %s: %sable, %dmV",
		     name, stpmic1_is_regulator_enabled(name) ? "en" : "dis",
		     stpmic1_regulator_voltage_get(name));
	}
}

int stpmic1_get_version(unsigned long *version)
{
	uint8_t read_val = 0;

	if (stpmic1_register_read(VERSION_STATUS_REG, &read_val))
		return -1;

	*version = read_val;
	return 0;
}
