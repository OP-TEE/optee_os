// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021-2023, STMicroelectronics
 */

#include <assert.h>
#include <compiler.h>
#include <drivers/regulator.h>
#include <drivers/stm32mp1_pwr.h>
#include <drivers/stm32mp1_syscfg.h>
#include <drivers/stm32mp13_regulator_iod.h>
#include <initcall.h>
#include <io.h>
#include <kernel/boot.h>
#include <kernel/dt.h>
#include <kernel/panic.h>
#include <kernel/pm.h>
#include <libfdt.h>
#include <stdint.h>
#include <stdio.h>
#include <stm32_util.h>
#include <trace.h>

#define TIMEOUT_US_10MS		U(10000)

#define IO_VOLTAGE_THRESHOLD_UV	2700000

/*
 * struct iod_regul - IO domain regulator instance
 *
 * @enable_reg: PWR register offset for the IO domain
 * @enable_mask: Domain enable register bit mask in PWR register
 * @ready_mask: Domain ready bit mask in PWR register
 * @valid_mask: Domain valid bit mask in PWR register
 * @hslv_id: ID of the related HSLV domain
 * @io_comp_id: ID of the related IO compensation domain
 * @suspend_state: True if regulator is enabled before suspend, false otherwise
 * @suspend_level_uv: Voltage level before suspend, in microvolts
 */
struct iod_regul {
	uint32_t enable_reg;
	uint32_t enable_mask;
	uint32_t ready_mask;
	uint32_t valid_mask;
	enum stm32mp13_hslv_id hslv_id;
	enum stm32mp13_vddsd_comp_id io_comp_id;
	bool suspend_state;
	int suspend_level_uv;
};

static struct iod_regul iod_regulator_priv[IOD_REGU_COUNT] = {
	 [IOD_SDMMC1] = {
		.enable_reg = PWR_CR3_OFF,
		.enable_mask = PWR_CR3_VDDSD1EN,
		.ready_mask = PWR_CR3_VDDSD1RDY,
		.valid_mask = PWR_CR3_VDDSD1VALID,
		.hslv_id = SYSCFG_HSLV_IDX_SDMMC1,
		.io_comp_id = SYSCFG_IO_COMP_IDX_SD1,
	 },
	 [IOD_SDMMC2] = {
		.enable_reg = PWR_CR3_OFF,
		.enable_mask = PWR_CR3_VDDSD2EN,
		.ready_mask = PWR_CR3_VDDSD2RDY,
		.valid_mask = PWR_CR3_VDDSD2VALID,
		.hslv_id = SYSCFG_HSLV_IDX_SDMMC2,
		.io_comp_id = SYSCFG_IO_COMP_IDX_SD2,
	 },
};

static struct regulator *iod_regulator[IOD_REGU_COUNT];

struct regulator *stm32mp1_get_iod_regulator(enum iod_regulator_id index)
{
	assert(index >= IOD_SDMMC1 && index < IOD_REGU_COUNT);

	return iod_regulator[index];
}

static TEE_Result iod_set_state(struct regulator *regu, bool enable)
{
	struct iod_regul *iod = regu->priv;
	uintptr_t pwr_reg = stm32_pwr_base() + iod->enable_reg;

	FMSG("%s: set state %u", regulator_name(regu), enable);

	if (enable) {
		uint32_t value = 0;

		io_setbits32(pwr_reg, iod->enable_mask);

		if (IO_READ32_POLL_TIMEOUT(pwr_reg, value,
					   value & iod->ready_mask,
					   0, TIMEOUT_US_10MS))
			return TEE_ERROR_GENERIC;

		io_setbits32(pwr_reg, iod->valid_mask);
		io_clrbits32(pwr_reg, iod->enable_mask);

		stm32mp_set_vddsd_comp_state(iod->io_comp_id, true);
	} else {
		stm32mp_set_vddsd_comp_state(iod->io_comp_id, false);

		io_clrbits32(pwr_reg, iod->enable_mask | iod->valid_mask);
	}

	return TEE_SUCCESS;
}

static TEE_Result iod_get_state(struct regulator *regu, bool *enabled)
{
	struct iod_regul *iod = regu->priv;
	uintptr_t pwr_reg = stm32_pwr_base() + iod->enable_reg;

	*enabled = io_read32(pwr_reg) & (iod->enable_mask | iod->valid_mask);

	return TEE_SUCCESS;
}

static TEE_Result iod_get_voltage(struct regulator *regu, int *level_uv)
{
	*level_uv = regulator_get_voltage(regu->supply);

	return TEE_SUCCESS;
}

static TEE_Result iod_set_voltage(struct regulator *regu, int level_uv)
{
	struct iod_regul *iod = regu->priv;
	TEE_Result res = TEE_ERROR_GENERIC;
	bool iod_enabled = false;

	FMSG("%s: set voltage level to %duV", regulator_name(regu), level_uv);

	res = iod_get_state(regu, &iod_enabled);
	if (res)
		return res;

	/* Isolate IOs and disable IOs compensation when changing voltage */
	if (iod_enabled) {
		res = iod_set_state(regu, false);
		if (res)
			return res;
	}

	/*
	 * Set IO to low speed.
	 * Setting high voltage with IOs in high speed mode may damage the IOs.
	 */
	stm32mp_set_hslv_state(iod->hslv_id, false);

	/* Forward set voltage request to the power supply */
	res = regulator_set_voltage(regu->supply, level_uv);
	if (res) {
		EMSG("regulator %s set voltage failed: %#"PRIx32,
		     regulator_name(regu), res);

		/* Ensure IO domain consistency for current voltage level */
		level_uv = regulator_get_voltage(regu->supply);
	}

	if (level_uv <= IO_VOLTAGE_THRESHOLD_UV)
		stm32mp_set_hslv_state(iod->hslv_id, true);

	if (iod_enabled) {
		TEE_Result res2 = TEE_ERROR_GENERIC;

		res2 = iod_set_state(regu, true);
		if (res2)
			return res2;
	}

	return res;
}

static TEE_Result iod_list_voltages(struct regulator *regu,
				    struct regulator_voltages_desc **desc,
				    const int **levels)
{
	/* Return supply voltage list */
	return regulator_supported_voltages(regu->supply, desc, levels);
}

/*
 * To protect the IOs, we disable High Speed Low Voltage mode before
 * entering suspend state and restore the configuration when resuming.
 */
static TEE_Result iod_pm(enum pm_op op, unsigned int pm_hint __unused,
			 const struct pm_callback_handle *hdl)
{
	struct regulator *regu = hdl->handle;
	struct iod_regul *iod = regu->priv;
	TEE_Result res = TEE_ERROR_GENERIC;

	assert(op == PM_OP_SUSPEND || op == PM_OP_RESUME);

	if (op == PM_OP_SUSPEND) {
		FMSG("%s: suspend", regulator_name(regu));

		res = iod_get_state(regu, &iod->suspend_state);
		if (res)
			return res;

		res = iod_get_voltage(regu, &iod->suspend_level_uv);
		if (res)
			return res;

		stm32mp_set_hslv_state(iod->hslv_id, false);
	} else {
		FMSG("%s: resume", regulator_name(regu));

		res = iod_set_voltage(regu, iod->suspend_level_uv);
		if (res)
			return res;

		res = iod_set_state(regu, iod->suspend_state);
		if (res)
			return res;
	}

	return TEE_SUCCESS;
}

static TEE_Result iod_supplied_init(struct regulator *regu,
				    const void *fdt __unused, int node __unused)
{
	struct iod_regul *iod = regu->priv;
	int index = iod - iod_regulator_priv;

	assert(index >= 0 && index < IOD_REGU_COUNT);

	if (regulator_get_voltage(regu) < IO_VOLTAGE_THRESHOLD_UV)
		stm32mp_set_hslv_state(iod->hslv_id, true);

	/* Save regulator reference */
	iod_regulator[index] = regu;

	register_pm_driver_cb(iod_pm, regu, "iod-regulator");

	FMSG("IOD regulator %s intiialized", regulator_name(regu));

	return TEE_SUCCESS;
}

static const struct regulator_ops iod_ops = {
	.set_state = iod_set_state,
	.get_state = iod_get_state,
	.set_voltage = iod_set_voltage,
	.get_voltage = iod_get_voltage,
	.supported_voltages = iod_list_voltages,
	.supplied_init = iod_supplied_init,
};

#define DEFINE_REG(_id, _name, _supply_name) { \
	.name = (_name), \
	.ops = &iod_ops, \
	.priv = iod_regulator_priv + (_id), \
	.supply_name = (_supply_name), \
}

static struct regu_dt_desc iod_regul_desc[IOD_REGU_COUNT] = {
	[IOD_SDMMC1] = DEFINE_REG(IOD_SDMMC1, "sdmmc1_io", "vddsd1"),
	[IOD_SDMMC2] = DEFINE_REG(IOD_SDMMC2, "sdmmc2_io", "vddsd2"),
};

static TEE_Result iod_regulator_probe(const void *fdt, int node,
				      const void *compat_data __unused)
{
	const char *node_name = NULL;
	size_t i = 0;

	node_name = fdt_get_name(fdt, node, NULL);

	FMSG("iod probe node '%s'", node_name);

	/* Look up matching regulator name defined in SoC DTSI file */
	for (i = 0; i < IOD_REGU_COUNT; i++)
		if (!strcmp(iod_regul_desc[i].name, node_name))
			break;

	if (i == IOD_REGU_COUNT) {
		EMSG("Unexpected IO domain node name '%s'", node_name);
		return TEE_ERROR_GENERIC;
	}

	return regulator_dt_register(fdt, node, node, iod_regul_desc + i);
}

static const struct dt_device_match iod_regulator_match_table[] = {
	{ .compatible = "st,stm32mp13-iod" },
	{ }
};

DEFINE_DT_DRIVER(stm32mp13_regulator_iod_dt_driver) = {
	.name = "stm32mp13-iod-regulator",
	.match_table = iod_regulator_match_table,
	.probe = iod_regulator_probe,
};
