// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, STMicroelectronics
 */

#include <assert.h>
#include <compiler.h>
#include <drivers/regulator.h>
#include <drivers/stm32mp2_pwr.h>
#include <drivers/stm32_rif.h>
#include <dt-bindings/firewall/stm32mp25-rifsc.h>
#include <io.h>
#include <kernel/delay.h>
#include <kernel/dt.h>
#include <kernel/dt_driver.h>
#include <kernel/panic.h>
#include <kernel/pm.h>
#include <kernel/thread.h>
#include <libfdt.h>
#include <stm32_sysconf.h>
#include <stm32mp_pm.h>
#include <trace.h>

#define PWR_CR1			U(0x00)
#define PWR_CR7			U(0x18)
#define PWR_CR8			U(0x1c)
#define PWR_CR9			U(0x20)
#define PWR_CR12		U(0x2c)

#define PWR_CR1_VDDIO3VMEN	BIT(0)
#define PWR_CR1_VDDIO4VMEN	BIT(1)
#define PWR_CR1_USB33VMEN	BIT(2)
#define PWR_CR1_UCPDVMEN	BIT(3)
#define PWR_CR1_AVMEN		BIT(4)
#define PWR_CR1_VDDIO3SV	BIT(8)
#define PWR_CR1_VDDIO4SV	BIT(9)
#define PWR_CR1_UCPDSV		BIT(11)
#define PWR_CR1_ASV		BIT(12)
#define PWR_CR1_VDDIO3RDY	BIT(16)
#define PWR_CR1_VDDIO4RDY	BIT(17)
#define PWR_CR1_USB33RDY	BIT(18)
#define PWR_CR1_UCPDRDY		BIT(19)
#define PWR_CR1_ARDY		BIT(20)
#define PWR_CR1_VDDIOVRSEL	BIT(24)
#define PWR_CR1_VDDIO3VRSEL	BIT(25)
#define PWR_CR1_VDDIO4VRSEL	BIT(26)
#define PWR_CR1_GPVMO		BIT(31)

#define PWR_CR7_VDDIO2VMEN	BIT(0)
#define PWR_CR7_VDDIO2SV	BIT(8)
#define PWR_CR7_VDDIO2RDY	BIT(16)
#define PWR_CR7_VDDIO2VRSEL	BIT(24)
#define PWR_CR7_VDDIO2VRSTBY	BIT(25)

#define PWR_CR8_VDDIO1VMEN	BIT(0)
#define PWR_CR8_VDDIO1SV	BIT(8)
#define PWR_CR8_VDDIO1RDY	BIT(16)
#define PWR_CR8_VDDIO1VRSEL	BIT(24)
#define PWR_CR8_VDDIO1VRSTBY	BIT(25)

#define PWR_CR9_BKPRBSEN	BIT(0)
#define PWR_CR9_LPR1BSEN	BIT(4)

#define PWR_CR12_GPUVMEN	BIT(0)
#define PWR_CR12_GPULVTEN	BIT(1)
#define PWR_CR12_GPUSV		BIT(8)
#define PWR_CR12_VDDGPURDY	BIT(16)

#define TIMEOUT_US_10MS		U(10000)
#define DELAY_100US		U(100)

#define IO_VOLTAGE_THRESHOLD_UV	2700000

#define IOCOMP_CODE_MAX		U(2)

/*
 * struct pwr_regul - PWR regulator instance
 *
 * @enable_reg: Offset of regulator enable register in PWR IOMEM interface
 * @enable_mask: Bitmask of regulator enable bit in PWR IOMEM register
 * @ready_mask: Bitmask of regulator enable status bit in PWR IOMEM register
 * @valid_mask: Bitmask of regulator valid state bit in PWR IOMEM register
 * @vrsel_mask: Bitmask of reference voltage switch in PWR IOMEM register
 * @comp_idx: Index on compensation cell in SYSCFG IO domain
 * @suspend_uv: Supply voltage level at PM suspend time to be restored at resume
 * @suspend_state: Supply state at PM suspend time to be restored at resume
 * @is_an_iod: True if regulator relates to an IO domain, else false
 * @keep_monitor_on: Never turn of the voltage monitor
 * @has_clamp: Handle clamp workaround
 */
struct pwr_regul {
	uint32_t enable_reg;
	uint32_t enable_mask;
	uint32_t ready_mask;
	uint32_t valid_mask;
	uint32_t vrsel_mask;
	enum syscfg_io_ids comp_idx;
	int suspend_uv;
	bool suspend_state;
	/*
	 * An IO domain is a power switch, meaning that
	 * its output voltage follows its power supply voltage
	 * and the IOs have IO compensation cell
	 */
	bool is_an_iod;

	bool keep_monitor_on;
	/*
	 * Has_clamp: The VDDA regulator implements a workaround
	 * to reduce power consumption that occurs when the regulator
	 * is disabled but its supply is still present.
	 * In this case, activating the monitor also activates a clamping
	 * mechanism.
	 */
	bool has_clamp;
	/*
	 * rifsc_filtering_id is used to disable filtering when
	 * accessing to the register
	 */
	uint8_t rifsc_filtering_id;
	/* IO compensation codes */
	bool iocomp_fixed;
	uint32_t iocomp_code[IOCOMP_CODE_MAX];
};

static TEE_Result stm32mp2_pwr_regul_enable_regul(struct pwr_regul *pwr_regu)
{
	uintptr_t reg = stm32_pwr_base() + pwr_regu->enable_reg;
	uint64_t to = 0;
	bool cid_enabled = false;

	if (!pwr_regu->enable_mask)
		return TEE_SUCCESS;

	if (pwr_regu->rifsc_filtering_id)
		cid_enabled =
			stm32_rifsc_cid_is_enabled
				(pwr_regu->rifsc_filtering_id);

	if (cid_enabled)
		stm32_rifsc_cid_disable(pwr_regu->rifsc_filtering_id);

	io_setbits32(reg, pwr_regu->enable_mask);

	/* Wait for vddgpu to enable as stated in the reference manual */
	if (pwr_regu->keep_monitor_on)
		udelay(DELAY_100US);

	to = timeout_init_us(TIMEOUT_US_10MS);
	while (!timeout_elapsed(to))
		if (io_read32(reg) & pwr_regu->ready_mask)
			break;

	if (!(io_read32(reg) & pwr_regu->ready_mask)) {
		io_clrbits32(reg, pwr_regu->enable_mask);
		if (cid_enabled)
			stm32_rifsc_cid_enable(pwr_regu->rifsc_filtering_id);
		return TEE_ERROR_GENERIC;
	}

	io_setbits32(reg, pwr_regu->valid_mask);

	/*
	 * Disable voltage monitor to reduce consumption.
	 * Not for GPU or for clamp workaround
	 */
	if (!(pwr_regu->keep_monitor_on || pwr_regu->has_clamp))
		io_clrbits32(reg, pwr_regu->enable_mask);

	if (cid_enabled)
		stm32_rifsc_cid_enable(pwr_regu->rifsc_filtering_id);

	return TEE_SUCCESS;
}

static void stm32mp2_pwr_regul_disable_regul(struct pwr_regul *pwr_regu)
{
	uintptr_t reg = stm32_pwr_base() + pwr_regu->enable_reg;
	bool cid_enabled = false;

	if (pwr_regu->enable_mask) {
		if (pwr_regu->rifsc_filtering_id)
			cid_enabled =
				stm32_rifsc_cid_is_enabled
					(pwr_regu->rifsc_filtering_id);

		if (cid_enabled)
			stm32_rifsc_cid_disable(pwr_regu->rifsc_filtering_id);

		/* Make sure the previous operations are visible */
		dsb();

		io_clrbits32(reg, pwr_regu->valid_mask);

		if (pwr_regu->has_clamp)
			io_setbits32(reg, pwr_regu->enable_mask);
		else
			io_clrbits32(reg, pwr_regu->enable_mask);
	}

	if (cid_enabled)
		stm32_rifsc_cid_enable(pwr_regu->rifsc_filtering_id);
}

static TEE_Result stm32mp2_pwr_regul_set_state(struct regulator *regulator,
					       bool enable)
{
	struct pwr_regul *pwr_regu = regulator->priv;
	size_t iod_idx = pwr_regu->comp_idx;
	TEE_Result res = TEE_ERROR_GENERIC;

	FMSG("%s: set state %u", regulator_name(regulator), enable);

	if (enable) {
		res = stm32mp2_pwr_regul_enable_regul(pwr_regu);
		if (res)
			return res;

		if (pwr_regu->is_an_iod && !pwr_regu->iocomp_fixed) {
			res = stm32mp25_syscfg_enable_iocomp(iod_idx);
			if (res) {
				stm32mp2_pwr_regul_disable_regul(pwr_regu);
				return res;
			}
		}
	} else {
		if (pwr_regu->is_an_iod && !pwr_regu->iocomp_fixed) {
			res = stm32mp25_syscfg_disable_iocomp(iod_idx);
			if (res)
				return res;
		}

		stm32mp2_pwr_regul_disable_regul(pwr_regu);
	}

	return TEE_SUCCESS;
}

static TEE_Result stm32mp2_pwr_regul_get_state(struct regulator *regulator,
					       bool *enabled)
{
	struct pwr_regul *pwr_regu = regulator->priv;
	uintptr_t pwr_reg = stm32_pwr_base() + pwr_regu->enable_reg;

	FMSG("%s: get state", regulator_name(regulator));

	if (pwr_regu->enable_mask)
		*enabled = io_read32(pwr_reg) & pwr_regu->valid_mask;
	else
		*enabled = true;

	return TEE_SUCCESS;
}

static TEE_Result stm32mp2_pwr_regul_set_low_volt(struct regulator *regulator,
						  bool state)
{
	struct pwr_regul *pwr_regu = regulator->priv;
	uintptr_t reg = stm32_pwr_base() + pwr_regu->enable_reg;

	if (pwr_regu->vrsel_mask) {
		FMSG("%s: set speed=%u", regulator_name(regulator), state);

		if (state) {
			io_setbits32(reg, pwr_regu->vrsel_mask);

			if (!(io_read32(reg) & pwr_regu->vrsel_mask)) {
				EMSG("%s: set VRSEL failed",
				     regulator_name(regulator));
				panic();
			}
		} else {
			io_clrbits32(reg, pwr_regu->vrsel_mask);
		}
	}

	return TEE_SUCCESS;
}

static TEE_Result stm32mp2_pwr_regul_get_voltage(struct regulator *regulator,
						 int *level_uv)
{
	FMSG("%s: get volt", regulator_name(regulator));

	*level_uv = regulator_get_voltage(regulator->supply);

	return TEE_SUCCESS;
}

static TEE_Result stm32mp2_pwr_regul_set_voltage(struct regulator *regulator,
						 int level_uv)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	TEE_Result result = TEE_ERROR_GENERIC;
	bool is_enabled = false;

	FMSG("%s: set volt to %d uV", regulator_name(regulator), level_uv);

	res = stm32mp2_pwr_regul_get_state(regulator, &is_enabled);
	if (res)
		return res;

	/* Isolate IOs and disable IOs compensation */
	if (is_enabled) {
		res = stm32mp2_pwr_regul_set_state(regulator, false);
		if (res)
			return res;
	}

	/* Set IO to high voltage */
	if (level_uv >= IO_VOLTAGE_THRESHOLD_UV) {
		res = stm32mp2_pwr_regul_set_low_volt(regulator, false);
		if (res)
			return res;
	}

	/* Forward set voltage request to the power supply */
	result = regulator_set_voltage(regulator->supply, level_uv);
	if (result) {
		EMSG("regulator %s set voltage failed: %"PRIx32,
		     regulator_name(regulator), result);
		/* Continue to restore IOs setting for current voltage */
		level_uv = regulator_get_voltage(regulator->supply);
	}

	if (level_uv < IO_VOLTAGE_THRESHOLD_UV) {
		res = stm32mp2_pwr_regul_set_low_volt(regulator, true);
		if (res)
			return res;
	}

	/* De-isolate IOs and enable IOs compensation */
	if (is_enabled) {
		res = stm32mp2_pwr_regul_set_state(regulator, true);
		if (res)
			return res;
	}

	/* Make sure the regulator is updated before returning to caller */
	dsb();

	return result;
}

static TEE_Result
stm32mp2_pwr_regul_supported_voltages(struct regulator *regulator,
				      struct regulator_voltages_desc **desc,
				      const int **levels)
{
	/* Return parent voltage list */
	return regulator_supported_voltages(regulator->supply, desc, levels);
}

/*
 * suspend - resume operations:
 * To protect the IOs, disable low voltage mode before entering suspend
 * resume restore the previous configuration.
 */
static TEE_Result
stm32mp2_pwr_regul_regu_pm(enum pm_op op, unsigned int pm_hint,
			   const struct pm_callback_handle *hdl)
{
	struct regulator *regulator = hdl->handle;
	struct pwr_regul *pwr_regu = regulator->priv;
	TEE_Result res = TEE_ERROR_GENERIC;
	unsigned int pwrlvl = PM_HINT_PLATFORM_STATE(pm_hint);

	assert(op == PM_OP_SUSPEND || op == PM_OP_RESUME);

	/* Skip as regulators don't change for Stop1 modes */
	if (pwrlvl < PM_D1_LPLV_LEVEL)
		return TEE_SUCCESS;

	if (op == PM_OP_SUSPEND) {
		FMSG("%s: suspend", regulator_name(regulator));

		res = stm32mp2_pwr_regul_get_state(regulator,
						   &pwr_regu->suspend_state);
		if (res)
			return res;

		if (pwr_regu->is_an_iod) {
			size_t iod_idx = pwr_regu->comp_idx;

			res = stm32mp2_pwr_regul_get_voltage
				(regulator, &pwr_regu->suspend_uv);
			if (res)
				return res;

			/* Disable low voltage mode to protect IOs */
			res = stm32mp2_pwr_regul_set_low_volt(regulator, false);
			if (res)
				return res;

			if (!pwr_regu->iocomp_fixed) {
				res = stm32mp25_syscfg_disable_iocomp(iod_idx);
				if (res)
					return res;
			}
		}
	} else {
		FMSG("%s: resume", regulator_name(regulator));

		if (pwr_regu->is_an_iod) {
			if (pwr_regu->iocomp_fixed) {
				stm32mp25_syscfg_fixed_iocomp
					(pwr_regu->comp_idx,
					 pwr_regu->iocomp_code[0],
					 pwr_regu->iocomp_code[1]);
			}

			res = stm32mp2_pwr_regul_set_voltage
				(regulator, pwr_regu->suspend_uv);
			if (res)
				return res;
		}

		res = stm32mp2_pwr_regul_set_state(regulator,
						   pwr_regu->suspend_state);
		if (res)
			return res;
	}

	return TEE_SUCCESS;
}

static TEE_Result
stm32mp2_pwr_regul_supplied_init(struct regulator *regulator,
				 const void *fdt __unused, int node __unused)
{
	struct pwr_regul *pwr_regu = regulator->priv;

	FMSG("%s supplied initialization", regulator_name(regulator));

	if (pwr_regu->is_an_iod) {
		TEE_Result res = TEE_ERROR_GENERIC;
		int level_uv = 0;

		if (pwr_regu->iocomp_fixed) {
			stm32mp25_syscfg_fixed_iocomp(pwr_regu->comp_idx,
						      pwr_regu->iocomp_code[0],
						      pwr_regu->iocomp_code[1]);
		}

		res = stm32mp2_pwr_regul_get_voltage(regulator, &level_uv);
		if (res)
			return res;

		if (level_uv < IO_VOLTAGE_THRESHOLD_UV) {
			res = stm32mp2_pwr_regul_set_low_volt(regulator, true);
			if (res)
				return res;
		}
	}

	if (pwr_regu->has_clamp) {
		uintptr_t reg = stm32_pwr_base() + pwr_regu->enable_reg;

		io_setbits32(reg, pwr_regu->enable_mask);
	}

	register_pm_driver_cb(stm32mp2_pwr_regul_regu_pm, regulator,
			      "stm32mp2-pwr-regu");

	return TEE_SUCCESS;
}

static const struct regulator_ops stm32mp2_pwr_regul_ops = {
	.set_state = stm32mp2_pwr_regul_set_state,
	.get_state = stm32mp2_pwr_regul_get_state,
	.set_voltage = stm32mp2_pwr_regul_set_voltage,
	.get_voltage = stm32mp2_pwr_regul_get_voltage,
	.supported_voltages = stm32mp2_pwr_regul_supported_voltages,
	.supplied_init = stm32mp2_pwr_regul_supplied_init,
};

static const struct regulator_ops stm32mp2_pwr_regul_fixed_ops = {
	.set_state = stm32mp2_pwr_regul_set_state,
	.get_state = stm32mp2_pwr_regul_get_state,
	.supplied_init = stm32mp2_pwr_regul_supplied_init,
};

enum pwr_regulator {
	IOD_VDDIO1,
	IOD_VDDIO2,
	IOD_VDDIO3,
#ifndef CFG_STM32MP21
	IOD_VDDIO4,
#endif
	IOD_VDDIO,
#ifndef CFG_STM32MP21
	REGU_UCPD,
#endif
	REGU_A,
#ifndef CFG_STM32MP21
	REGU_GPU,
#endif
	PWR_REGU_COUNT
};

static struct pwr_regul pwr_regulators[PWR_REGU_COUNT] = {
	 [IOD_VDDIO1] = {
		.enable_reg = PWR_CR8,
		.enable_mask = PWR_CR8_VDDIO1VMEN,
		.ready_mask = PWR_CR8_VDDIO1RDY,
		.valid_mask = PWR_CR8_VDDIO1SV,
		.vrsel_mask = PWR_CR8_VDDIO1VRSEL,
		.is_an_iod = true,
		.comp_idx = SYSFG_VDDIO1_ID,
	 },
	 [IOD_VDDIO2] = {
		.enable_reg = PWR_CR7,
		.enable_mask = PWR_CR7_VDDIO2VMEN,
		.ready_mask = PWR_CR7_VDDIO2RDY,
		.valid_mask = PWR_CR7_VDDIO2SV,
		.vrsel_mask = PWR_CR7_VDDIO2VRSEL,
		.is_an_iod = true,
		.comp_idx = SYSFG_VDDIO2_ID,
	 },
	 [IOD_VDDIO3] = {
		.enable_reg = PWR_CR1,
		.enable_mask = PWR_CR1_VDDIO3VMEN,
		.ready_mask = PWR_CR1_VDDIO3RDY,
		.valid_mask = PWR_CR1_VDDIO3SV,
		.vrsel_mask = PWR_CR1_VDDIO3VRSEL,
		.is_an_iod = true,
		.comp_idx = SYSFG_VDDIO3_ID,
	 },
#ifndef CFG_STM32MP21
	 [IOD_VDDIO4] = {
		.enable_reg = PWR_CR1,
		.enable_mask = PWR_CR1_VDDIO4VMEN,
		.ready_mask = PWR_CR1_VDDIO4RDY,
		.valid_mask = PWR_CR1_VDDIO4SV,
		.vrsel_mask = PWR_CR1_VDDIO4VRSEL,
		.is_an_iod = true,
		.comp_idx = SYSFG_VDDIO4_ID,
	 },
#endif
	 [IOD_VDDIO] = {
		.enable_reg = PWR_CR1,
		.vrsel_mask = PWR_CR1_VDDIOVRSEL,
		.is_an_iod = true,
		.comp_idx = SYSFG_VDD_IO_ID,
	 },
#ifndef CFG_STM32MP21
	 [REGU_UCPD] = {
		.enable_reg = PWR_CR1,
		.enable_mask = PWR_CR1_UCPDVMEN,
		.ready_mask = PWR_CR1_UCPDRDY,
		.valid_mask = PWR_CR1_UCPDSV,
	 },
#endif
	 [REGU_A] = {
		.enable_reg = PWR_CR1,
		.enable_mask = PWR_CR1_AVMEN,
		.ready_mask = PWR_CR1_ARDY,
		.valid_mask = PWR_CR1_ASV,
#if defined(CFG_STM32MP21)
		.has_clamp = true,
#endif
	 },
#ifndef CFG_STM32MP21
	 [REGU_GPU] = {
		.enable_reg = PWR_CR12,
		.enable_mask = PWR_CR12_GPUVMEN,
		.ready_mask = PWR_CR12_VDDGPURDY,
		.valid_mask = PWR_CR12_GPUSV,
		.keep_monitor_on = true,
		.rifsc_filtering_id = STM32MP25_RIFSC_GPU_ID,
	 },
#endif
};

#define DEFINE_REGUL(_id, _name, _supply) {		\
		.name = (_name),			\
		.supply_name = (_supply),		\
		.ops = &stm32mp2_pwr_regul_ops,		\
		.priv = pwr_regulators + (_id),		\
		.regulator = pwr_regu_device + (_id),	\
	}

#define DEFINE_FIXED(_id, _name, _supply) {		\
		.name = (_name),			\
		.supply_name = (_supply),		\
		.ops = &stm32mp2_pwr_regul_fixed_ops,	\
		.priv = pwr_regulators + (_id),		\
		.regulator = pwr_regu_device + (_id),	\
	}

/* Preallocated regulator devices */
static struct regulator pwr_regu_device[PWR_REGU_COUNT];

/* Not const to allow probe to reassign ops if device is a fixed_iod */
static const struct regu_dt_desc pwr_regu_desc[PWR_REGU_COUNT] = {
	[IOD_VDDIO1] = DEFINE_REGUL(IOD_VDDIO1, "vddio1", "vddio1"),
	[IOD_VDDIO2] = DEFINE_REGUL(IOD_VDDIO2, "vddio2", "vddio2"),
	[IOD_VDDIO3] = DEFINE_REGUL(IOD_VDDIO3, "vddio3", "vddio3"),
#ifndef CFG_STM32MP21
	[IOD_VDDIO4] = DEFINE_REGUL(IOD_VDDIO4, "vddio4", "vddio4"),
#endif
	[IOD_VDDIO]  = DEFINE_REGUL(IOD_VDDIO, "vddio", "vdd"),
#ifndef CFG_STM32MP21
	[REGU_UCPD]  = DEFINE_FIXED(REGU_UCPD, "vdd33ucpd", "vdd33ucpd"),
#endif
	[REGU_A]     = DEFINE_FIXED(REGU_A, "vdda18adc", "vdda18adc"),
#ifndef CFG_STM32MP21
	[REGU_GPU]   = DEFINE_REGUL(REGU_GPU, "vddgpu", "vddgpu"),
#endif
};

static TEE_Result
stm32mp2_pwr_regul_regulator_probe(const void *fdt, int node,
				   const void *compat_data __unused)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	const struct regu_dt_desc *desc = NULL;
	const char *regu_name = NULL;
	struct pwr_regul *pwr_regu = NULL;
	size_t i = 0;

	regu_name = fdt_get_name(fdt, node, NULL);

	FMSG("PWR probe regulator node %s", regu_name);

	/* Look for matching regulator */
	for (i = 0; i < PWR_REGU_COUNT; i++) {
		if (!strcmp(pwr_regu_desc[i].name, regu_name)) {
			desc = pwr_regu_desc + i;
			break;
		}
	}
	if (!desc) {
		EMSG("No regulator found for node %s", regu_name);
		return TEE_ERROR_GENERIC;
	}

	pwr_regu = desc->priv;
	if (pwr_regu->is_an_iod) {
		int ret;

		ret = fdt_read_uint32_array(fdt, node, "st,iocomp",
					    pwr_regu->iocomp_code,
					    IOCOMP_CODE_MAX);
		if (ret && ret != -FDT_ERR_NOTFOUND)
			return TEE_ERROR_BAD_PARAMETERS;

		if (!ret)
			pwr_regu->iocomp_fixed = true;
	}

	res = regulator_dt_register(fdt, node, node, desc);
	if (res) {
		EMSG("Failed to register node %s: %#"PRIx32, regu_name, res);
		return res;
	}

	FMSG("regu_name=%s probed", regu_name);

	return TEE_SUCCESS;
}

static const struct dt_device_match stm32mp2_pwr_regul_match_table[] = {
	{ .compatible = "st,stm32mp21-pwr-regu" },
	{ .compatible = "st,stm32mp25-pwr-regu" },
	{ }
};

DEFINE_DT_DRIVER(stm32mp2_pwr_regulator_dt_driver) = {
	.name = "stm32mp2-pwr-regulator",
	.type = DT_DRIVER_REGULATOR,
	.match_table = stm32mp2_pwr_regul_match_table,
	.probe = stm32mp2_pwr_regul_regulator_probe,
};
