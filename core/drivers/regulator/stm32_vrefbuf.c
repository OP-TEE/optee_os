// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021-2023, STMicroelectronics
 */

#include <drivers/clk.h>
#include <drivers/clk_dt.h>
#include <drivers/regulator.h>
#include <drivers/stm32_vrefbuf.h>
#include <initcall.h>
#include <io.h>
#include <keep.h>
#include <kernel/delay.h>
#include <kernel/pm.h>
#include <libfdt.h>
#include <mm/core_memprot.h>

/* STM32 VREFBUF registers */
#define VREFBUF_CSR			U(0)

/* STM32 VREFBUF CSR bitfields */

/* VRS bit 3 is unused because the voltage is not specified */
#define VREFBUF_CSR_VRS			GENMASK_32(5, 4)
#define VREFBUF_CSR_VRS_SHIFT		U(4)
#define INV_VRS(x)			((~(x)) & VREFBUF_CSR_VRS)

#define VREFBUF_CSR_VRR			BIT(3)
#define VREFBUF_CSR_HIZ			BIT(1)
#define VREFBUF_CSR_ENVR			BIT(0)

#define TIMEOUT_US_10MS			U(10 * 1000)
#define TIMEOUT_US_1MS			U(1 * 1000)

#define VREFBUF_LEVELS_COUNT		U(4)

/*
 * struct vrefbuf_compat - Compatibility data
 * @voltages: Voltage levels supported
 */
struct vrefbuf_compat {
	int voltages[VREFBUF_LEVELS_COUNT];
};

/*
 * struct vrefbuf_regul - VREFBUF regulator
 * @base: IO memory base address
 * @clock: VREFBUF access bus clock
 * @regulator: Preallocated instance for the regulator
 * @compat: Compatibility data
 * @voltages_desc: Supported voltage level description
 * @voltages_level: Supplorted levels description
 * @voltages_start_index: start index in compat for supported levels
 */
struct vrefbuf_regul {
	vaddr_t base;
	struct clk *clock;
	uint64_t disable_timeout;
	struct regulator regulator;
	const struct vrefbuf_compat *compat;
	struct regulator_voltages_desc voltages_desc;
	size_t voltages_start_index;
};

static const struct vrefbuf_compat stm32mp15_vrefbuf_compat = {
	.voltages = {
		/* Matches resp. VRS = 011b, 010b, 001b, 000b */
		1500000, 1800000, 2048000, 2500000,
	},
};

static const struct vrefbuf_compat stm32mp13_vrefbuf_compat = {
	.voltages = {
		/* Matches resp. VRS = 011b, 010b, 001b, 000b */
		1650000, 1800000, 2048000, 2500000,
	},
};

/* Expect at most 1 instance */
static struct vrefbuf_regul *stm32_vrefbuf;

struct regulator *stm32_vrefbuf_regulator(void)
{
	if (!stm32_vrefbuf)
		return NULL;

	return &stm32_vrefbuf->regulator;
}

static struct vrefbuf_regul *regulator_to_vr(struct regulator *regulator)
{
	return container_of(regulator, struct vrefbuf_regul, regulator);
}

static TEE_Result vrefbuf_wait_ready(struct vrefbuf_regul *vr)
{
	uint32_t val = 0;

	if (IO_READ32_POLL_TIMEOUT(vr->base + VREFBUF_CSR, val,
				   val & VREFBUF_CSR_VRR, 0, TIMEOUT_US_10MS))
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

static TEE_Result vrefbuf_set_state(struct regulator *regulator, bool enable)
{
	struct vrefbuf_regul *vr = regulator_to_vr(regulator);
	TEE_Result res = TEE_ERROR_GENERIC;

	res = clk_enable(vr->clock);
	if (res)
		return res;

	if (enable) {
		io_clrbits32(vr->base + VREFBUF_CSR, VREFBUF_CSR_HIZ);

		/*
		 * If first enable after boot or if it was disabled since
		 * less than 1ms, then wait for 1ms in pull down mode to
		 * avoid an overshoot.
		 */
		if (!vr->disable_timeout ||
		    !timeout_elapsed(vr->disable_timeout))
			udelay(1000);

		io_setbits32(vr->base + VREFBUF_CSR, VREFBUF_CSR_ENVR);

		if (vrefbuf_wait_ready(vr) != TEE_SUCCESS) {
			clk_disable(vr->clock);

			return TEE_ERROR_GENERIC;
		}
	} else {
		io_clrbits32(vr->base + VREFBUF_CSR, VREFBUF_CSR_ENVR);

		vr->disable_timeout = timeout_init_us(TIMEOUT_US_1MS);
	}

	clk_disable(vr->clock);

	return TEE_SUCCESS;
}

static TEE_Result vrefbuf_get_state(struct regulator *regulator, bool *enabled)
{
	struct vrefbuf_regul *vr = regulator_to_vr(regulator);
	TEE_Result res = TEE_ERROR_GENERIC;

	res = clk_enable(vr->clock);
	if (res)
		return res;

	*enabled = io_read32(vr->base + VREFBUF_CSR) & VREFBUF_CSR_VRR;

	clk_disable(vr->clock);

	return TEE_SUCCESS;
}

static TEE_Result vrefbuf_get_voltage(struct regulator *regulator,
				      int *level_uv)
{
	struct vrefbuf_regul *vr = regulator_to_vr(regulator);
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t index = 0;

	res = clk_enable(vr->clock);
	if (res)
		return res;

	index = io_read32(vr->base + VREFBUF_CSR) & VREFBUF_CSR_VRS;
	index = INV_VRS(index) >> VREFBUF_CSR_VRS_SHIFT;

	clk_disable(vr->clock);

	*level_uv = vr->compat->voltages[index];

	return TEE_SUCCESS;
}

static TEE_Result vrefbuf_set_voltage(struct regulator *regulator, int level_uv)
{
	struct vrefbuf_regul *vr = regulator_to_vr(regulator);
	TEE_Result res = TEE_ERROR_GENERIC;
	size_t i = 0;

	for (i = 0 ; i < ARRAY_SIZE(vr->compat->voltages) ; i++) {
		if (vr->compat->voltages[i] == level_uv) {
			uint32_t val = INV_VRS(i << VREFBUF_CSR_VRS_SHIFT);

			res = clk_enable(vr->clock);
			if (res)
				return res;

			io_clrsetbits32(vr->base + VREFBUF_CSR, VREFBUF_CSR_VRS,
					val);

			clk_disable(vr->clock);

			return TEE_SUCCESS;
		}
	}

	EMSG("Failed to set voltage on vrefbuf");

	return TEE_ERROR_BAD_PARAMETERS;
}

static TEE_Result vrefbuf_list_voltages(struct regulator *regulator __unused,
					struct regulator_voltages_desc **desc,
					const int **levels)
{
	struct vrefbuf_regul *vr = regulator_to_vr(regulator);
	const int *levels_ref = vr->compat->voltages;

	*desc = &vr->voltages_desc;
	*levels = levels_ref + vr->voltages_start_index;

	return TEE_SUCCESS;
}

static TEE_Result set_voltages_desc(struct regulator *regulator)
{
	struct vrefbuf_regul *vr = regulator_to_vr(regulator);
	size_t num_levels = ARRAY_SIZE(vr->compat->voltages);
	int index_high = num_levels - 1;
	int index_low = 0;
	int n = 0;

	vr->voltages_desc.type = VOLTAGE_TYPE_FULL_LIST;

	for (n = 0; n <= index_high; n++)
		if (vr->compat->voltages[n] >= regulator->min_uv)
			break;
	if (n > index_high)
		return TEE_ERROR_GENERIC;
	index_low = n;

	for (n = index_high; n >= index_low; n--)
		if (vr->compat->voltages[n] <= regulator->max_uv)
			break;
	if (n < index_low)
		return TEE_ERROR_GENERIC;
	index_high = n;

	assert(index_high - index_low + 1 >= 0 && index_low >= 0);

	vr->voltages_desc.type = VOLTAGE_TYPE_FULL_LIST;
	vr->voltages_desc.num_levels = index_high - index_low + 1;
	vr->voltages_start_index = index_low;

	return TEE_SUCCESS;
}

static TEE_Result stm32_vrefbuf_pm(enum pm_op op, unsigned int pm_hint __unused,
				   const struct pm_callback_handle *hdl)
{
	struct regulator *regulator = hdl->handle;
	struct vrefbuf_regul *vr = regulator_to_vr(regulator);
	vaddr_t csr_va = vr->base + VREFBUF_CSR;
	TEE_Result res = TEE_ERROR_GENERIC;
	/* Context to save/restore on PM suspend/resume */
	static uint32_t pm_val;

	assert(op == PM_OP_SUSPEND || op == PM_OP_RESUME);

	res = clk_enable(vr->clock);
	if (res)
		return res;

	if (op == PM_OP_SUSPEND) {
		pm_val = io_read32(csr_va);

		if (pm_val & VREFBUF_CSR_ENVR && vrefbuf_wait_ready(vr)) {
			clk_disable(vr->clock);

			return TEE_ERROR_GENERIC;
		}
	} else {
		io_clrsetbits32(csr_va, VREFBUF_CSR_VRS, pm_val);

		if (pm_val & VREFBUF_CSR_ENVR) {
			vr->disable_timeout = 0;
			vrefbuf_set_state(&vr->regulator, true);
		}
	}

	clk_disable(vr->clock);

	return TEE_SUCCESS;
}
DECLARE_KEEP_PAGER(stm32_vrefbuf_pm);

static TEE_Result stm32_vrefbuf_init(struct regulator *regulator,
				     const void *fdt __unused,
				     int node __unused)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	res = set_voltages_desc(regulator);
	if (res)
		return res;

	register_pm_driver_cb(stm32_vrefbuf_pm, regulator, "stm32-vrefbuf");

	return TEE_SUCCESS;
}

static const struct regulator_ops vrefbuf_ops = {
	.set_state = vrefbuf_set_state,
	.get_state = vrefbuf_get_state,
	.set_voltage = vrefbuf_set_voltage,
	.get_voltage = vrefbuf_get_voltage,
	.supported_voltages = vrefbuf_list_voltages,
	.supplied_init = stm32_vrefbuf_init,
};

static TEE_Result stm32_vrefbuf_regulator_probe(const void *fdt, int node,
						const void *compat_data)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct vrefbuf_regul *vr = NULL;
	struct regu_dt_desc desc = { };
	char *regu_name = NULL;
	struct clk *clk = NULL;
	paddr_t reg_base = 0;
	size_t reg_size = 0;

	assert(!stm32_vrefbuf);

	res = clk_dt_get_by_index(fdt, node, 0, &clk);
	if (res)
		return res;

	vr = calloc(1, sizeof(*vr));
	if (!vr)
		panic();

	vr->compat = compat_data;

	regu_name = strdup(fdt_get_name(fdt, node, NULL));
	if (!regu_name)
		panic();

	reg_base = fdt_reg_base_address(fdt, node);
	reg_size = fdt_reg_size(fdt, node);
	if (reg_base == DT_INFO_INVALID_REG ||
	    reg_size == DT_INFO_INVALID_REG_SIZE)
		panic();

	vr->base = (vaddr_t)phys_to_virt(reg_base, MEM_AREA_IO_SEC, reg_size);
	if (!vr->base)
		panic();

	vr->clock = clk;

	desc = (struct regu_dt_desc){
		.name = regu_name,
		.ops = &vrefbuf_ops,
		.supply_name = "vdda",
		.regulator = &vr->regulator,
	};

	res = regulator_dt_register(fdt, node, node, &desc);
	if (res)
		panic();

	stm32_vrefbuf = vr;

	return TEE_SUCCESS;
}

static const struct dt_device_match stm32_vrefbuf_match_table[] = {
	{
		.compatible = "st,stm32-vrefbuf",
		.compat_data = &stm32mp15_vrefbuf_compat,
	},
	{
		.compatible = "st,stm32mp13-vrefbuf",
		.compat_data = &stm32mp13_vrefbuf_compat
	},
	{ }
};

DEFINE_DT_DRIVER(stm32_vrefbuf_regulator_dt_driver) = {
	.name = "stm32-vrefbuf-regulator",
	.match_table = stm32_vrefbuf_match_table,
	.probe = &stm32_vrefbuf_regulator_probe,
};
