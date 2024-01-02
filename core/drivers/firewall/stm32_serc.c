// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2022-2024, STMicroelectronics
 */
#include <drivers/clk.h>
#include <drivers/clk_dt.h>
#include <drivers/stm32_rif.h>
#include <io.h>
#include <kernel/boot.h>
#include <kernel/dt.h>
#include <kernel/interrupt.h>
#include <kernel/panic.h>
#include <kernel/pm.h>
#include <libfdt.h>
#include <mm/core_memprot.h>
#include <tee_api_defines.h>
#include <trace.h>
#include <util.h>

/* SERC offset register */
#define _SERC_IER0		U(0x000)
#define _SERC_ISR0		U(0x040)
#define _SERC_ICR0		U(0x080)
#define _SERC_ENABLE		U(0x100)

#define _SERC_HWCFGR		U(0x3F0)
#define _SERC_VERR		U(0x3F4)

/* SERC_ENABLE register fields */
#define _SERC_ENABLE_SERFEN	BIT(0)

/* SERC_HWCFGR register fields */
#define _SERC_HWCFGR_CFG1_MASK	GENMASK_32(7, 0)
#define _SERC_HWCFGR_CFG1_SHIFT	U(0)
#define _SERC_HWCFGR_CFG2_MASK	GENMASK_32(18, 16)
#define _SERC_HWCFGR_CFG2_SHIFT	U(16)

/* SERC_VERR register fields */
#define _SERC_VERR_MINREV_MASK	GENMASK_32(3, 0)
#define _SERC_VERR_MINREV_SHIFT	U(0)
#define _SERC_VERR_MAJREV_MASK	GENMASK_32(7, 4)
#define _SERC_VERR_MAJREV_SHIFT	U(4)

/* Periph id per register */
#define _PERIPH_IDS_PER_REG	U(32)

#define _SERC_FLD_PREP(field, value)	(((uint32_t)(value) << \
					  (field ## _SHIFT)) & (field ## _MASK))
#define _SERC_FLD_GET(field, value)	(((uint32_t)(value) & \
					  (field ## _MASK)) >> \
					 (field ## _SHIFT))

#define SERC_EXCEPT_MSB_BIT(x) ((x) * _PERIPH_IDS_PER_REG + \
				_PERIPH_IDS_PER_REG - 1)
#define SERC_EXCEPT_LSB_BIT(x) ((x) * _PERIPH_IDS_PER_REG)

/**
 * struct serc_driver_data - Hardware information on the SERC peripheral
 *
 * @version: Peripheral version number
 * @num_ilac: Number of SERC lines
 */
struct serc_driver_data {
	uint32_t version;
	uint8_t num_ilac;
};

/**
 * struct stm32_serc_platdata - Platform data for the SERC driver
 *
 * @base: Base address of the SERC peripheral
 * @clock: Reference on the SERC clock
 * @irq: Id of the SERC interrupt
 */
struct stm32_serc_platdata {
	uintptr_t base;
	struct clk *clock;
	int irq;
};

struct serc_device {
	int node;
	struct stm32_serc_platdata pdata;
	struct serc_driver_data *ddata;
	struct itr_handler *itr;
	const void *fdt;
};

static struct serc_device serc_dev;

static void stm32_serc_get_hwdata(void)
{
	struct stm32_serc_platdata *pdata = &serc_dev.pdata;
	struct serc_driver_data *ddata = serc_dev.ddata;
	uintptr_t base = pdata->base;
	uint32_t regval = 0;

	regval = io_read32(base + _SERC_HWCFGR);

	ddata->num_ilac = _SERC_FLD_GET(_SERC_HWCFGR_CFG1, regval);

	ddata->version = io_read32(base + _SERC_VERR);

	DMSG("SERC version %"PRIu32".%"PRIu32,
	     _SERC_FLD_GET(_SERC_VERR_MAJREV, ddata->version),
	     _SERC_FLD_GET(_SERC_VERR_MINREV, ddata->version));

	DMSG("HW cap: num ilac:[%"PRIu8"]", ddata->num_ilac);
}

static TEE_Result stm32_serc_parse_fdt(void)
{
	struct stm32_serc_platdata *pdata = &serc_dev.pdata;
	struct dt_node_info dt_info = { };
	static struct io_pa_va base = { };
	const void *fdt = serc_dev.fdt;
	int node = serc_dev.node;

	assert(serc_dev.fdt);

	fdt_fill_device_info(fdt, &dt_info, node);
	if (dt_info.status == DT_STATUS_DISABLED ||
	    dt_info.reg == DT_INFO_INVALID_REG ||
	    dt_info.clock == DT_INFO_INVALID_CLOCK ||
	    dt_info.interrupt == DT_INFO_INVALID_INTERRUPT)
		return TEE_ERROR_BAD_PARAMETERS;

	base.pa = dt_info.reg;
	pdata->base = io_pa_or_va_secure(&base, 1);
	pdata->irq = dt_info.interrupt;

	return clk_dt_get_by_index(fdt, node, 0, &pdata->clock);
}

static void stm32_serc_handle_ilac(void)
{
	struct serc_driver_data *ddata = serc_dev.ddata;
	struct stm32_serc_platdata *pdata = &serc_dev.pdata;
	uintptr_t base = pdata->base;
	int nreg = DIV_ROUND_UP(ddata->num_ilac, _PERIPH_IDS_PER_REG);
	bool do_panic = false;
	uint32_t isr = 0;
	uint32_t i = 0;

	for (i = 0; i < (unsigned int)nreg; i++) {
		uint32_t offset = sizeof(uint32_t) * i;
		uint8_t tries = 0;

		isr = io_read32(base + _SERC_ISR0 + offset);
		isr &= io_read32(base + _SERC_IER0 + offset);

		if (isr) {
			do_panic = true;

			EMSG("SERC exceptions [%d:%d]: %#x",
			     SERC_EXCEPT_MSB_BIT(i), SERC_EXCEPT_LSB_BIT(i),
			     isr);
		}

		while (isr && tries < _PERIPH_IDS_PER_REG) {
			EMSG("SERC exception ID: %d",
			     SERC_EXCEPT_LSB_BIT(i) + __builtin_ffs(isr) - 1);

			io_write32(base + _SERC_ICR0 + offset,
				   1 << (__builtin_ffs(isr) - 1));

			isr = io_read32(base + _SERC_ISR0 + offset);
			isr &= io_read32(base + _SERC_IER0 + offset);

			tries++;
		}
	}

	if (do_panic) {
		stm32_rif_access_violation_action();
		if (IS_ENABLED(CFG_STM32_PANIC_ON_SERC_EVENT))
			panic();
	}
}

static enum itr_return stm32_serc_itr(struct itr_handler *h __unused)
{
	stm32_serc_handle_ilac();

	return ITRR_HANDLED;
}

static void stm32_serc_setup(void)
{
	struct stm32_serc_platdata *pdata = &serc_dev.pdata;
	struct serc_driver_data *ddata = serc_dev.ddata;
	uintptr_t base = serc_dev.pdata.base;
	uint32_t nreg = DIV_ROUND_UP(ddata->num_ilac, _PERIPH_IDS_PER_REG);
	uint32_t i = 0;

	io_setbits32(pdata->base + _SERC_ENABLE, _SERC_ENABLE_SERFEN);

	for (i = 0; i < nreg; i++) {
		vaddr_t reg_ofst = base + sizeof(uint32_t) * i;

		//clear status flags
		io_write32(reg_ofst + _SERC_ICR0, ~0x0);
		//enable all peripherals of nreg
		io_write32(reg_ofst + _SERC_IER0, ~0x0);
	}
}

static TEE_Result probe_serc_device(void)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	res = stm32_serc_parse_fdt();
	if (res)
		return res;

	/* Asymmetric clock enable to have the SERC running */
	if (clk_enable(serc_dev.pdata.clock))
		panic();

	stm32_serc_get_hwdata();
	stm32_serc_setup();

	res = interrupt_alloc_add_handler(interrupt_get_main_chip(),
					  serc_dev.pdata.irq, stm32_serc_itr,
					  ITRF_TRIGGER_LEVEL, NULL,
					  &serc_dev.itr);
	if (res)
		return res;

	interrupt_enable(interrupt_get_main_chip(), serc_dev.itr->it);

	return TEE_SUCCESS;
}

static TEE_Result stm32_serc_pm(enum pm_op op, unsigned int pm_hint,
				const struct pm_callback_handle *hdl __unused)
{
	if (!PM_HINT_IS_STATE(pm_hint, CONTEXT))
		return TEE_SUCCESS;

	if (op == PM_OP_RESUME) {
		/* Asymmetric clock enable to have the SERC running */
		if (clk_enable(serc_dev.pdata.clock))
			panic();
		stm32_serc_setup();

	} else {
		clk_disable(serc_dev.pdata.clock);
	}

	return TEE_SUCCESS;
}

static void stm32_serc_free(void)
{
	if (serc_dev.itr)
		interrupt_remove_free_handler(serc_dev.itr);

	free(serc_dev.ddata);
}

static TEE_Result stm32_serc_probe(const void *fdt, int node,
				   const void *compat_data __unused)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	serc_dev.ddata = calloc(1, sizeof(*serc_dev.ddata));
	if (!serc_dev.ddata)
		return TEE_ERROR_OUT_OF_MEMORY;

	serc_dev.fdt = fdt;
	serc_dev.node = node;

	res = probe_serc_device();
	if (res) {
		stm32_serc_free();
		return res;
	}

	register_pm_core_service_cb(stm32_serc_pm, NULL, "stm32-serc");

	return TEE_SUCCESS;
}

static const struct dt_device_match stm32_serc_match_table[] = {
	{ .compatible = "st,stm32mp25-serc" },
	{ }
};

DEFINE_DT_DRIVER(stm32_serc_dt_driver) = {
	.name = "stm32-serc",
	.match_table = stm32_serc_match_table,
	.probe = stm32_serc_probe,
};
