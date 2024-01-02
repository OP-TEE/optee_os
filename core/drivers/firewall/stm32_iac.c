// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2022-2024, STMicroelectronics
 */
#include <drivers/stm32_rif.h>
#include <io.h>
#include <kernel/boot.h>
#include <kernel/dt.h>
#include <kernel/interrupt.h>
#include <kernel/panic.h>
#include <libfdt.h>
#include <mm/core_memprot.h>
#include <tee_api_defines.h>
#include <trace.h>
#include <util.h>

/* IAC offset register */
#define _IAC_IER0		U(0x000)
#define _IAC_ISR0		U(0x080)
#define _IAC_ICR0		U(0x100)
#define _IAC_IISR0		U(0x36C)

#define _IAC_HWCFGR2		U(0x3EC)
#define _IAC_HWCFGR1		U(0x3F0)
#define _IAC_VERR		U(0x3F4)

/* IAC_HWCFGR2 register fields */
#define _IAC_HWCFGR2_CFG1_MASK	GENMASK_32(3, 0)
#define _IAC_HWCFGR2_CFG1_SHIFT	0
#define _IAC_HWCFGR2_CFG2_MASK	GENMASK_32(7, 4)
#define _IAC_HWCFGR2_CFG2_SHIFT	4

/* IAC_HWCFGR1 register fields */
#define _IAC_HWCFGR1_CFG1_MASK	GENMASK_32(3, 0)
#define _IAC_HWCFGR1_CFG1_SHIFT	0
#define _IAC_HWCFGR1_CFG2_MASK	GENMASK_32(7, 4)
#define _IAC_HWCFGR1_CFG2_SHIFT	4
#define _IAC_HWCFGR1_CFG3_MASK	GENMASK_32(11, 8)
#define _IAC_HWCFGR1_CFG3_SHIFT	8
#define _IAC_HWCFGR1_CFG4_MASK	GENMASK_32(15, 12)
#define _IAC_HWCFGR1_CFG4_SHIFT	12
#define _IAC_HWCFGR1_CFG5_MASK	GENMASK_32(24, 16)
#define _IAC_HWCFGR1_CFG5_SHIFT	16

/* IAC_VERR register fields */
#define _IAC_VERR_MINREV_MASK	GENMASK_32(3, 0)
#define _IAC_VERR_MINREV_SHIFT	0
#define _IAC_VERR_MAJREV_MASK	GENMASK_32(7, 4)
#define _IAC_VERR_MAJREV_SHIFT	4

/* Periph ID per register */
#define _PERIPH_IDS_PER_REG	32

#define _IAC_FLD_PREP(field, value)	(SHIFT_U32((value), \
						   (field ## _SHIFT)) & \
					 (field ## _MASK))
#define _IAC_FLD_GET(field, value)	(((uint32_t)(value) & \
					  (field ## _MASK)) >> \
					 (field ## _SHIFT))

#define IAC_EXCEPT_MSB_BIT(x)		((x) * _PERIPH_IDS_PER_REG + \
					 _PERIPH_IDS_PER_REG - 1)
#define IAC_EXCEPT_LSB_BIT(x)		((x) * _PERIPH_IDS_PER_REG)
#define IAC_FIRST_ILAC_IN_REG(x)	(__builtin_ffs((x)) - 1)
#define IAC_ILAC_ID(reg_val, offset)	(IAC_FIRST_ILAC_IN_REG(reg_val) + \
					 IAC_EXCEPT_LSB_BIT(offset))

/**
 * struct iac_driver_data - Hardware information on the IAC peripheral
 *
 * @version: Peripheral version number
 * @num_ilac: Number of IAC lines
 */
struct iac_driver_data {
	uint32_t version;
	uint8_t num_ilac;
};

/**
 * struct stm32_iac_platdata - Platform data for the IAC driver
 *
 * @irq_chip: Reference to the main IRQ chip of the platform
 * @base: Virtual base address of the IAC peripheral
 * @irq: ID of the IAC interrupt
 */
struct stm32_iac_platdata {
	struct itr_chip *irq_chip;
	vaddr_t base;
	size_t irq;
};

/**
 * struct iac_device - IAC device private data
 * @pdata: Platform data read from the DT
 * @ddata: Device data read from the hardware
 * @itr: Interrupt handler reference
 */
struct iac_device {
	struct stm32_iac_platdata pdata;
	struct iac_driver_data *ddata;
	struct itr_handler *itr;
};

static struct iac_device iac_dev;

static void stm32_iac_get_hwdata(void)
{
	struct iac_driver_data *ddata = iac_dev.ddata;
	vaddr_t base = iac_dev.pdata.base;
	uint32_t regval = 0;

	regval = io_read32(base + _IAC_HWCFGR1);
	ddata->num_ilac = _IAC_FLD_GET(_IAC_HWCFGR1_CFG5, regval);

	ddata->version = io_read32(base + _IAC_VERR);

	DMSG("IAC version %"PRIu32".%"PRIu32,
	     _IAC_FLD_GET(_IAC_VERR_MAJREV, ddata->version),
	     _IAC_FLD_GET(_IAC_VERR_MINREV, ddata->version));

	DMSG("HW cap: enabled, num ilac:[%"PRIu8"]", ddata->num_ilac);
}

static TEE_Result stm32_iac_parse_fdt(const void *fdt, int node)
{
	struct stm32_iac_platdata *pdata = &iac_dev.pdata;
	TEE_Result res = TEE_ERROR_GENERIC;
	struct dt_node_info dt_info = { };
	struct io_pa_va base = { };

	fdt_fill_device_info(fdt, &dt_info, node);
	if (dt_info.reg == DT_INFO_INVALID_REG)
		return TEE_ERROR_BAD_PARAMETERS;

	res = interrupt_dt_get(fdt, node, &pdata->irq_chip, &pdata->irq);
	if (res)
		return res;

	base.pa = dt_info.reg;
	pdata->base = io_pa_or_va_secure(&base, dt_info.reg_size);

	return TEE_SUCCESS;
}

static enum itr_return stm32_iac_itr(struct itr_handler *h __unused)
{
	struct iac_driver_data *ddata = iac_dev.ddata;
	vaddr_t base = iac_dev.pdata.base;
	unsigned int nreg = DIV_ROUND_UP(ddata->num_ilac, _PERIPH_IDS_PER_REG);
	unsigned int i = 0;
	uint32_t isr = 0;

	for (i = 0; i < nreg; i++) {
		uint32_t offset = sizeof(uint32_t) * i;
		unsigned int j = 0;

		isr = io_read32(base + _IAC_ISR0 + offset);
		isr &= io_read32(base + _IAC_IER0 + offset);

		if (!isr)
			continue;

		EMSG("IAC exceptions [%d:%d]: %#"PRIx32, IAC_EXCEPT_MSB_BIT(i),
		     IAC_EXCEPT_LSB_BIT(i), isr);

		for (j = 0; j < _PERIPH_IDS_PER_REG; j++) {
			EMSG("IAC exception ID: %d", IAC_ILAC_ID(isr, i));

			io_write32(base + _IAC_ICR0 + offset,
				   BIT(IAC_FIRST_ILAC_IN_REG(isr)));

			isr = io_read32(base + _IAC_ISR0 + offset);
			isr &= io_read32(base + _IAC_IER0 + offset);

			if (!isr)
				break;
		}
	}

	stm32_rif_access_violation_action();
	if (IS_ENABLED(CFG_STM32_PANIC_ON_IAC_EVENT))
		panic();

	return ITRR_HANDLED;
}

static void stm32_iac_setup(void)
{
	struct iac_driver_data *ddata = iac_dev.ddata;
	vaddr_t base = iac_dev.pdata.base;
	unsigned int nreg = DIV_ROUND_UP(ddata->num_ilac, _PERIPH_IDS_PER_REG);
	unsigned int i = 0;

	for (i = 0; i < nreg; i++) {
		vaddr_t reg_ofst = base + sizeof(uint32_t) * i;

		/* Clear status flags */
		io_write32(reg_ofst + _IAC_ICR0, ~0x0);
		/* Enable all peripherals of nreg */
		io_write32(reg_ofst + _IAC_IER0, ~0x0);
	}
}

static TEE_Result probe_iac_device(const void *fdt, int node)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	bool is_tdcid = false;

	res = stm32_rifsc_check_tdcid(&is_tdcid);
	if (res)
		return res;

	/* IAC must be managed by the trusted domain CID */
	if (!is_tdcid)
		return TEE_ERROR_ACCESS_DENIED;

	res = stm32_iac_parse_fdt(fdt, node);
	if (res)
		return res;

	stm32_iac_get_hwdata();
	stm32_iac_setup();

	res = interrupt_alloc_add_handler(iac_dev.pdata.irq_chip,
					  iac_dev.pdata.irq, stm32_iac_itr,
					  ITRF_TRIGGER_LEVEL, NULL,
					  &iac_dev.itr);
	if (res)
		panic();

	interrupt_enable(iac_dev.pdata.irq_chip, iac_dev.itr->it);

	return TEE_SUCCESS;
}

static TEE_Result stm32_iac_probe(const void *fdt, int node,
				  const void *compat_data __unused)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	iac_dev.ddata = calloc(1, sizeof(*iac_dev.ddata));
	if (!iac_dev.ddata)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = probe_iac_device(fdt, node);
	if (res)
		free(iac_dev.ddata);

	return res;
}

static const struct dt_device_match stm32_iac_match_table[] = {
	{ .compatible = "st,stm32mp25-iac" },
	{ }
};

DEFINE_DT_DRIVER(stm32_iac_dt_driver) = {
	.name = "stm32-iac",
	.match_table = stm32_iac_match_table,
	.probe = stm32_iac_probe,
};
