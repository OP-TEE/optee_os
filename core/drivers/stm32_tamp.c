// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2021-2022, STMicroelectronics
 */

#include <drivers/clk.h>
#include <drivers/clk_dt.h>
#include <drivers/stm32_tamp.h>
#include <io.h>
#include <kernel/dt.h>
#include <kernel/dt_driver.h>
#include <kernel/interrupt.h>
#include <libfdt.h>
#include <mm/core_memprot.h>
#include <stdbool.h>

/* STM32 Registers */
#define _TAMP_CR1			0x00U
#define _TAMP_CR2			0x04U
#define _TAMP_CR3			0x08U
#define _TAMP_FLTCR			0x0CU
#define _TAMP_ATCR1			0x10U
#define _TAMP_ATSEEDR			0x14U
#define _TAMP_ATOR			0x18U
#define _TAMP_ATCR2			0x1CU
#define _TAMP_SECCFGR			0x20U
#define _TAMP_SMCR			0x20U
#define _TAMP_PRIVCFGR			0x24U
#define _TAMP_IER			0x2CU
#define _TAMP_SR			0x30U
#define _TAMP_MISR			0x34U
#define _TAMP_SMISR			0x38U
#define _TAMP_SCR			0x3CU
#define _TAMP_COUNTR			0x40U
#define _TAMP_COUNT2R			0x44U
#define _TAMP_OR			0x50U
#define _TAMP_ERCFGR			0X54U
#define _TAMP_HWCFGR2			0x3ECU
#define _TAMP_HWCFGR1			0x3F0U
#define _TAMP_VERR			0x3F4U
#define _TAMP_IPIDR			0x3F8U
#define _TAMP_SIDR			0x3FCU

/* _TAMP_SECCFGR bit fields */
#define _TAMP_SECCFGR_BKPRWSEC_MASK	GENMASK_32(7, 0)
#define _TAMP_SECCFGR_BKPRWSEC_SHIFT	0U
#define _TAMP_SECCFGR_CNT2SEC		BIT(14)
#define _TAMP_SECCFGR_CNT1SEC		BIT(15)
#define _TAMP_SECCFGR_BKPWSEC_MASK	GENMASK_32(23, 16)
#define _TAMP_SECCFGR_BKPWSEC_SHIFT	16U
#define _TAMP_SECCFGR_BHKLOCK		BIT(30)
#define _TAMP_SECCFGR_TAMPSEC		BIT(31)
#define _TAMP_SECCFGR_BUT_BKP_MASK	(GENMASK_32(31, 30) | \
					 GENMASK_32(15, 14))

/* _TAMP_SMCR bit fields */
#define _TAMP_SMCR_BKPRWDPROT_MASK	GENMASK_32(7, 0)
#define _TAMP_SMCR_BKPRWDPROT_SHIFT	0U
#define _TAMP_SMCR_BKPWDPROT_MASK	GENMASK_32(23, 16)
#define _TAMP_SMCR_BKPWDPROT_SHIFT	16U
#define _TAMP_SMCR_DPROT		BIT(31)
/*
 * _TAMP_PRIVCFGR bit fields
 */
#define _TAMP_PRIVCFG_CNT2PRIV		BIT(14)
#define _TAMP_PRIVCFG_CNT1PRIV		BIT(15)
#define _TAMP_PRIVCFG_BKPRWPRIV		BIT(29)
#define _TAMP_PRIVCFG_BKPWPRIV		BIT(30)
#define _TAMP_PRIVCFG_TAMPPRIV		BIT(31)
#define _TAMP_PRIVCFGR_MASK		(GENMASK_32(31, 29) | \
					 GENMASK_32(15, 14))

/*
 * _TAMP_PRIVCFGR bit fields
 */
#define _TAMP_PRIVCFG_CNT2PRIV		BIT(14)
#define _TAMP_PRIVCFG_CNT1PRIV		BIT(15)
#define _TAMP_PRIVCFG_BKPRWPRIV		BIT(29)
#define _TAMP_PRIVCFG_BKPWPRIV		BIT(30)
#define _TAMP_PRIVCFG_TAMPPRIV		BIT(31)
#define _TAMP_PRIVCFGR_MASK		(GENMASK_32(31, 29) | \
					 GENMASK_32(15, 14))

/* _TAMP_HWCFGR2 bit fields */
#define _TAMP_HWCFGR2_TZ		GENMASK_32(11, 8)
#define _TAMP_HWCFGR2_OR		GENMASK_32(7, 0)

/* _TAMP_HWCFGR1 bit fields */
#define _TAMP_HWCFGR1_BKPREG		GENMASK_32(7, 0)
#define _TAMP_HWCFGR1_TAMPER		GENMASK_32(11, 8)
#define _TAMP_HWCFGR1_ACTIVE		GENMASK_32(15, 12)
#define _TAMP_HWCFGR1_INTERN		GENMASK_32(31, 16)
#define _TAMP_HWCFGR1_ITAMP_MAX_ID	16U
#define _TAMP_HWCFGR1_ITAMP(id)		BIT((id) - INT_TAMP1 + 16U)

/* _TAMP_VERR bit fields */
#define _TAMP_VERR_MINREV		GENMASK_32(3, 0)
#define _TAMP_VERR_MAJREV		GENMASK_32(7, 4)

/*
 * TAMP instance data
 * @base - IOMEM base address
 * @clock - TAMP clock
 * @it - TAMP interrupt number
 * @hwconf1 - Copy of TAMP HWCONF1 register content
 * @hwconf2 - Copy of TAMP HWCONF2 register content
 * @compat - Reference to compat data passed at driver initialization
 */
struct stm32_tamp_instance {
	struct io_pa_va base;
	struct clk *clock;
	int it;
	uint32_t hwconf1;
	uint32_t hwconf2;
	struct stm32_tamp_compat *compat;
};

/*
 * Compatibility capabilities
 * TAMP_HAS_REGISTER_SECCFG - Supports SECCFGR, otherwise supports SMCR register
 * TAMP_HAS_REGISTER_PRIVCFG - Supports PRIVCFGR configuration register
 */
#define TAMP_HAS_REGISTER_SECCFG	BIT(0)
#define TAMP_HAS_REGISTER_PRIVCFGR	BIT(1)

/*
 * @nb_monotonic_counter - Number of monotic counter supported
 * @tags - Bit flags TAMP_HAS_* for compatibily management
 */
struct stm32_tamp_compat {
	int nb_monotonic_counter;
	uint32_t tags;
};

/* Expects at most a single instance */
static struct stm32_tamp_instance *stm32_tamp_device;

TEE_Result stm32_tamp_set_secure_bkpregs(struct stm32_bkpregs_conf *bkr_conf)
{
	struct stm32_tamp_instance *tamp = stm32_tamp_device;
	vaddr_t base = 0;
	uint32_t first_z2 = 0;
	uint32_t first_z3 = 0;

	if (!tamp)
		return TEE_ERROR_DEFER_DRIVER_INIT;

	if (!bkr_conf)
		return TEE_ERROR_BAD_PARAMETERS;

	base = io_pa_or_va(&tamp->base, 1);

	first_z2 = bkr_conf->nb_zone1_regs;
	first_z3 = bkr_conf->nb_zone1_regs + bkr_conf->nb_zone2_regs;

	if ((first_z2 > (tamp->hwconf1 & _TAMP_HWCFGR1_BKPREG)) ||
	    (first_z3 > (tamp->hwconf1 & _TAMP_HWCFGR1_BKPREG)))
		return TEE_ERROR_BAD_PARAMETERS;

	if (tamp->compat && (tamp->compat->tags & TAMP_HAS_REGISTER_SECCFG)) {
		io_clrsetbits32(base + _TAMP_SECCFGR,
				_TAMP_SECCFGR_BKPRWSEC_MASK,
				(first_z2 << _TAMP_SECCFGR_BKPRWSEC_SHIFT) &
				_TAMP_SECCFGR_BKPRWSEC_MASK);

		io_clrsetbits32(base + _TAMP_SECCFGR,
				_TAMP_SECCFGR_BKPWSEC_MASK,
				(first_z3 << _TAMP_SECCFGR_BKPWSEC_SHIFT) &
				_TAMP_SECCFGR_BKPWSEC_MASK);
	} else {
		io_clrsetbits32(base + _TAMP_SMCR,
				_TAMP_SMCR_BKPRWDPROT_MASK,
				(first_z2 << _TAMP_SMCR_BKPRWDPROT_SHIFT) &
				_TAMP_SMCR_BKPRWDPROT_MASK);

		io_clrsetbits32(base + _TAMP_SMCR,
				_TAMP_SMCR_BKPWDPROT_MASK,
				(first_z3 << _TAMP_SMCR_BKPWDPROT_SHIFT) &
				_TAMP_SMCR_BKPWDPROT_MASK);
	}

	return TEE_SUCCESS;
}

static void stm32_tamp_set_secure(struct stm32_tamp_instance *tamp,
				  uint32_t mode)
{
	vaddr_t base = io_pa_or_va(&tamp->base, 1);

	if (tamp->compat && (tamp->compat->tags & TAMP_HAS_REGISTER_SECCFG)) {
		io_clrsetbits32(base + _TAMP_SECCFGR,
				_TAMP_SECCFGR_BUT_BKP_MASK,
				mode & _TAMP_SECCFGR_BUT_BKP_MASK);
	} else {
		/*
		 * Note: MP15 doesn't use SECCFG register and
		 * inverts the secure bit.
		 */
		if (mode & _TAMP_SECCFGR_TAMPSEC)
			io_clrbits32(base + _TAMP_SMCR, _TAMP_SMCR_DPROT);
		else
			io_setbits32(base + _TAMP_SMCR, _TAMP_SMCR_DPROT);
	}
}

static void stm32_tamp_set_privilege(struct stm32_tamp_instance *tamp,
				     uint32_t mode)
{
	vaddr_t base = io_pa_or_va(&tamp->base, 1);

	if (tamp->compat && (tamp->compat->tags & TAMP_HAS_REGISTER_PRIVCFGR))
		io_clrsetbits32(base + _TAMP_PRIVCFGR, _TAMP_PRIVCFGR_MASK,
				mode & _TAMP_PRIVCFGR_MASK);
}

static TEE_Result stm32_tamp_parse_fdt(struct stm32_tamp_instance *tamp,
				       const void *fdt, int node,
				       const void *compat)
{
	struct dt_node_info dt_tamp = { };

	fdt_fill_device_info(fdt, &dt_tamp, node);

	if (dt_tamp.reg == DT_INFO_INVALID_REG ||
	    dt_tamp.reg_size == DT_INFO_INVALID_REG_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	tamp->compat = (struct stm32_tamp_compat *)compat;
	tamp->it = dt_tamp.interrupt;
	tamp->base.pa = dt_tamp.reg;
	io_pa_or_va_secure(&tamp->base, dt_tamp.reg_size);

	return clk_dt_get_by_index(fdt, node, 0, &tamp->clock);
}

static TEE_Result stm32_tamp_probe(const void *fdt, int node,
				   const void *compat_data)
{
	struct stm32_tamp_instance *tamp = NULL;
	uint32_t __maybe_unused revision = 0;
	TEE_Result res = TEE_SUCCESS;
	vaddr_t base = 0;

	tamp = calloc(1, sizeof(*tamp));
	if (!tamp)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = stm32_tamp_parse_fdt(tamp, fdt, node, compat_data);
	if (res)
		goto err;

	clk_enable(tamp->clock);

	base = io_pa_or_va(&tamp->base, 1);

	tamp->hwconf1 = io_read32(base + _TAMP_HWCFGR1);
	tamp->hwconf2 = io_read32(base + _TAMP_HWCFGR2);

	revision = io_read32(base + _TAMP_VERR);
	FMSG("STM32 TAMPER V%"PRIx32".%"PRIu32,
	     (revision & _TAMP_VERR_MAJREV) >> 4, revision & _TAMP_VERR_MINREV);

	if (!(tamp->hwconf2 & _TAMP_HWCFGR2_TZ)) {
		EMSG("TAMP doesn't support TrustZone");
		res = TEE_ERROR_NOT_SUPPORTED;
		goto err_clk;
	}

	/*
	 * Enforce secure only access to protected TAMP registers.
	 * Allow non-secure access to monotonic counter.
	 */
	stm32_tamp_set_secure(tamp, _TAMP_SECCFGR_TAMPSEC);

	/*
	 * Enforce privilege only access to TAMP registers, backup
	 * registers and monotonic counter.
	 */
	stm32_tamp_set_privilege(tamp, _TAMP_PRIVCFG_TAMPPRIV |
				 _TAMP_PRIVCFG_BKPRWPRIV |
				 _TAMP_PRIVCFG_BKPWPRIV);

	stm32_tamp_device = tamp;

	return TEE_SUCCESS;

err_clk:
	clk_disable(tamp->clock);
err:
	free(tamp);
	return res;
}

static const struct stm32_tamp_compat mp13_compat = {
	.nb_monotonic_counter = 2,
	.tags = TAMP_HAS_REGISTER_SECCFG | TAMP_HAS_REGISTER_PRIVCFGR,
};

static const struct stm32_tamp_compat mp15_compat = {
	.nb_monotonic_counter = 1,
	.tags = 0,
};

static const struct dt_device_match stm32_tamp_match_table[] = {
	{ .compatible = "st,stm32mp13-tamp", .compat_data = &mp13_compat },
	{ .compatible = "st,stm32-tamp", .compat_data = &mp15_compat },
	{ }
};

DEFINE_DT_DRIVER(stm32_tamp_dt_driver) = {
	.name = "stm32-tamp",
	.match_table = stm32_tamp_match_table,
	.probe = stm32_tamp_probe,
};
