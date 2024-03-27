// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2022-2024, STMicroelectronics
 */

#include <arm.h>
#include <config.h>
#include <drivers/clk.h>
#include <drivers/clk_dt.h>
#include <drivers/stm32_rif.h>
#include <io.h>
#include <kernel/boot.h>
#include <kernel/delay.h>
#include <kernel/dt.h>
#include <kernel/dt_driver.h>
#include <kernel/panic.h>
#include <kernel/pm.h>
#include <libfdt.h>
#include <mm/core_memprot.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stm32_util.h>
#include <trace.h>

#define IPCC_C1SECCFGR			U(0x80)
#define IPCC_C1PRIVCFGR			U(0x84)
#define IPCC_C1CIDCFGR			U(0x88)
#define IPCC_C2SECCFGR			U(0x90)
#define IPCC_C2PRIVCFGR			U(0x94)
#define IPCC_C2CIDCFGR			U(0x98)
#define IPCC_HWCFGR			U(0x3F0)

/*
 * CIDCFGR register bitfields
 */
#define IPCC_CIDCFGR_SCID_MASK		GENMASK_32(6, 4)
#define IPCC_CIDCFGR_CONF_MASK		(_CIDCFGR_CFEN |	 \
					 IPCC_CIDCFGR_SCID_MASK)

/*
 * PRIVCFGR register bitfields
 */
#define IPCC_PRIVCFGR_MASK		GENMASK_32(15, 0)

/*
 * SECCFGR register bitfields
 */
#define IPCC_SECCFGR_MASK		GENMASK_32(15, 0)

/*
 * IPCC_HWCFGR register bitfields
 */
#define IPCC_HWCFGR_CHAN_MASK		GENMASK_32(7, 0)

/*
 * Miscellaneous
 */
#define IPCC_NB_MAX_RIF_CHAN		U(16)

#define IPCC_NB_MAX_CID_SUPPORTED	U(7)

struct ipcc_pdata {
	/*
	 * An IPCC has nb_channels_cfg channel configuration for its
	 * (nb_channels_cfg / 2) bi-directionnal channels
	 */
	unsigned int nb_channels_cfg;
	struct clk *ipcc_clock;
	vaddr_t base;
	struct rif_conf_data conf_data;

	STAILQ_ENTRY(ipcc_pdata) link;
};

static STAILQ_HEAD(, ipcc_pdata) ipcc_list =
		STAILQ_HEAD_INITIALIZER(ipcc_list);

/* This function expects IPCC bus clock is enabled */
static void apply_rif_config(struct ipcc_pdata *ipcc_d, bool is_tdcid)
{
	uint32_t priv_proc_1 = 0;
	uint32_t priv_proc_2 = 0;
	uint32_t sec_proc_1 = 0;
	uint32_t sec_proc_2 = 0;
	unsigned int i = 0;
	bool is_cid_configured = false;

	/*
	 * Check that the number of channel supported by hardware
	 * is coherent with the config
	 */
	assert((io_read32(ipcc_d->base + IPCC_HWCFGR) &
			  IPCC_HWCFGR_CHAN_MASK) >=
	       ipcc_d->nb_channels_cfg / 2);

	/*
	 * When TDCID, OP-TEE should be the one to set the CID filtering
	 * configuration. Clearing previous configuration prevents
	 * undesired events during the only legitimate configuration.
	 */
	if (is_tdcid) {
		/* IPCC Processor 1 */
		io_clrbits32(ipcc_d->base + IPCC_C1CIDCFGR,
			     IPCC_CIDCFGR_CONF_MASK);

		/* IPCC Processor 2 */
		io_clrbits32(ipcc_d->base + IPCC_C2CIDCFGR,
			     IPCC_CIDCFGR_CONF_MASK);
	}

	/* Split the sec and priv configuration for IPCC processor 1 and 2 */
	sec_proc_1 = ipcc_d->conf_data.sec_conf[0] &
		     GENMASK_32(IPCC_NB_MAX_RIF_CHAN - 1, 0);
	priv_proc_1 = ipcc_d->conf_data.priv_conf[0] &
		     GENMASK_32(IPCC_NB_MAX_RIF_CHAN - 1, 0);

	sec_proc_2 = (ipcc_d->conf_data.sec_conf[0] &
		      GENMASK_32((IPCC_NB_MAX_RIF_CHAN * 2) - 1,
				 IPCC_NB_MAX_RIF_CHAN)) >>
		     IPCC_NB_MAX_RIF_CHAN;
	priv_proc_2 = (ipcc_d->conf_data.priv_conf[0] &
		       GENMASK_32((IPCC_NB_MAX_RIF_CHAN * 2) - 1,
				  IPCC_NB_MAX_RIF_CHAN)) >>
		      IPCC_NB_MAX_RIF_CHAN;

	/* Security and privilege RIF configuration */
	io_clrsetbits32(ipcc_d->base + IPCC_C1PRIVCFGR, IPCC_PRIVCFGR_MASK,
			priv_proc_1);
	io_clrsetbits32(ipcc_d->base + IPCC_C2PRIVCFGR, IPCC_PRIVCFGR_MASK,
			priv_proc_2);
	io_clrsetbits32(ipcc_d->base + IPCC_C1SECCFGR, IPCC_SECCFGR_MASK,
			sec_proc_1);
	io_clrsetbits32(ipcc_d->base + IPCC_C2SECCFGR, IPCC_SECCFGR_MASK,
			sec_proc_2);

	/*
	 * Evaluate RIF CID filtering configuration before setting it.
	 * Parsed configuration must have consistency. If CID filtering
	 * is enabled for an IPCC channel, then it must be the case for all
	 * channels of this processor. This is a configuration check.
	 */
	for (i = 0; i < IPCC_NB_MAX_RIF_CHAN; i++) {
		if (!(BIT(i) & ipcc_d->conf_data.access_mask[0]))
			continue;

		if (!is_cid_configured &&
		    (BIT(0) & ipcc_d->conf_data.cid_confs[i])) {
			is_cid_configured = true;
			if (i == IPCC_NB_MAX_RIF_CHAN - 1)
				panic("Inconsistent IPCC CID filtering RIF configuration");
		}

		if (is_cid_configured &&
		    !(BIT(0) & ipcc_d->conf_data.cid_confs[i]))
			panic("Inconsistent IPCC CID filtering RIF configuration");
	}

	/* IPCC processor 1 CID filtering configuration */
	if (!is_tdcid)
		return;

	io_clrsetbits32(ipcc_d->base + IPCC_C1CIDCFGR,
			IPCC_CIDCFGR_CONF_MASK,
			ipcc_d->conf_data.cid_confs[0]);

	/*
	 * Reset this field to evaluate CID filtering configuration
	 * for processor 2
	 */
	is_cid_configured = false;

	for (i = IPCC_NB_MAX_RIF_CHAN; i < IPCC_NB_MAX_RIF_CHAN * 2; i++) {
		if (!(BIT(i) & ipcc_d->conf_data.access_mask[0]))
			continue;

		if (!is_cid_configured &&
		    (BIT(0) & ipcc_d->conf_data.cid_confs[i])) {
			is_cid_configured = true;
			if (i == (IPCC_NB_MAX_RIF_CHAN * 2) - 1)
				panic("Inconsistent IPCC CID filtering RIF configuration");
		}

		if (is_cid_configured &&
		    !(BIT(0) & ipcc_d->conf_data.cid_confs[i]))
			panic("Inconsistent IPCC CID filtering RIF configuration");
	}

	/* IPCC Processor 2 CID filtering configuration */
	io_clrsetbits32(ipcc_d->base + IPCC_C2CIDCFGR,
			IPCC_CIDCFGR_CONF_MASK,
			ipcc_d->conf_data.cid_confs[IPCC_NB_MAX_RIF_CHAN]);
}

static void stm32_ipcc_pm_resume(struct ipcc_pdata *ipcc)
{
	apply_rif_config(ipcc, true);
}

static void stm32_ipcc_pm_suspend(struct ipcc_pdata *ipcc __unused)
{
	/*
	 * Do nothing because IPCC forbids RIF configuration read if CID
	 * filtering is enabled. We'll simply restore the device tree RIF
	 * configuration.
	 */
}

static TEE_Result
stm32_ipcc_pm(enum pm_op op, unsigned int pm_hint,
	      const struct pm_callback_handle *pm_handle)
{
	struct ipcc_pdata *ipcc = pm_handle->handle;
	TEE_Result res = TEE_ERROR_GENERIC;
	bool is_tdcid = false;

	if (stm32_rifsc_check_tdcid(&is_tdcid))
		panic();

	if (!PM_HINT_IS_STATE(pm_hint, CONTEXT) || !is_tdcid)
		return TEE_SUCCESS;

	res = clk_enable(ipcc->ipcc_clock);
	if (res)
		return res;

	if (op == PM_OP_RESUME)
		stm32_ipcc_pm_resume(ipcc);
	else
		stm32_ipcc_pm_suspend(ipcc);

	clk_disable(ipcc->ipcc_clock);

	return TEE_SUCCESS;
}

static TEE_Result parse_dt(const void *fdt, int node, struct ipcc_pdata *ipcc_d)
{
	int lenp = 0;
	unsigned int i = 0;
	TEE_Result res = TEE_ERROR_GENERIC;
	const fdt32_t *cuint = NULL;
	struct dt_node_info info = { };
	struct io_pa_va addr = { };

	fdt_fill_device_info(fdt, &info, node);
	assert(info.reg != DT_INFO_INVALID_REG &&
	       info.reg_size != DT_INFO_INVALID_REG_SIZE);

	addr.pa = info.reg;
	ipcc_d->base = io_pa_or_va_secure(&addr, info.reg_size);
	assert(ipcc_d->base);

	/* Gate the IP */
	res = clk_dt_get_by_index(fdt, node, 0, &ipcc_d->ipcc_clock);
	if (res)
		return res;

	cuint = fdt_getprop(fdt, node, "st,protreg", &lenp);
	if (!cuint)
		panic("No RIF configuration available");

	ipcc_d->nb_channels_cfg = (unsigned int)(lenp / sizeof(uint32_t));
	assert(ipcc_d->nb_channels_cfg <= (IPCC_NB_MAX_RIF_CHAN * 2));

	ipcc_d->conf_data.cid_confs = calloc(IPCC_NB_MAX_RIF_CHAN * 2,
					     sizeof(uint32_t));
	ipcc_d->conf_data.sec_conf = calloc(1, sizeof(uint32_t));
	ipcc_d->conf_data.priv_conf = calloc(1, sizeof(uint32_t));
	ipcc_d->conf_data.access_mask = calloc(1, sizeof(uint32_t));
	assert(ipcc_d->conf_data.cid_confs && ipcc_d->conf_data.sec_conf &&
	       ipcc_d->conf_data.priv_conf && ipcc_d->conf_data.access_mask);

	for (i = 0; i < ipcc_d->nb_channels_cfg; i++)
		stm32_rif_parse_cfg(fdt32_to_cpu(cuint[i]), &ipcc_d->conf_data,
				    IPCC_NB_MAX_CID_SUPPORTED,
				    IPCC_NB_MAX_RIF_CHAN * 2);

	return TEE_SUCCESS;
}

static TEE_Result stm32_ipcc_probe(const void *fdt, int node,
				   const void *compat_data __unused)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct ipcc_pdata *ipcc_d = NULL;
	bool is_tdcid = false;

	res = stm32_rifsc_check_tdcid(&is_tdcid);
	if (res)
		return res;

	ipcc_d = calloc(1, sizeof(*ipcc_d));
	if (!ipcc_d)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = parse_dt(fdt, node, ipcc_d);
	if (res)
		goto err;

	res = clk_enable(ipcc_d->ipcc_clock);
	if (res)
		panic("Cannot access IPCC clock");

	apply_rif_config(ipcc_d, is_tdcid);

	clk_disable(ipcc_d->ipcc_clock);

	STAILQ_INSERT_TAIL(&ipcc_list, ipcc_d, link);

	register_pm_core_service_cb(stm32_ipcc_pm, ipcc_d, "stm32-ipcc");

	return res;

err:
	/* Free all allocated resources */
	free(ipcc_d->conf_data.access_mask);
	free(ipcc_d->conf_data.cid_confs);
	free(ipcc_d->conf_data.priv_conf);
	free(ipcc_d->conf_data.sec_conf);
	free(ipcc_d);

	return res;
}

static const struct dt_device_match stm32_ipcc_match_table[] = {
	{ .compatible = "st,stm32mp25-ipcc" },
	{ }
};

DEFINE_DT_DRIVER(stm32_ipcc_dt_driver) = {
	.name = "st,stm32mp-ipcc",
	.match_table = stm32_ipcc_match_table,
	.probe = stm32_ipcc_probe,
};
