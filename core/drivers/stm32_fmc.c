// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021-2024, STMicroelectronics
 */

#include <arm.h>
#include <config.h>
#include <drivers/clk.h>
#include <drivers/clk_dt.h>
#include <drivers/stm32_gpio.h>
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

#define _FMC_CFGR			U(0x020)
#define _FMC_SECCFGR			U(0x300)
#define _FMC_PRIVCFGR			U(0x304)
#define _FMC_RCFGLOCKR			U(0x308)
#define _FMC_CIDCFGR(x)			(U(0x30C) + U(0x8) * (x))
#define _FMC_SEMCR(x)			(U(0x310) + U(0x8) * (x))
/*
 * CFGR register bitfields
 */
#define _FMC_CFGR_CLKDIV_MASK		GENMASK_32(19, 16)
#define _FMC_CFGR_CLKDIV_SHIFT		U(16)
#define _FMC_CFGR_CCLKEN		BIT(20)
#define _FMC_CFGR_ENABLE		BIT(31)

/*
 * CIDCFGR register bitfields
 */
#define _FMC_CIDCFGR_SEMWL_MASK		GENMASK_32(23, 16)
#define _FMC_CIDCFGR_SCID_MASK		GENMASK_32(6, 4)
#define _FMC_CIDCFGR_CONF_MASK		(_CIDCFGR_CFEN |	 \
					 _CIDCFGR_SEMEN |	 \
					 _FMC_CIDCFGR_SCID_MASK |\
					 _FMC_CIDCFGR_SEMWL_MASK)

/*
 * PRIVCFGR register bitfields
 */
#define _FMC_PRIVCFGR_MASK		GENMASK_32(5, 0)

/*
 * RCFGLOCKR register bitfields
 */
#define _FMC_RCFGLOCKR_MASK		GENMASK_32(5, 0)

/*
 * SECCFGR register bitfields
 */
#define _FMC_SECCFGR_EN			BIT(0)
#define _FMC_SECCFGR_MASK		GENMASK_32(5, 0)

/*
 * SEMCR register bitfields
 */
#define _FMC_SEMCR_SCID_MASK		GENMASK_32(7, 5)
#define _FMC_SEMCR_SCID_SHIFT		U(5)

/*
 * Miscellaneous
 */

#define FMC_RIF_CONTROLLERS		U(6)

#define FMC_NB_MAX_CID_SUPPORTED	U(7)

#define FMC_NSEC_PER_SEC		UL(1000000000)

struct fmc_pdata {
	struct clk *fmc_clock;
	struct pinctrl_state *pinctrl_d;
	struct pinctrl_state *pinctrl_s;
	struct rif_conf_data conf_data;
	unsigned int nb_controller;
	vaddr_t base;
	uint32_t clk_period_ns;
	bool cclken;
};

static struct fmc_pdata *fmc_d;

static bool fmc_controller_is_secure(uint8_t controller)
{
	return io_read32(fmc_d->base + _FMC_SECCFGR) & BIT(controller);
}

static TEE_Result apply_rif_config(void)
{
	TEE_Result res = TEE_ERROR_ACCESS_DENIED;
	uint32_t cidcfgr = 0;
	unsigned int i = 0;

	res = clk_enable(fmc_d->fmc_clock);
	if (res)
		panic("Cannot access FMC clock");

	for (i = 0; i < FMC_RIF_CONTROLLERS; i++) {
		if (!(BIT(i) & fmc_d->conf_data.access_mask[0]))
			continue;

		/*
		 * Whatever the TDCID state, try to clear the configurable part
		 * of the CIDCFGR register.
		 * If TDCID, register will be cleared, if not, the clear will
		 * be ignored.
		 * When TDCID, OP-TEE should be the one to set the CID filtering
		 * configuration. Clearing previous configuration prevents
		 * undesired events during the only legitimate configuration.
		 */
		io_clrbits32(fmc_d->base + _FMC_CIDCFGR(i),
			     _FMC_CIDCFGR_CONF_MASK);

		cidcfgr = io_read32(fmc_d->base + _FMC_CIDCFGR(i));

		/* Check if the controller is in semaphore mode */
		if (!stm32_rif_semaphore_enabled_and_ok(cidcfgr, RIF_CID1))
			continue;

		/* If not TDCID, we want to acquire semaphores assigned to us */
		res = stm32_rif_acquire_semaphore(fmc_d->base + _FMC_SEMCR(i),
						  FMC_NB_MAX_CID_SUPPORTED);
		if (res) {
			EMSG("Couldn't acquire semaphore for controller %u", i);
			clk_disable(fmc_d->fmc_clock);
			return res;
		}
	}

	/* Security and privilege RIF configuration */
	io_clrsetbits32(fmc_d->base + _FMC_PRIVCFGR, _FMC_PRIVCFGR_MASK,
			fmc_d->conf_data.priv_conf[0]);
	io_clrsetbits32(fmc_d->base + _FMC_SECCFGR, _FMC_SECCFGR_MASK,
			fmc_d->conf_data.sec_conf[0]);

	for (i = 0; i < FMC_RIF_CONTROLLERS; i++) {
		if (!(BIT(i) & fmc_d->conf_data.access_mask[0]))
			continue;

		io_clrsetbits32(fmc_d->base + _FMC_CIDCFGR(i),
				_FMC_CIDCFGR_CONF_MASK,
				fmc_d->conf_data.cid_confs[i]);

		cidcfgr = io_read32(fmc_d->base + _FMC_CIDCFGR(i));

		/*
		 * Take semaphore if the resource is in semaphore mode
		 * and secured
		 */
		if (!stm32_rif_semaphore_enabled_and_ok(cidcfgr, RIF_CID1) ||
		    !(io_read32(fmc_d->base + _FMC_SECCFGR) & BIT(i))) {
			res =
			stm32_rif_release_semaphore(fmc_d->base + _FMC_SEMCR(i),
						    FMC_NB_MAX_CID_SUPPORTED);
			if (res) {
				EMSG("Couldn't release semaphore for res%u", i);
				clk_disable(fmc_d->fmc_clock);
				return res;
			}
		} else {
			res =
			stm32_rif_acquire_semaphore(fmc_d->base + _FMC_SEMCR(i),
						    FMC_NB_MAX_CID_SUPPORTED);
			if (res) {
				EMSG("Couldn't acquire semaphore for res%u", i);
				clk_disable(fmc_d->fmc_clock);
				return res;
			}
		}
	}

	/*
	 * Lock RIF configuration if configured. This cannot be undone until
	 * next reset.
	 */
	io_clrsetbits32(fmc_d->base + _FMC_RCFGLOCKR, _FMC_RCFGLOCKR_MASK,
			fmc_d->conf_data.lock_conf[0]);

	if (IS_ENABLED(CFG_TEE_CORE_DEBUG)) {
		/* Check that RIF config are applied, panic otherwise */
		if ((io_read32(fmc_d->base + _FMC_PRIVCFGR) &
		     fmc_d->conf_data.access_mask[0]) !=
		    fmc_d->conf_data.priv_conf[0]) {
			EMSG("FMC controller priv conf is incorrect");
			panic();
		}

		if ((io_read32(fmc_d->base + _FMC_SECCFGR) &
		     fmc_d->conf_data.access_mask[0]) !=
		    fmc_d->conf_data.sec_conf[0]) {
			EMSG("FMC controller sec conf is incorrect");
			panic();
		}
	}

	/* Disable the clock to allow RCC RIF re-configuration on this clock */
	clk_disable(fmc_d->fmc_clock);

	return TEE_SUCCESS;
}

static TEE_Result parse_dt(const void *fdt, int node)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t rif_conf = 0;
	unsigned int i = 0;
	int lenp = 0;
	const fdt32_t *cuint = NULL;
	struct dt_node_info info = { };
	struct io_pa_va addr = { };
	int ctrl_node = 0;

	fdt_fill_device_info(fdt, &info, node);
	assert(info.reg != DT_INFO_INVALID_REG &&
	       info.reg_size != DT_INFO_INVALID_REG_SIZE);

	addr.pa = info.reg;
	fmc_d->base = io_pa_or_va(&addr, info.reg_size);

	res = clk_dt_get_by_index(fdt, node, 0, &fmc_d->fmc_clock);
	if (res)
		return res;

	res = pinctrl_get_state_by_name(fdt, node, "default",
					&fmc_d->pinctrl_d);
	if (res && res != TEE_ERROR_ITEM_NOT_FOUND)
		return res;

	res = pinctrl_get_state_by_name(fdt, node, "sleep",
					&fmc_d->pinctrl_s);
	if (res && res != TEE_ERROR_ITEM_NOT_FOUND)
		return res;

	cuint = fdt_getprop(fdt, node, "st,protreg", &lenp);
	if (!cuint)
		panic("No RIF configuration available");

	fmc_d->nb_controller = (unsigned int)(lenp / sizeof(uint32_t));
	assert(fmc_d->nb_controller <= FMC_RIF_CONTROLLERS);

	fmc_d->conf_data.cid_confs = calloc(FMC_RIF_CONTROLLERS,
					    sizeof(uint32_t));
	fmc_d->conf_data.sec_conf = calloc(1, sizeof(uint32_t));
	fmc_d->conf_data.priv_conf = calloc(1, sizeof(uint32_t));
	fmc_d->conf_data.lock_conf = calloc(1, sizeof(uint32_t));
	fmc_d->conf_data.access_mask = calloc(1, sizeof(uint32_t));
	assert(fmc_d->conf_data.cid_confs && fmc_d->conf_data.sec_conf &&
	       fmc_d->conf_data.priv_conf && fmc_d->conf_data.access_mask);

	for (i = 0; i < fmc_d->nb_controller; i++) {
		rif_conf = fdt32_to_cpu(cuint[i]);

		stm32_rif_parse_cfg(rif_conf, &fmc_d->conf_data,
				    FMC_NB_MAX_CID_SUPPORTED,
				    FMC_RIF_CONTROLLERS);
	}

	fdt_for_each_subnode(ctrl_node, fdt, node) {
		int status = fdt_get_status(fdt, ctrl_node);
		uint32_t bank = 0;

		if (status == DT_STATUS_DISABLED)
			continue;

		if (fdt_read_uint32(fdt, ctrl_node, "reg", &bank) < 0)
			return TEE_ERROR_BAD_PARAMETERS;

		if (bank != 0)
			continue;

		if (fdt_getprop(fdt, ctrl_node,
				"st,fmc2-ebi-cs-cclk-enable", NULL))
			fmc_d->cclken = true;

		if (!fmc_d->cclken)
			continue;

		if (fdt_read_uint32(fdt, ctrl_node,
				    "st,fmc2-ebi-cs-clk-period-ns",
				    &fmc_d->clk_period_ns) < 0)
			return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_SUCCESS;
}

static TEE_Result __maybe_unused check_fmc_rif_conf(void)
{
	unsigned int i = 0;
	TEE_Result res = TEE_ERROR_GENERIC;

	res = clk_enable(fmc_d->fmc_clock);
	if (res)
		panic("Cannot access FMC clock");

	if (fmc_controller_is_secure(0))
		goto end;

	for (i = 1; i < fmc_d->nb_controller; i++) {
		uint32_t cidcfgr = io_read32(fmc_d->base + _FMC_CIDCFGR(i));
		uint32_t semcr = io_read32(fmc_d->base + _FMC_SEMCR(i));

		/* Check if a controller is secure */
		if (fmc_controller_is_secure(i)) {
			res = TEE_ERROR_BAD_STATE;
			goto end;
		}

		/*
		 * Check if a controller is shared with incorrect CID
		 * (!= RIF_CID1)
		 */
		res = stm32_rif_check_access(cidcfgr, semcr,
					     FMC_NB_MAX_CID_SUPPORTED,
					     RIF_CID1);
		if (res)
			break;
	}

end:
	clk_disable(fmc_d->fmc_clock);

	return res;
}

static void configure_fmc(void)
{
	uint32_t cidcfgr = 0;
	uint32_t semcr = 0;

	if (clk_enable(fmc_d->fmc_clock))
		panic("Cannot access FMC clock");

	semcr = io_read32(fmc_d->base + _FMC_SEMCR(0));
	cidcfgr = io_read32(fmc_d->base + _FMC_CIDCFGR(0));

	/*
	 * If OP-TEE doesn't have access to the controller 0,
	 * then we don't want to try to enable the FMC.
	 */
	if (stm32_rif_check_access(cidcfgr, semcr,
				   FMC_NB_MAX_CID_SUPPORTED, RIF_CID1))
		goto end;

	/* Check controller 0 access */
	if (!fmc_controller_is_secure(0)) {
		DMSG("Controller 0 non-secure, FMC not enabled");
		goto end;
	}

	if (cidcfgr & _CIDCFGR_SEMEN &&
	    stm32_rif_acquire_semaphore(fmc_d->base + _FMC_SEMCR(0),
					FMC_NB_MAX_CID_SUPPORTED))
		panic("Couldn't acquire controller 0 semaphore");

	if (fmc_d->pinctrl_d && pinctrl_apply_state(fmc_d->pinctrl_d))
		panic("Could not apply FMC pinctrl");

	if (fmc_d->cclken) {
		unsigned long hclk = clk_get_rate(fmc_d->fmc_clock);
		unsigned long hclkp = FMC_NSEC_PER_SEC / (hclk / 1000);
		unsigned long timing = DIV_ROUND_UP(fmc_d->clk_period_ns * 1000,
						    hclkp);
		uint32_t clk_div = SHIFT_U32(1, _FMC_CFGR_CLKDIV_SHIFT);

		if (timing > 1) {
			timing--;
			if (timing >
			    _FMC_CFGR_CLKDIV_MASK >> _FMC_CFGR_CLKDIV_SHIFT)
				clk_div = _FMC_CFGR_CLKDIV_MASK;
			else
				clk_div = SHIFT_U32(timing,
						    _FMC_CFGR_CLKDIV_SHIFT);
		}

		io_clrsetbits32(fmc_d->base + _FMC_CFGR,
				_FMC_CFGR_CLKDIV_MASK | _FMC_CFGR_CCLKEN,
				clk_div | _FMC_CFGR_CCLKEN);
	}

	/* Set the FMC enable BIT */
	io_setbits32(fmc_d->base + _FMC_CFGR, _FMC_CFGR_ENABLE);

end:
	clk_disable(fmc_d->fmc_clock);
}

static void fmc_setup(void)
{
	if (apply_rif_config())
		panic("Failed to apply rif_config");

	/* Sanity check for FMC RIF config */
	assert(check_fmc_rif_conf());

	configure_fmc();
}

static void fmc_suspend(void)
{
	unsigned int i = 0;

	if (clk_enable(fmc_d->fmc_clock))
		panic("Cannot access FMC clock");

	if (fmc_controller_is_secure(0) && fmc_d->pinctrl_s &&
	    pinctrl_apply_state(fmc_d->pinctrl_s))
		panic();

	for (i = 0; i < FMC_RIF_CONTROLLERS; i++)
		fmc_d->conf_data.cid_confs[i] =
			io_read32(fmc_d->base + _FMC_CIDCFGR(i)) &
			_FMC_CIDCFGR_CONF_MASK;

	fmc_d->conf_data.priv_conf[0] =
		io_read32(fmc_d->base + _FMC_PRIVCFGR) & _FMC_PRIVCFGR_MASK;
	fmc_d->conf_data.sec_conf[0] =
		io_read32(fmc_d->base + _FMC_SECCFGR) & _FMC_SECCFGR_MASK;
	fmc_d->conf_data.lock_conf[0] =
		io_read32(fmc_d->base + _FMC_RCFGLOCKR) & _FMC_RCFGLOCKR_MASK;
	fmc_d->conf_data.access_mask[0] =
		GENMASK_32(FMC_RIF_CONTROLLERS - 1, 0);

	clk_disable(fmc_d->fmc_clock);
}

static TEE_Result fmc_pm(enum pm_op op, unsigned int pm_hint,
			 const struct pm_callback_handle *pm_handle __unused)
{
	if (pm_hint != PM_HINT_CONTEXT_STATE)
		return TEE_SUCCESS;

	if (op == PM_OP_RESUME)
		fmc_setup();
	else
		fmc_suspend();

	return TEE_SUCCESS;
}

static TEE_Result fmc_probe(const void *fdt, int node,
			    const void *compat_data __unused)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	fmc_d = calloc(1, sizeof(*fmc_d));
	if (!fmc_d)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = parse_dt(fdt, node);
	if (res)
		goto err;

	fmc_setup();

	register_pm_core_service_cb(fmc_pm, NULL, "stm32-fmc");

	return TEE_SUCCESS;
err:
	/* Free all allocated resources */
	free(fmc_d->conf_data.cid_confs);
	free(fmc_d->conf_data.sec_conf);
	free(fmc_d->conf_data.priv_conf);
	free(fmc_d->conf_data.access_mask);
	free(fmc_d);

	return res;
}

static const struct dt_device_match stm32_fmc_match_table[] = {
	{ .compatible = "st,stm32mp25-fmc2-ebi" },
	{ }
};

DEFINE_DT_DRIVER(stm32_fmc_dt_driver) = {
	.name = "stm32_fmc",
	.match_table = stm32_fmc_match_table,
	.probe = fmc_probe,
};
