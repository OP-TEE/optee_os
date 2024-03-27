// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2022-2024, STMicroelectronics
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

#define _HPDMA_SECCFGR			U(0x000)
#define _HPDMA_PRIVCFGR			U(0x004)
#define _HPDMA_RCFGLOCKR		U(0x008)
#define _HPDMA_CIDCFGR(x)		(U(0x054) + U(0x080) * (x))
#define _HPDMA_SEMCR(x)			(U(0x058) + U(0x080) * (x))

/*
 * CFGR register bitfields
 */
#define _HPDMA_CFGR_ENABLE		BIT(31)

/*
 * CIDCFGR register bitfields
 */
#define _HPDMA_CIDCFGR_SEMWL_MASK	GENMASK_32(23, 16)
#define _HPDMA_CIDCFGR_SCID_MASK	GENMASK_32(5, 4)
#define _HPDMA_CIDCFGR_CONF_MASK	(_CIDCFGR_CFEN |	 \
					 _CIDCFGR_SEMEN |	 \
					 _HPDMA_CIDCFGR_SCID_MASK |\
					 _HPDMA_CIDCFGR_SEMWL_MASK)

/*
 * PRIVCFGR register bitfields
 */
#define _HPDMA_PRIVCFGR_MASK		GENMASK_32(15, 0)

/*
 * RCFGLOCKR register bitfields
 */
#define _HPDMA_RCFGLOCKR_MASK		GENMASK_32(15, 0)

/*
 * SECCFGR register bitfields
 */
#define _HPDMA_SECCFGR_EN		BIT(0)
#define _HPDMA_SECCFGR_MASK		GENMASK_32(15, 0)

/*
 * SEMCR register bitfields
 */
#define _HPDMA_SEMCR_SCID_MASK		GENMASK_32(5, 4)
#define _HPDMA_SEMCR_SCID_SHIFT		U(4)

/*
 * Miscellaneous
 */

#define HPDMA_RIF_CHANNELS		U(16)

#define HPDMA_NB_MAX_CID_SUPPORTED	U(3)

struct hpdma_pdata {
	struct clk *hpdma_clock;
	struct rif_conf_data conf_data;
	unsigned int nb_channels;
	vaddr_t base;

	SLIST_ENTRY(hpdma_pdata) link;
};

static SLIST_HEAD(, hpdma_pdata) hpdma_list =
		SLIST_HEAD_INITIALIZER(hpdma_list);

/* This function expects HPDMA bus clock is enabled */
static TEE_Result apply_rif_config(struct hpdma_pdata *hpdma_d, bool is_tdcid)
{
	TEE_Result res = TEE_ERROR_ACCESS_DENIED;
	uint32_t cidcfgr = 0;
	unsigned int i = 0;

	for (i = 0; i < HPDMA_RIF_CHANNELS; i++) {
		if (!(BIT(i) & hpdma_d->conf_data.access_mask[0]))
			continue;
		/*
		 * When TDCID, OP-TEE should be the one to set the CID filtering
		 * configuration. Clearing previous configuration prevents
		 * undesired events during the only legitimate configuration.
		 */
		if (is_tdcid)
			io_clrbits32(hpdma_d->base + _HPDMA_CIDCFGR(i),
				     _HPDMA_CIDCFGR_CONF_MASK);

		cidcfgr = io_read32(hpdma_d->base + _HPDMA_CIDCFGR(i));

		/* Check if the channel is in semaphore mode */
		if (!stm32_rif_semaphore_enabled_and_ok(cidcfgr, RIF_CID1))
			continue;

		/* If not TDCID, we want to acquire semaphores assigned to us */
		res = stm32_rif_acquire_semaphore(hpdma_d->base +
						  _HPDMA_SEMCR(i),
						  HPDMA_NB_MAX_CID_SUPPORTED);
		if (res) {
			EMSG("Couldn't acquire semaphore for channel %u", i);
			return res;
		}
	}

	/* Security and privilege RIF configuration */
	io_clrsetbits32(hpdma_d->base + _HPDMA_PRIVCFGR, _HPDMA_PRIVCFGR_MASK &
			hpdma_d->conf_data.access_mask[0],
			hpdma_d->conf_data.priv_conf[0]);
	io_clrsetbits32(hpdma_d->base + _HPDMA_SECCFGR, _HPDMA_SECCFGR_MASK &
			hpdma_d->conf_data.access_mask[0],
			hpdma_d->conf_data.sec_conf[0]);

	/* Skip CID/semaphore configuration if not in TDCID state. */
	if (!is_tdcid)
		goto end;

	for (i = 0; i < HPDMA_RIF_CHANNELS; i++) {
		if (!(BIT(i) & hpdma_d->conf_data.access_mask[0]))
			continue;

		io_clrsetbits32(hpdma_d->base + _HPDMA_CIDCFGR(i),
				_HPDMA_CIDCFGR_CONF_MASK,
				hpdma_d->conf_data.cid_confs[i]);

		cidcfgr = io_read32(hpdma_d->base + _HPDMA_CIDCFGR(i));

		/*
		 * Take semaphore if the resource is in semaphore
		 * mode and secured.
		 */
		if (!stm32_rif_semaphore_enabled_and_ok(cidcfgr, RIF_CID1) ||
		    !(io_read32(hpdma_d->base + _HPDMA_SECCFGR) & BIT(i))) {
			res =
			stm32_rif_release_semaphore(hpdma_d->base +
						    _HPDMA_SEMCR(i),
						    HPDMA_NB_MAX_CID_SUPPORTED);
			if (res) {
				EMSG("Couldn't release semaphore for res%u", i);
				return TEE_ERROR_ACCESS_DENIED;
			}
		} else {
			res =
			stm32_rif_acquire_semaphore(hpdma_d->base +
						    _HPDMA_SEMCR(i),
						    HPDMA_NB_MAX_CID_SUPPORTED);
			if (res) {
				EMSG("Couldn't acquire semaphore for res%u", i);
				return TEE_ERROR_ACCESS_DENIED;
			}
		}
	}

	/*
	 * Lock RIF configuration if configured. This cannot be undone until
	 * next reset.
	 */
	io_clrsetbits32(hpdma_d->base + _HPDMA_RCFGLOCKR, _HPDMA_RCFGLOCKR_MASK,
			hpdma_d->conf_data.lock_conf[0]);

end:
	if (IS_ENABLED(CFG_TEE_CORE_DEBUG)) {
		/* Check that RIF config are applied, panic otherwise */
		if ((io_read32(hpdma_d->base + _HPDMA_PRIVCFGR) &
		     hpdma_d->conf_data.access_mask[0]) !=
		    hpdma_d->conf_data.priv_conf[0])
			panic("HPDMA channel priv conf is incorrect");

		if ((io_read32(hpdma_d->base + _HPDMA_SECCFGR) &
		     hpdma_d->conf_data.access_mask[0]) !=
		    hpdma_d->conf_data.sec_conf[0])
			panic("HPDMA channel sec conf is incorrect");
	}

	return TEE_SUCCESS;
}

static TEE_Result parse_dt(const void *fdt, int node,
			   struct hpdma_pdata *hpdma_d)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	unsigned int i = 0;
	int lenp = 0;
	const fdt32_t *cuint = NULL;
	struct dt_node_info info = { };
	struct io_pa_va addr = { };

	fdt_fill_device_info(fdt, &info, node);
	assert(info.reg != DT_INFO_INVALID_REG &&
	       info.reg_size != DT_INFO_INVALID_REG_SIZE);

	addr.pa = info.reg;
	hpdma_d->base = io_pa_or_va_secure(&addr, info.reg_size);

	/* Gate the IP */
	res = clk_dt_get_by_index(fdt, node, 0, &hpdma_d->hpdma_clock);
	if (res)
		return res;

	cuint = fdt_getprop(fdt, node, "st,protreg", &lenp);
	if (!cuint)
		panic("No RIF configuration available");

	hpdma_d->nb_channels = (unsigned int)(lenp / sizeof(uint32_t));
	assert(hpdma_d->nb_channels <= HPDMA_RIF_CHANNELS);

	hpdma_d->conf_data.cid_confs = calloc(HPDMA_RIF_CHANNELS,
					      sizeof(uint32_t));
	hpdma_d->conf_data.sec_conf = calloc(1, sizeof(uint32_t));
	hpdma_d->conf_data.priv_conf = calloc(1, sizeof(uint32_t));
	hpdma_d->conf_data.access_mask = calloc(1, sizeof(uint32_t));
	hpdma_d->conf_data.lock_conf = calloc(1, sizeof(uint32_t));
	assert(hpdma_d->conf_data.cid_confs && hpdma_d->conf_data.sec_conf &&
	       hpdma_d->conf_data.priv_conf && hpdma_d->conf_data.access_mask &&
	       hpdma_d->conf_data.lock_conf);

	for (i = 0; i < hpdma_d->nb_channels; i++)
		stm32_rif_parse_cfg(fdt32_to_cpu(cuint[i]), &hpdma_d->conf_data,
				    HPDMA_NB_MAX_CID_SUPPORTED,
				    HPDMA_RIF_CHANNELS);

	return TEE_SUCCESS;
}

static void stm32_hpdma_pm_resume(struct hpdma_pdata *hpdma)
{
	if (apply_rif_config(hpdma, true))
		panic("Failed to resume HPDMA");
}

static void stm32_hpdma_pm_suspend(struct hpdma_pdata *hpdma)
{
	size_t i = 0;

	for (i = 0; i < HPDMA_RIF_CHANNELS; i++)
		hpdma->conf_data.cid_confs[i] = io_read32(hpdma->base +
							  _HPDMA_CIDCFGR(i)) &
						_HPDMA_CIDCFGR_CONF_MASK;

	hpdma->conf_data.priv_conf[0] = io_read32(hpdma->base +
						  _HPDMA_PRIVCFGR) &
					_HPDMA_PRIVCFGR_MASK;
	hpdma->conf_data.sec_conf[0] = io_read32(hpdma->base +
						 _HPDMA_SECCFGR) &
				       _HPDMA_SECCFGR_MASK;
	hpdma->conf_data.lock_conf[0] = io_read32(hpdma->base +
						  _HPDMA_RCFGLOCKR) &
					_HPDMA_RCFGLOCKR_MASK;

	/*
	 * The access mask is modified to restore the conf for all
	 * resources.
	 */
	hpdma->conf_data.access_mask[0] = GENMASK_32(HPDMA_RIF_CHANNELS - 1, 0);
}

static TEE_Result
stm32_hpdma_pm(enum pm_op op, unsigned int pm_hint,
	       const struct pm_callback_handle *pm_handle)
{
	struct hpdma_pdata *hpdma = pm_handle->handle;
	TEE_Result res = TEE_ERROR_GENERIC;
	bool is_tdcid = false;

	res = stm32_rifsc_check_tdcid(&is_tdcid);
	if (res)
		panic();

	if (!PM_HINT_IS_STATE(pm_hint, CONTEXT) || !is_tdcid)
		return TEE_SUCCESS;

	res = clk_enable(hpdma->hpdma_clock);
	if (res)
		return res;

	if (op == PM_OP_RESUME)
		stm32_hpdma_pm_resume(hpdma);
	else
		stm32_hpdma_pm_suspend(hpdma);

	clk_disable(hpdma->hpdma_clock);

	return TEE_SUCCESS;
}

static TEE_Result stm32_hpdma_probe(const void *fdt, int node,
				    const void *compat_data __unused)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct hpdma_pdata *hpdma_d = NULL;
	bool is_tdcid = false;

	res = stm32_rifsc_check_tdcid(&is_tdcid);
	if (res)
		return res;

	hpdma_d = calloc(1, sizeof(*hpdma_d));
	if (!hpdma_d)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = parse_dt(fdt, node, hpdma_d);
	if (res) {
		free(hpdma_d);
		return res;
	}

	if (clk_enable(hpdma_d->hpdma_clock))
		panic("Cannot access hpdma clock");

	res = apply_rif_config(hpdma_d, is_tdcid);
	if (res)
		panic("Failed to apply RIF config");

	clk_disable(hpdma_d->hpdma_clock);

	SLIST_INSERT_HEAD(&hpdma_list, hpdma_d, link);

	register_pm_core_service_cb(stm32_hpdma_pm, hpdma_d, "stm32-hpdma");

	return TEE_SUCCESS;
}

static const struct dt_device_match stm32_hpdma_match_table[] = {
	{ .compatible = "st,stm32-dma3" },
	{ }
};

DEFINE_DT_DRIVER(stm32_hpdma_dt_driver) = {
	.name = "st,stm32-hpdma",
	.match_table = stm32_hpdma_match_table,
	.probe = stm32_hpdma_probe,
};
