// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, STMicroelectronics
 */

#include <arm.h>
#include <config.h>
#include <drivers/clk.h>
#include <drivers/clk_dt.h>
#include <drivers/stm32_rif.h>
#include <drivers/stm32mp_dt_bindings.h>
#include <drivers/stm32mp2_pwr.h>
#include <io.h>
#include <kernel/boot.h>
#include <kernel/delay.h>
#include <kernel/dt.h>
#include <kernel/dt_driver.h>
#include <kernel/panic.h>
#include <kernel/pm.h>
#include <libfdt.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stm32_util.h>
#include <trace.h>

/*PWR control registers */
#define _PWR_CR2			U(0x004)
#define _PWR_CR5			U(0x010)
#define _PWR_CR6			U(0x014)

/* Non-shareable resources registers */
#define _PWR_RSECCFGR			U(0x100)
#define _PWR_RPRIVCFGR			U(0x104)
#define _PWR_R_CIDCFGR(x)		(U(0x108) + U(0x4) * (x))

/* Shareable resources registers */
#define _PWR_WIOSECCFGR			U(0x180)
#define _PWR_WIOPRIVCFGR		U(0x184)
#define _PWR_WIO_CIDCFGR(x)		(U(0x188) + U(0x8) * ((x) - 1))
#define _PWR_WIO_SEMCR(x)		(U(0x18C) + U(0x8) * ((x) - 1))

/*PWR_CR2 bitfields*/
#define _PWR_CR2_MONEN			BIT(0)

/*PWR_CR5 bitfields*/
#define _PWR_CR5_VCOREMONEN		BIT(0)

/*PWR_CR6 bitfields*/
#define _PWR_CR6_VCPUMONEN		BIT(0)

/*
 * CIDCFGR register bitfields
 */
#define _PWR_CIDCFGR_SEMWL_MASK		GENMASK_32(23, 16)
#define _PWR_CIDCFGR_SCID_MASK		GENMASK_32(6, 4)
#define _PWR_CIDCFGR_W_CONF_MASK	(_CIDCFGR_CFEN |	 \
					 _CIDCFGR_SEMEN |	 \
					 _PWR_CIDCFGR_SCID_MASK |\
					 _PWR_CIDCFGR_SEMWL_MASK)
#define _PWR_CIDCFGR_R_CONF_MASK	(_CIDCFGR_CFEN |	 \
					 _PWR_CIDCFGR_SCID_MASK)

/*
 * PRIVCFGR register bitfields
 */
#define _PWR_R_PRIVCFGR_MASK		GENMASK_32(6, 0)
#define _PWR_WIO_PRIVCFGR_C_MASK	GENMASK_32(12, 7)
#define _PWR_WIO_PRIVCFGR_MASK		GENMASK_32(5, 0)
/*
 * SECCFGR register bitfields
 */
#define _PWR_R_SECCFGR_MASK		GENMASK_32(6, 0)
#define _PWR_WIO_SECCFGR_C_MASK		GENMASK_32(12, 7)
#define _PWR_WIO_SECCFGR_MASK		GENMASK_32(5, 0)

/*
 * SEMCR register bitfields
 */
#define _PWR_SEMCR_SCID_MASK		GENMASK_32(6, 4)
#define _PWR_SEMCR_SCID_SHIFT		U(4)

#define _PWR_NB_RESOURCES		U(13)
#define _PWR_NB_NS_RESOURCES		U(7)
#define _PWR_NB_MAX_CID_SUPPORTED	U(7)

struct pwr_pdata {
	vaddr_t base;
	uint8_t nb_ressources;
	struct rif_conf_data *conf_data;
};

static struct pwr_pdata *pwr_d;

vaddr_t stm32_pwr_base(void)
{
	static struct io_pa_va base = { .pa = PWR_BASE };

	if (!pwr_d)
		return io_pa_or_va_secure(&base, 1);

	assert(pwr_d->base);

	return pwr_d->base;
}

static TEE_Result handle_available_semaphores(void)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t cidcfgr = 0;
	unsigned int i = 0;

	for (i = _PWR_NB_NS_RESOURCES ; i < _PWR_NB_RESOURCES; i++) {
		unsigned int wio_offset = i + 1 - _PWR_NB_NS_RESOURCES;
		vaddr_t reg_offset = pwr_d->base + _PWR_WIO_SEMCR(wio_offset);

		if (!(BIT(i) & pwr_d->conf_data->access_mask[0]))
			continue;

		cidcfgr = io_read32(pwr_d->base + _PWR_WIO_CIDCFGR(wio_offset));

		if (!stm32_rif_semaphore_enabled_and_ok(cidcfgr, RIF_CID1))
			continue;

		if (!(io_read32(pwr_d->base + _PWR_WIOSECCFGR) &
		      BIT(wio_offset - 1))) {
			res = stm32_rif_release_semaphore(reg_offset,
							  MAX_CID_SUPPORTED);
			if (res) {
				EMSG("Cannot release semaphore for resource %"
				     PRIu32, wio_offset);
				return res;
			}
		} else {
			res = stm32_rif_acquire_semaphore(reg_offset,
							  MAX_CID_SUPPORTED);
			if (res) {
				EMSG("Cannot acquire semaphore for resource %"
				     PRIu32, wio_offset);
				return res;
			}
		}
	}

	return TEE_SUCCESS;
}

static TEE_Result apply_rif_config(bool is_tdcid)
{
	TEE_Result res = TEE_ERROR_ACCESS_DENIED;
	uint32_t r_priv = 0;
	uint32_t r_sec = 0;
	uint32_t wio_priv = 0;
	uint32_t wio_sec = 0;
	unsigned int wio_offset = 0;
	unsigned int i = 0;

	if (!pwr_d->conf_data)
		return TEE_SUCCESS;

	if (is_tdcid) {
		for (i = 0; i < _PWR_NB_RESOURCES; i++) {
			if (!(BIT(i) & pwr_d->conf_data->access_mask[0]))
				continue;

			/*
			 * When TDCID, OP-TEE should be the one to set the CID
			 * filtering configuration. Clearing previous
			 * configuration prevents undesired events during the
			 * only legitimate configuration.
			 */
			if (i < _PWR_NB_NS_RESOURCES) {
				io_clrbits32(pwr_d->base + _PWR_R_CIDCFGR(i),
					     _PWR_CIDCFGR_R_CONF_MASK);
			} else {
				wio_offset = i + 1 - _PWR_NB_NS_RESOURCES;
				io_clrbits32(pwr_d->base +
					     _PWR_WIO_CIDCFGR(wio_offset),
					     _PWR_CIDCFGR_W_CONF_MASK);
			}
		}
	} else {
		res = handle_available_semaphores();
		if (res)
			panic();
	}

	/* Separate non-shareable resources RIF configuration */
	r_priv = pwr_d->conf_data->priv_conf[0] & _PWR_R_PRIVCFGR_MASK;
	r_sec = pwr_d->conf_data->sec_conf[0] & _PWR_R_SECCFGR_MASK;

	wio_priv = (pwr_d->conf_data->priv_conf[0] &
		    _PWR_WIO_PRIVCFGR_C_MASK) >> _PWR_NB_NS_RESOURCES;
	wio_sec = (pwr_d->conf_data->sec_conf[0] & _PWR_WIO_SECCFGR_C_MASK) >>
		  _PWR_NB_NS_RESOURCES;

	/* Security and privilege RIF configuration */
	io_clrsetbits32(pwr_d->base + _PWR_RPRIVCFGR, _PWR_R_PRIVCFGR_MASK,
			r_priv);
	io_clrsetbits32(pwr_d->base + _PWR_RSECCFGR, _PWR_R_SECCFGR_MASK,
			r_sec);
	io_clrsetbits32(pwr_d->base + _PWR_WIOPRIVCFGR, _PWR_WIO_PRIVCFGR_MASK,
			wio_priv);
	io_clrsetbits32(pwr_d->base + _PWR_WIOSECCFGR, _PWR_WIO_SECCFGR_MASK,
			wio_sec);

	if (!is_tdcid) {
		res = TEE_SUCCESS;
		goto out;
	}

	for (i = 0; i < _PWR_NB_RESOURCES; i++) {
		if (!(BIT(i) & pwr_d->conf_data->access_mask[0]))
			continue;

		if (i < _PWR_NB_NS_RESOURCES) {
			io_clrsetbits32(pwr_d->base + _PWR_R_CIDCFGR(i),
					_PWR_CIDCFGR_R_CONF_MASK,
					pwr_d->conf_data->cid_confs[i]);
		} else {
			wio_offset = i + 1 - _PWR_NB_NS_RESOURCES;
			io_clrsetbits32(pwr_d->base +
					_PWR_WIO_CIDCFGR(wio_offset),
					_PWR_CIDCFGR_W_CONF_MASK,
					pwr_d->conf_data->cid_confs[i]);
		}
	}

	res = handle_available_semaphores();
	if (res)
		panic();

out:
	if (IS_ENABLED(CFG_TEE_CORE_DEBUG)) {
		/* Check that RIF config are applied, panic otherwise */
		if ((io_read32(pwr_d->base + _PWR_RPRIVCFGR) &
		     pwr_d->conf_data->access_mask[0]) != r_priv) {
			EMSG("pwr r resources priv conf is incorrect");
			panic();
		}

		if ((io_read32(pwr_d->base + _PWR_WIOPRIVCFGR) &
		     (pwr_d->conf_data->access_mask[0] >>
		      _PWR_NB_NS_RESOURCES)) != wio_priv) {
			EMSG("pwr wio resources priv conf is incorrect");
			panic();
		}

		if ((io_read32(pwr_d->base + _PWR_RSECCFGR) &
		     pwr_d->conf_data->access_mask[0]) != r_sec) {
			EMSG("pwr r resources sec conf is incorrect");
			panic();
		}

		if ((io_read32(pwr_d->base + _PWR_WIOSECCFGR) &
		     (pwr_d->conf_data->access_mask[0] >>
		      _PWR_NB_NS_RESOURCES)) != wio_sec) {
			EMSG("pwr wio resources sec conf is incorrect");
			panic();
		}
	}

	return res;
}

static void parse_dt(const void *fdt, int node)
{
	unsigned int i = 0;
	int lenp = 0;
	const fdt32_t *cuint = NULL;
	struct io_pa_va addr = { };
	size_t reg_size = 0;

	if (fdt_reg_info(fdt, node, &addr.pa, &reg_size))
		panic("Failed to get STM32MP2 PWR register info");

	pwr_d->base = io_pa_or_va_secure(&addr, reg_size);

	cuint = fdt_getprop(fdt, node, "st,protreg", &lenp);
	if (!cuint) {
		DMSG("No RIF configuration available");
		return;
	}

	pwr_d->nb_ressources = (unsigned int)(lenp / sizeof(uint32_t));
	assert(pwr_d->nb_ressources <= _PWR_NB_RESOURCES);

	pwr_d->conf_data = calloc(1, sizeof(*pwr_d->conf_data));
	if (!pwr_d->conf_data)
		panic();

	pwr_d->conf_data->cid_confs = calloc(_PWR_NB_RESOURCES,
					     sizeof(uint32_t));
	pwr_d->conf_data->sec_conf = calloc(1, sizeof(uint32_t));
	pwr_d->conf_data->priv_conf = calloc(1, sizeof(uint32_t));
	pwr_d->conf_data->access_mask = calloc(1, sizeof(uint32_t));
	if (!pwr_d->conf_data->cid_confs || !pwr_d->conf_data->sec_conf ||
	    !pwr_d->conf_data->priv_conf || !pwr_d->conf_data->access_mask)
		panic("Missing memory capacity for PWR RIF configuration");

	for (i = 0; i < pwr_d->nb_ressources; i++)
		stm32_rif_parse_cfg(fdt32_to_cpu(cuint[i]), pwr_d->conf_data,
				    _PWR_NB_RESOURCES);
}

static void pm_resume(void)
{
	if (apply_rif_config(true))
		panic();
}

static void pm_suspend(void)
{
	unsigned int wio_offset = 0;
	uint32_t wio_priv = 0;
	uint32_t wio_sec = 0;
	uint32_t r_priv = 0;
	uint32_t r_sec = 0;
	size_t i = 0;

	for (i = 0; i < _PWR_NB_RESOURCES; i++) {
		if (i < _PWR_NB_NS_RESOURCES) {
			pwr_d->conf_data->cid_confs[i] =
				io_read32(pwr_d->base + _PWR_R_CIDCFGR(i)) &
				_PWR_CIDCFGR_R_CONF_MASK;
		} else {
			wio_offset = i + 1 - _PWR_NB_NS_RESOURCES;
			pwr_d->conf_data->cid_confs[i] =
				io_read32(pwr_d->base +
					  _PWR_WIO_CIDCFGR(wio_offset)) &
				_PWR_CIDCFGR_W_CONF_MASK;
		}
	}

	r_priv = io_read32(pwr_d->base + _PWR_RPRIVCFGR) & _PWR_R_PRIVCFGR_MASK;
	r_sec =  io_read32(pwr_d->base + _PWR_RSECCFGR) & _PWR_R_SECCFGR_MASK;
	wio_priv = io_read32(pwr_d->base + _PWR_WIOPRIVCFGR) &
		   _PWR_WIO_PRIVCFGR_MASK;
	wio_sec = io_read32(pwr_d->base + _PWR_WIOSECCFGR) &
		  _PWR_WIO_SECCFGR_MASK;

	pwr_d->conf_data->priv_conf[0] = r_priv |
					 (wio_priv << _PWR_NB_NS_RESOURCES);
	pwr_d->conf_data->sec_conf[0] = r_sec |
					(wio_sec << _PWR_NB_NS_RESOURCES);

	/*
	 * The access mask is modified to restore the conf for all
	 * resources.
	 */
	pwr_d->conf_data->access_mask[0] = GENMASK_32(_PWR_NB_RESOURCES - 1, 0);
}

static TEE_Result
stm32mp2_pwr_pm(enum pm_op op, unsigned int pm_hint,
		const struct pm_callback_handle *pm_handle __unused)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	bool is_tdcid = false;

	res = stm32_rifsc_check_tdcid(&is_tdcid);
	if (res)
		panic();

	if (!PM_HINT_IS_STATE(pm_hint, CONTEXT) || !is_tdcid)
		return TEE_SUCCESS;

	if (op == PM_OP_RESUME)
		pm_resume();
	else
		pm_suspend();

	return TEE_SUCCESS;
}

static TEE_Result stm32mp2_pwr_probe(const void *fdt, int node,
				     const void *compat_data __unused)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	bool is_tdcid = false;
	int subnode = 0;

	FMSG("PWR probe");

	res = stm32_rifsc_check_tdcid(&is_tdcid);
	if (res)
		return res;

	pwr_d = calloc(1, sizeof(*pwr_d));
	if (!pwr_d)
		return TEE_ERROR_OUT_OF_MEMORY;

	parse_dt(fdt, node);

	res = apply_rif_config(is_tdcid);
	if (res)
		panic("Failed to apply rif_config");

	fdt_for_each_subnode(subnode, fdt, node) {
		res = dt_driver_maybe_add_probe_node(fdt, subnode);
		if (res) {
			EMSG("Failed on node %s with %#"PRIx32,
			     fdt_get_name(fdt, subnode, NULL), res);
			panic();
		}
	}

	register_pm_core_service_cb(stm32mp2_pwr_pm, NULL, "stm32mp2-pwr");

	return TEE_SUCCESS;
}

static const struct dt_device_match stm32mp2_pwr_match_table[] = {
	{ .compatible = "st,stm32mp21-pwr" },
	{ .compatible = "st,stm32mp25-pwr" },
	{ }
};

DEFINE_DT_DRIVER(stm32mp2_pwr_dt_driver) = {
	.name = "stm32mp2_pwr",
	.match_table = stm32mp2_pwr_match_table,
	.probe = stm32mp2_pwr_probe,
};
