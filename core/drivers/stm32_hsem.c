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
#include <libfdt.h>
#include <mm/core_memprot.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stm32_util.h>
#include <trace.h>

#define HSEM_SECCFGR			U(0x200)
#define HSEM_PRIVCFGR			U(0x210)
#define HSEM_CnCIDCFGR(x)		(U(0x220) + U(0x004) * ((x) - 1))
#define HSEM_GpCIDCFGR(x)		(U(0x240) + U(0x004) * (x))

/*
 * CnCIDCFGR register bitfields
 */
#define HSEM_CnCIDCFGR_CONF_MASK	(_CIDCFGR_CFEN |	 \
					 HSEM_CnCIDCFGR_SCID_MASK)
#define HSEM_CnCIDCFGR_SCID_MASK	GENMASK_32(6, 4)

/*
 * GpCIDCFGR register bitfields
 */
#define HSEM_GpCIDCFGR_SEM_WLIST_C_MASK	GENMASK_32(18, 16)
#define HSEM_GpCIDCFGR_SEM_WLIST_SHIFT	U(16)
#define HSEM_GpCIDCFGR_CONF_MASK	(_CIDCFGR_CFEN |	 \
					 HSEM_GpCIDCFGR_SEM_WLIST_C_MASK)

/*
 * PRIVCFGR register bitfields
 */
#define HSEM_PRIVCFGR_MASK		GENMASK_32(15, 0)

/*
 * SECCFGR register bitfields
 */
#define HSEM_SECCFGR_MASK		GENMASK_32(15, 0)

/*
 * Miscellaneous
 */
#define HSEM_NB_PROC			U(3)
#define HSEM_NB_SEM_GROUPS		U(4)
#define HSEM_NB_SEM_PER_GROUP		U(4)

#define HSEM_NB_MAX_CID_SUPPORTED	U(7)
#define HSEM_RIF_RESOURCES		U(16)

struct hsem_pdata {
	struct clk *hsem_clock;
	struct rif_conf_data conf_data;
	unsigned int nb_channels;
	vaddr_t base;
	uint32_t *rif_proc_conf;
};

static struct hsem_pdata *hsem_d;

static void apply_rif_config(bool is_tdcid)
{
	unsigned int i = 0;
	unsigned int j = 0;
	uint32_t prev_cid_value = 0;

	/*
	 * When TDCID, OP-TEE should be the one to set the CID filtering
	 * configuration. Clearing previous configuration prevents
	 * undesired events during the only legitimate configuration.
	 */
	if (is_tdcid) {
		for (i = 0; i < HSEM_NB_PROC; i++)
			io_clrbits32(hsem_d->base + HSEM_CnCIDCFGR(i + 1),
				     HSEM_CnCIDCFGR_CONF_MASK);

		/* Clean HSEM groups configuration registers */
		for (i = 0; i < HSEM_NB_SEM_GROUPS; i++)
			io_clrbits32(hsem_d->base + HSEM_GpCIDCFGR(i),
				     HSEM_GpCIDCFGR_CONF_MASK);
	}

	/* Security and privilege RIF configuration */
	io_clrsetbits32(hsem_d->base + HSEM_SECCFGR,
			HSEM_SECCFGR_MASK & hsem_d->conf_data.access_mask[0],
			hsem_d->conf_data.sec_conf[0]);
	io_clrsetbits32(hsem_d->base + HSEM_PRIVCFGR,
			HSEM_PRIVCFGR_MASK & hsem_d->conf_data.access_mask[0],
			hsem_d->conf_data.priv_conf[0]);

	if (!is_tdcid)
		return;

	/* Configure HSEM processors configuration registers */
	for (i = 0; i < HSEM_NB_PROC; i++) {
		/*
		 * If a processor CID configuration is present, enable it.
		 * Else, nothing to do.
		 */
		if (!hsem_d->rif_proc_conf[i])
			continue;

		io_clrsetbits32(hsem_d->base + HSEM_CnCIDCFGR(i + 1),
				HSEM_CnCIDCFGR_CONF_MASK,
				_CIDCFGR_CFEN | hsem_d->rif_proc_conf[i]);
	}

	/*
	 * Configure HSEM groups configuration registers
	 * If one semaphore is configured, all semaphores of its group
	 * must be configured too and MUST have the same RIF
	 * configuration.
	 */
	for (i = 0; i < HSEM_NB_SEM_GROUPS; i++) {
		unsigned int hsem_idx = i * HSEM_NB_SEM_PER_GROUP;
		unsigned int hsem_cid = 0;
		unsigned int known_cid_idx = 0;

		prev_cid_value = hsem_d->conf_data.cid_confs[hsem_idx];

		/* If CID filtering is disabled, do nothing */
		if (!(prev_cid_value & _CIDCFGR_CFEN))
			continue;

		/*
		 * Check if configured CID corresponds to a processor's
		 * CID in HSEM_CnCIDCFGR.
		 */
		for (j = 0; j < HSEM_NB_PROC; j++) {
			uint32_t proc_cid = hsem_d->rif_proc_conf[j];

			hsem_cid = (prev_cid_value & HSEM_CnCIDCFGR_SCID_MASK);
			DMSG("hsem_cid %u", hsem_cid);
			DMSG("proc_cid %u", proc_cid);
			if (proc_cid == hsem_cid) {
				known_cid_idx = BIT(j +
					HSEM_GpCIDCFGR_SEM_WLIST_SHIFT);
				break;
			}
		}
		if (!known_cid_idx)
			panic("Unknown HSEM processor CID");

		/*
		 * HSEM resources in the same group must have the same CID
		 * filtering configuration. Else it is inconsistent.
		 */
		for (j = 0; j < HSEM_NB_SEM_PER_GROUP; j++)
			if (hsem_d->conf_data.cid_confs[j + hsem_idx] !=
			    prev_cid_value)
				panic("Inconsistent HSEM RIF group config");

		io_clrsetbits32(hsem_d->base + HSEM_GpCIDCFGR(i),
				HSEM_GpCIDCFGR_CONF_MASK,
				_CIDCFGR_CFEN | known_cid_idx);
	}
}

static TEE_Result parse_dt(const void *fdt, int node)
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
	hsem_d->base = io_pa_or_va_secure(&addr, info.reg_size);

	/* Gate the IP */
	res = clk_dt_get_by_index(fdt, node, 0, &hsem_d->hsem_clock);
	if (res)
		return res;

	cuint = fdt_getprop(fdt, node, "st,protreg", &lenp);
	if (!cuint)
		panic("No RIF configuration available");

	hsem_d->nb_channels = (unsigned int)(lenp / sizeof(uint32_t));
	assert(hsem_d->nb_channels <= HSEM_RIF_RESOURCES);

	hsem_d->rif_proc_conf = calloc(HSEM_NB_PROC, sizeof(uint32_t));
	assert(hsem_d->rif_proc_conf);
	hsem_d->conf_data.cid_confs = calloc(HSEM_RIF_RESOURCES,
					     sizeof(uint32_t));
	hsem_d->conf_data.sec_conf = calloc(1, sizeof(uint32_t));
	hsem_d->conf_data.priv_conf = calloc(1, sizeof(uint32_t));
	hsem_d->conf_data.access_mask = calloc(1, sizeof(uint32_t));
	assert(hsem_d->conf_data.cid_confs && hsem_d->conf_data.sec_conf &&
	       hsem_d->conf_data.priv_conf && hsem_d->conf_data.access_mask);

	for (i = 0; i < hsem_d->nb_channels; i++)
		stm32_rif_parse_cfg(fdt32_to_cpu(cuint[i]), &hsem_d->conf_data,
				    HSEM_NB_MAX_CID_SUPPORTED,
				    HSEM_RIF_RESOURCES);

	cuint = fdt_getprop(fdt, node, "st,proccid", &lenp);
	if (!cuint)
		panic("No RIF proc configuration available");

	lenp = (unsigned int)(lenp / sizeof(uint32_t));
	/*
	 * There should be maximum (HSEM_NB_PROC * 2) property argument.
	 * First argument for a processor is its number, the second is its CID.
	 */
	assert((unsigned int)lenp <= (HSEM_NB_PROC * 2));

	for (i = 0; i < (unsigned int)lenp / 2; i++) {
		unsigned int pos = fdt32_to_cpu(cuint[i * 2]) - 1;
		unsigned int cid_value = fdt32_to_cpu(cuint[(i * 2) + 1]);

		hsem_d->rif_proc_conf[pos] = SHIFT_U32(cid_value, SCID_SHIFT);
	}

	return TEE_SUCCESS;
}

static TEE_Result stm32_hsem_probe(const void *fdt, int node,
				   const void *compat_data __unused)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	bool is_tdcid = false;

	res = stm32_rifsc_check_tdcid(&is_tdcid);
	if (res)
		return res;

	hsem_d = calloc(1, sizeof(*hsem_d));
	if (!hsem_d)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = parse_dt(fdt, node);
	if (res)
		return res;

	res = clk_enable(hsem_d->hsem_clock);
	if (res)
		panic("Cannot access HSEM clock");

	apply_rif_config(is_tdcid);

	clk_disable(hsem_d->hsem_clock);

	return TEE_SUCCESS;
}

static const struct dt_device_match stm32_hsem_match_table[] = {
	{ .compatible = "st,stm32mp25-hsem" },
	{ }
};

DEFINE_DT_DRIVER(stm32_hsem_dt_driver) = {
	.name = "st,stm32-hsem",
	.match_table = stm32_hsem_match_table,
	.probe = stm32_hsem_probe,
};
