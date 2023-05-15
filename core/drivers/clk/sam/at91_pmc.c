// SPDX-License-Identifier: GPL-2.0+ or BSD-3-Clause
/*
 *  Copyright (C) 2021 Microchip
 */

#include <dt-bindings/clock/at91.h>
#include <io.h>
#include <kernel/panic.h>
#include <kernel/pm.h>
#include <malloc.h>
#include <string.h>
#include <trace.h>
#include <types_ext.h>

#include "at91_clk.h"

#define PMC_MAX_IDS 128
#define PMC_MAX_PCKS 8

static struct clk *pmc_clk_get_by_id(struct pmc_clk *clks, unsigned int nclk,
				     unsigned int id)
{
	unsigned int i = 0;

	for (i = 0; i < nclk; i++) {
		if (clks[i].clk && clks[i].id == id)
			return clks[i].clk;
	}

	return NULL;
}

struct clk *pmc_clk_get_by_name(struct pmc_clk *clks, unsigned int nclk,
				const char *name)
{
	unsigned int i = 0;

	for (i = 0; i < nclk; i++)
		if (strcmp(clks[i].clk->name, name) == 0)
			return clks[i].clk;

	return NULL;
}

struct clk *clk_dt_pmc_get(struct dt_driver_phandle_args *clkspec, void *data,
			   TEE_Result *res)
{
	unsigned int type = clkspec->args[0];
	unsigned int idx = clkspec->args[1];
	struct pmc_data *pmc_data = data;
	struct pmc_clk *clks = NULL;
	struct clk *clk = NULL;
	unsigned int nclk = 0;
	*res = TEE_ERROR_GENERIC;

	if (clkspec->args_count != 2) {
		*res = TEE_ERROR_BAD_PARAMETERS;
		return NULL;
	}

	switch (type) {
	case PMC_TYPE_CORE:
		nclk = pmc_data->ncore;
		clks = pmc_data->chws;
		break;
	case PMC_TYPE_SYSTEM:
		nclk = pmc_data->nsystem;
		clks = pmc_data->shws;
		break;
	case PMC_TYPE_PERIPHERAL:
		nclk = pmc_data->nperiph;
		clks = pmc_data->phws;
		break;
	case PMC_TYPE_GCK:
		nclk = pmc_data->ngck;
		clks = pmc_data->ghws;
		break;
	case PMC_TYPE_PROGRAMMABLE:
		nclk = pmc_data->npck;
		clks = pmc_data->pchws;
		break;
	default:
		return NULL;
	}

	clk = pmc_clk_get_by_id(clks, nclk, idx);
	if (clk)
		*res = TEE_SUCCESS;

	return clk;
}

struct pmc_data *pmc_data_allocate(unsigned int ncore, unsigned int nsystem,
				   unsigned int nperiph, unsigned int ngck,
				   unsigned int npck)
{
	unsigned int num_clks = ncore + nsystem + nperiph + ngck + npck;
	unsigned int alloc_size = sizeof(struct pmc_data) +
				  num_clks * sizeof(struct pmc_clk);
	struct pmc_data *pmc_data = NULL;

	pmc_data = calloc(1, alloc_size);
	if (!pmc_data)
		return NULL;

	pmc_data->ncore = ncore;
	pmc_data->chws = pmc_data->hwtable;

	pmc_data->nsystem = nsystem;
	pmc_data->shws = pmc_data->chws + ncore;

	pmc_data->nperiph = nperiph;
	pmc_data->phws = pmc_data->shws + nsystem;

	pmc_data->ngck = ngck;
	pmc_data->ghws = pmc_data->phws + nperiph;

	pmc_data->npck = npck;
	pmc_data->pchws = pmc_data->ghws + ngck;

	return pmc_data;
}

#ifdef CFG_PM_ARM32
static uint8_t registered_ids[PMC_MAX_IDS];
static uint8_t registered_pcks[PMC_MAX_PCKS];

static struct
{
	uint32_t scsr;
	uint32_t pcsr0;
	uint32_t uckr;
	uint32_t mor;
	uint32_t mcfr;
	uint32_t pllar;
	uint32_t mckr;
	uint32_t usb;
	uint32_t imr;
	uint32_t pcsr1;
	uint32_t pcr[PMC_MAX_IDS];
	uint32_t audio_pll0;
	uint32_t audio_pll1;
	uint32_t pckr[PMC_MAX_PCKS];
} pmc_cache;

/*
 * As Peripheral ID 0 is invalid on AT91 chips, the identifier is stored
 * without alteration in the table, and 0 is for unused clocks.
 */
void pmc_register_id(uint8_t id)
{
	int i = 0;

	for (i = 0; i < PMC_MAX_IDS; i++) {
		if (registered_ids[i] == 0) {
			registered_ids[i] = id;
			return;
		}
		if (registered_ids[i] == id)
			return;
	}

	panic("Invalid clock ID");
}

/*
 * As Programmable Clock 0 is valid on AT91 chips, there is an offset
 * of 1 between the stored value and the real clock ID.
 */
void pmc_register_pck(uint8_t pck)
{
	int i = 0;

	for (i = 0; i < PMC_MAX_PCKS; i++) {
		if (registered_pcks[i] == 0) {
			registered_pcks[i] = pck + 1;
			return;
		}
		if (registered_pcks[i] == pck + 1)
			return;
	}

	panic("Invalid clock ID");
}

static void pmc_suspend(void)
{
	int i = 0;
	uint8_t num = 0;
	vaddr_t pmc_base = at91_pmc_get_base();

	pmc_cache.scsr = io_read32(pmc_base + AT91_PMC_SCSR);
	pmc_cache.pcsr0 = io_read32(pmc_base + AT91_PMC_PCSR);
	pmc_cache.uckr = io_read32(pmc_base + AT91_CKGR_UCKR);
	pmc_cache.mor = io_read32(pmc_base + AT91_CKGR_MOR);
	pmc_cache.mcfr = io_read32(pmc_base + AT91_CKGR_MCFR);
	pmc_cache.pllar = io_read32(pmc_base + AT91_CKGR_PLLAR);
	pmc_cache.mckr = io_read32(pmc_base + AT91_PMC_MCKR);
	pmc_cache.usb = io_read32(pmc_base + AT91_PMC_USB);
	pmc_cache.imr = io_read32(pmc_base + AT91_PMC_IMR);
	pmc_cache.pcsr1 = io_read32(pmc_base + AT91_PMC_PCSR1);

	for (i = 0; registered_ids[i]; i++) {
		io_write32(pmc_base + AT91_PMC_PCR,
			   registered_ids[i] & AT91_PMC_PCR_PID_MASK);
		pmc_cache.pcr[registered_ids[i]] = io_read32(pmc_base +
							     AT91_PMC_PCR);
	}
	for (i = 0; registered_pcks[i]; i++) {
		num = registered_pcks[i] - 1;
		pmc_cache.pckr[num] = io_read32(pmc_base + AT91_PMC_PCKR(num));
	}
}

static bool pmc_ready(vaddr_t pmc_base, unsigned int mask)
{
	uint32_t status = 0;

	status = io_read32(pmc_base + AT91_PMC_SR);

	return (status & mask) == mask;
}

static void pmc_resume(void)
{
	int i = 0;
	uint8_t num = 0;
	uint32_t tmp = 0;
	vaddr_t pmc_base = at91_pmc_get_base();
	uint32_t mask = AT91_PMC_MCKRDY | AT91_PMC_LOCKA;

	tmp = io_read32(pmc_base + AT91_PMC_MCKR);
	if (pmc_cache.mckr != tmp)
		panic("MCKR was not configured properly by the previous bootstage");
	tmp = io_read32(pmc_base + AT91_CKGR_PLLAR);
	if (pmc_cache.pllar != tmp)
		panic("PLLAR was not configured properly by the previous bootstage");

	io_write32(pmc_base + AT91_PMC_SCER, pmc_cache.scsr);
	io_write32(pmc_base + AT91_PMC_PCER, pmc_cache.pcsr0);
	io_write32(pmc_base + AT91_CKGR_UCKR, pmc_cache.uckr);
	io_write32(pmc_base + AT91_CKGR_MOR, pmc_cache.mor);
	io_write32(pmc_base + AT91_CKGR_MCFR, pmc_cache.mcfr);
	io_write32(pmc_base + AT91_PMC_USB, pmc_cache.usb);
	io_write32(pmc_base + AT91_PMC_IMR, pmc_cache.imr);
	io_write32(pmc_base + AT91_PMC_PCER1, pmc_cache.pcsr1);

	for (i = 0; registered_ids[i]; i++) {
		io_write32(pmc_base + AT91_PMC_PCR,
			   pmc_cache.pcr[registered_ids[i]] | AT91_PMC_PCR_CMD);
	}
	for (i = 0; registered_pcks[i]; i++) {
		num = registered_pcks[i] - 1;
		io_write32(pmc_base + AT91_PMC_PCKR(num), pmc_cache.pckr[num]);
	}

	if (pmc_cache.uckr & AT91_PMC_UPLLEN)
		mask |= AT91_PMC_LOCKU;

	while (!pmc_ready(pmc_base, mask))
		;
}

static TEE_Result pmc_pm(enum pm_op op, uint32_t pm_hint __unused,
			 const struct pm_callback_handle *hdl __unused)
{
	switch (op) {
	case PM_OP_RESUME:
		pmc_resume();
		break;
	case PM_OP_SUSPEND:
		pmc_suspend();
		break;
	default:
		panic("Invalid PM operation");
	}

	return TEE_SUCCESS;
}

void pmc_register_pm(void)
{
	/*
	 * We register the clock as a core service since clocks must be
	 * re-enable prior to accessing devices
	 */
	register_pm_core_service_cb(pmc_pm, NULL, "pmc");
}

#endif
