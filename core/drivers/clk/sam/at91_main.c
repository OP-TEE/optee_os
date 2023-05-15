// SPDX-License-Identifier: GPL-2.0+ or BSD-3-Clause
/*
 *  Copyright (C) 2013 Boris BREZILLON <b.brezillon@overkiz.com>
 *  Copyright (C) 2021 Microchip
 */

#include <io.h>
#include <kernel/delay.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <types_ext.h>

#include "at91_clk.h"

#define SLOW_CLOCK_FREQ		32768
#define MAINF_DIV		16
#define USEC_PER_SEC		1000000L
#define MAINF_LOOP_MIN_WAIT	(USEC_PER_SEC / SLOW_CLOCK_FREQ)

#define OSC_READY_TIMEOUT_US	1000

#define MOR_KEY_MASK		(0xFF << 16)

#define CLK_MAIN_PARENT_SELECT(s)	(((s) & \
					(AT91_PMC_MOSCEN | \
					AT91_PMC_OSCBYPASS)) ? 1 : 0)

/*
 * Main RC Oscillator
 */

struct main_rc_osc {
	unsigned long freq;
	vaddr_t base;
};

static bool pmc_main_rc_osc_ready(struct main_rc_osc *osc)
{
	uint32_t status = io_read32(osc->base + AT91_PMC_SR);

	return status & AT91_PMC_MOSCRCS;
}

static TEE_Result pmc_main_rc_osc_enable(struct clk *clk)
{
	struct main_rc_osc *osc = clk->priv;
	uint32_t mor = io_read32(osc->base + AT91_CKGR_MOR);

	/* Enable the oscillator if not */
	if (!(mor & AT91_PMC_MOSCRCEN)) {
		io_clrsetbits32(osc->base + AT91_CKGR_MOR,
				MOR_KEY_MASK | AT91_PMC_MOSCRCEN,
				AT91_PMC_MOSCRCEN | AT91_PMC_KEY);
	}

	while (!pmc_main_rc_osc_ready(osc))
		;

	return TEE_SUCCESS;
}

static void pmc_main_rc_osc_disable(struct clk *clk)
{
	struct main_rc_osc *osc = clk->priv;
	uint32_t mor = io_read32(osc->base + AT91_CKGR_MOR);

	if (!(mor & AT91_PMC_MOSCRCEN))
		return;

	io_clrsetbits32(osc->base + AT91_CKGR_MOR,
			MOR_KEY_MASK | AT91_PMC_MOSCRCEN, AT91_PMC_KEY);
}

static unsigned long
pmc_main_rc_osc_get_rate(struct clk *clk, unsigned long parent_rate __unused)
{
	struct main_rc_osc *osc = clk->priv;

	return osc->freq;
}

static const struct clk_ops pmc_main_rc_osc_clk_ops = {
	.enable = pmc_main_rc_osc_enable,
	.disable = pmc_main_rc_osc_disable,
	.get_rate = pmc_main_rc_osc_get_rate,
};

struct clk *pmc_register_main_rc_osc(struct pmc_data *pmc, const char *name,
				     unsigned long freq)
{
	struct clk *clk = NULL;
	struct main_rc_osc *osc = NULL;

	clk = clk_alloc(name, &pmc_main_rc_osc_clk_ops, NULL, 0);
	if (!clk)
		return NULL;

	osc = calloc(1, sizeof(*osc));
	if (!osc) {
		clk_free(clk);
		return NULL;
	}

	osc->freq = freq;
	osc->base = pmc->base;

	clk->priv = osc;

	if (clk_register(clk)) {
		free(osc);
		clk_free(clk);
		return NULL;
	}

	return clk;
}

/*
 * Main Oscillator
 */
static bool pmc_main_osc_ready(struct pmc_data *pmc)
{
	uint32_t status = io_read32(pmc->base + AT91_PMC_SR);

	return status & AT91_PMC_MOSCS;
}

static TEE_Result pmc_main_osc_enable(struct clk *clk)
{
	struct pmc_data *pmc = clk->priv;
	uint32_t mor = io_read32(pmc->base + AT91_CKGR_MOR);

	mor &= ~MOR_KEY_MASK;

	if (mor & AT91_PMC_OSCBYPASS)
		return TEE_SUCCESS;

	if (!(mor & AT91_PMC_MOSCEN)) {
		mor |= AT91_PMC_MOSCEN | AT91_PMC_KEY;
		io_write32(pmc->base + AT91_CKGR_MOR, mor);
	}

	while (!pmc_main_osc_ready(pmc))
		;

	return TEE_SUCCESS;
}

static void pmc_main_osc_disable(struct clk *clk)
{
	struct pmc_data *pmc = clk->priv;
	uint32_t mor = io_read32(pmc->base + AT91_CKGR_MOR);

	if (mor & AT91_PMC_OSCBYPASS)
		return;

	if (!(mor & AT91_PMC_MOSCEN))
		return;

	mor &= ~(AT91_PMC_KEY | AT91_PMC_MOSCEN);
	io_write32(pmc->base + AT91_CKGR_MOR, mor | AT91_PMC_KEY);
}

static const struct clk_ops pmc_main_osc_clk_ops = {
	.enable = pmc_main_osc_enable,
	.disable = pmc_main_osc_disable,
};

struct clk *pmc_register_main_osc(struct pmc_data *pmc, const char *name,
				  struct clk *parent, bool bypass)
{
	struct clk *clk = NULL;

	clk = clk_alloc(name, &pmc_main_osc_clk_ops, &parent, 1);
	if (!clk)
		panic();

	clk->priv = pmc;

	if (bypass)
		io_clrsetbits32(pmc->base + AT91_CKGR_MOR,
				MOR_KEY_MASK | AT91_PMC_OSCBYPASS,
				AT91_PMC_OSCBYPASS | AT91_PMC_KEY);

	if (clk_register(clk)) {
		clk_free(clk);
		return NULL;
	}

	return clk;
}

/*
 * Main Clock
 */
static TEE_Result clk_main_probe_frequency(vaddr_t base)
{
	while (!(io_read32(base + AT91_CKGR_MCFR) & AT91_PMC_MAINRDY))
		;

	return TEE_SUCCESS;
}

static unsigned long clk_main_get_rate(vaddr_t base,
				       unsigned long parent_rate)
{
	uint32_t mcfr = 0;

	if (parent_rate)
		return parent_rate;

	IMSG("Main crystal frequency not set, using approximate value");
	mcfr = io_read32(base + AT91_CKGR_MCFR);
	if (!(mcfr & AT91_PMC_MAINRDY))
		return 0;

	return ((mcfr & AT91_PMC_MAINF) * SLOW_CLOCK_FREQ) / MAINF_DIV;
}

static bool clk_sam9x5_main_ready(vaddr_t base)
{
	uint32_t status = io_read32(base + AT91_PMC_SR);

	return status & AT91_PMC_MOSCSELS;
}

static TEE_Result clk_sam9x5_main_enable(struct clk *clk)
{
	struct pmc_data *pmc = clk->priv;

	while (!clk_sam9x5_main_ready(pmc->base))
		;

	return clk_main_probe_frequency(pmc->base);
}

static unsigned long clk_sam9x5_main_get_rate(struct clk *clk,
					      unsigned long parent_rate)
{
	struct pmc_data *pmc = clk->priv;

	return clk_main_get_rate(pmc->base, parent_rate);
}

static TEE_Result clk_sam9x5_main_set_parent(struct clk *clk, size_t index)
{
	struct pmc_data *pmc = clk->priv;
	uint32_t tmp = 0;

	if (index > 1)
		return TEE_ERROR_BAD_PARAMETERS;

	tmp = io_read32(pmc->base + AT91_CKGR_MOR);

	if (index && !(tmp & AT91_PMC_MOSCSEL))
		tmp = AT91_PMC_MOSCSEL;
	else if (!index && (tmp & AT91_PMC_MOSCSEL))
		tmp = 0;
	else
		return TEE_SUCCESS;

	io_clrsetbits32(pmc->base + AT91_CKGR_MOR,
			AT91_PMC_MOSCSEL | MOR_KEY_MASK,
			tmp | AT91_PMC_KEY);

	while (!clk_sam9x5_main_ready(pmc->base))
		;

	return TEE_SUCCESS;
}

static size_t clk_sam9x5_main_get_parent(struct clk *clk)
{
	struct pmc_data *pmc = clk->priv;
	uint32_t status = io_read32(pmc->base + AT91_CKGR_MOR);

	return CLK_MAIN_PARENT_SELECT(status);
}

static const struct clk_ops sam9x5_main_ops = {
	.enable = clk_sam9x5_main_enable,
	.get_rate = clk_sam9x5_main_get_rate,
	.set_parent = clk_sam9x5_main_set_parent,
	.get_parent = clk_sam9x5_main_get_parent,
};

struct clk *
at91_clk_register_sam9x5_main(struct pmc_data *pmc,
			      const char *name,
			      struct clk **parent_clocks,
			      unsigned int num_parents)
{
	struct clk *clk = NULL;

	if (!name)
		return NULL;

	if (!parent_clocks || !num_parents)
		return NULL;

	clk = clk_alloc(name, &sam9x5_main_ops, parent_clocks, num_parents);
	if (!clk)
		return NULL;

	clk->flags = CLK_SET_PARENT_GATE;
	clk->priv = pmc;

	if (clk_register(clk)) {
		clk_free(clk);
		return NULL;
	}

	return clk;
}
