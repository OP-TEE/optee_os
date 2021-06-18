// SPDX-License-Identifier: GPL-2.0+ or BSD-3-Clause
/*
 *  Copyright (C) 2013 Boris BREZILLON <b.brezillon@overkiz.com>
 *  Copyright (C) 2021 Microchip
 */

#include <io.h>
#include <kernel/delay.h>
#include <mm/core_memprot.h>
#include <types_ext.h>

#include "at91_clk.h"

#define MASTER_PRES_MASK	0x7
#define MASTER_PRES_MAX		MASTER_PRES_MASK
#define MASTER_DIV_SHIFT	8
#define MASTER_DIV_MASK		0x7

struct clk_master {
	vaddr_t base;
	const struct clk_master_layout *layout;
	const struct clk_master_charac *charac;
	uint32_t *mux_table;
	uint32_t mckr;
	int chg_pid;
	uint8_t div;
};

static bool clk_master_ready(struct clk_master *master)
{
	uint32_t status = io_read32(master->base + AT91_PMC_SR);

	return status & AT91_PMC_MCKRDY;
}

static TEE_Result clk_master_enable(struct clk *clk)
{
	struct clk_master *master = clk->priv;

	while (!clk_master_ready(master))
		;

	return TEE_SUCCESS;
}

static unsigned long clk_master_div_get_rate(struct clk *clk,
					     unsigned long parent_rate)
{
	uint8_t div = 1;
	uint32_t mckr = 0;
	unsigned long rate = parent_rate;
	struct clk_master *master = clk->priv;
	const struct clk_master_layout *layout = master->layout;
	const struct clk_master_charac *charac = master->charac;

	mckr = io_read32(master->base + master->layout->offset);

	mckr &= layout->mask;

	div = (mckr >> MASTER_DIV_SHIFT) & MASTER_DIV_MASK;

	rate /= charac->divisors[div];

	if (rate < charac->output.min)
		IMSG("master clk div is underclocked");
	else if (rate > charac->output.max)
		IMSG("master clk div is overclocked");

	return rate;
}

static const struct clk_ops master_div_ops = {
	.enable = clk_master_enable,
	.get_rate = clk_master_div_get_rate,
};

static unsigned long clk_master_pres_get_rate(struct clk *clk,
					      unsigned long parent_rate)
{
	struct clk_master *master = clk->priv;
	const struct clk_master_charac *charac = master->charac;
	uint32_t val = 0;
	unsigned int pres = 0;

	val = io_read32(master->base + master->layout->offset);

	pres = (val >> master->layout->pres_shift) & MASTER_PRES_MASK;
	if (pres != 3 || !charac->have_div3_pres)
		pres = BIT(pres);

	return UDIV_ROUND_NEAREST(parent_rate, pres);
}

static size_t clk_master_pres_get_parent(struct clk *clk)
{
	struct clk_master *master = clk->priv;
	uint32_t mckr = 0;

	mckr = io_read32(master->base + master->layout->offset);

	return mckr & AT91_PMC_CSS;
}

static const struct clk_ops master_pres_ops = {
	.enable = clk_master_enable,
	.get_rate = clk_master_pres_get_rate,
	.get_parent = clk_master_pres_get_parent,
};

static struct clk *
at91_clk_register_master_internal(struct pmc_data *pmc,
				  const char *name, int num_parents,
				  struct clk **parents,
				  const struct clk_master_layout *layout,
				  const struct clk_master_charac *charac,
				  const struct clk_ops *ops, int chg_pid)
{
	struct clk_master *master = NULL;
	struct clk *clk = NULL;

	if (!name || !num_parents || !parents)
		return NULL;

	clk = clk_alloc(name, ops, parents, num_parents);
	if (!clk)
		return NULL;

	master = calloc(1, sizeof(*master));
	if (!master) {
		clk_free(clk);
		return NULL;
	}

	master->layout = layout;
	master->charac = charac;
	master->base = pmc->base;
	master->chg_pid = chg_pid;

	clk->priv = master;
	clk->flags = CLK_SET_RATE_GATE;

	if (clk_register(clk)) {
		clk_free(clk);
		free(master);
		return NULL;
	}

	return clk;
}

struct clk *
at91_clk_register_master_pres(struct pmc_data *pmc,
			      const char *name, int num_parents,
			      struct clk **parents,
			      const struct clk_master_layout *layout,
			      const struct clk_master_charac *charac,
			      int chg_pid)
{
	return at91_clk_register_master_internal(pmc, name, num_parents,
						 parents, layout,
						 charac,
						 &master_pres_ops, chg_pid);
}

struct clk *
at91_clk_register_master_div(struct pmc_data *pmc,
			     const char *name, struct clk *parent,
			     const struct clk_master_layout *layout,
			     const struct clk_master_charac *charac)
{
	return at91_clk_register_master_internal(pmc, name, 1,
						 &parent, layout,
						 charac,
						 &master_div_ops, -1);
}

const struct clk_master_layout at91sam9x5_master_layout = {
	.mask = 0x373,
	.pres_shift = 4,
	.offset = AT91_PMC_MCKR,
};
