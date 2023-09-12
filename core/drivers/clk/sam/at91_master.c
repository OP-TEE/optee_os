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
#define MASTER_MAX_ID		4 /* Total 5 MCK clocks for SAMA7G5 */

struct clk_master {
	vaddr_t base;
	const struct clk_master_layout *layout;
	const struct clk_master_charac *charac;
	uint32_t *mux_table;
	uint32_t mckr;
	int chg_pid;
	uint8_t div;
	uint8_t id; /* ID of MCK clocks for SAMA7G5, MCK0 ~ MCK4 */
	uint8_t parent; /* the source clock for SAMA7G5 MCKx */
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

static size_t clk_sama7g5_master_get_parent(struct clk *hw)
{
	struct clk_master *master = hw->priv;
	size_t i = 0;

	for (i = 0; i < hw->num_parents; i++)
		if (master->mux_table[i] == master->parent)
			return i;

	panic("Can't get correct parent of clock");
}

static TEE_Result clk_sama7g5_master_set_parent(struct clk *hw, size_t index)
{
	struct clk_master *master = hw->priv;

	if (index >= hw->num_parents)
		return TEE_ERROR_BAD_PARAMETERS;

	master->parent = master->mux_table[index];

	return TEE_SUCCESS;
}

static TEE_Result clk_sama7g5_master_set_rate(struct clk *hw,
					      unsigned long rate,
					      unsigned long parent_rate)
{
	struct clk_master *master = hw->priv;
	unsigned long div = 0;

	div = UDIV_ROUND_NEAREST(parent_rate, rate);
	if (div > (1 << (MASTER_PRES_MAX - 1)) ||
	    (!IS_POWER_OF_TWO(div) && div != 3))
		return TEE_ERROR_BAD_PARAMETERS;

	/*
	 * Divisor Value: Select the division ratio to be applied to the
	 * selected clock to generate the corresponding MCKx.
	 *  Value  |    Description
	 *    0    | Selected clock divided by 1
	 *    1    | Selected clock divided by 2
	 *    2    | Selected clock divided by 4
	 *    3    | Selected clock divided by 8
	 *    4    | Selected clock divided by 16
	 *    5    | Selected clock divided by 32
	 *    6    | Selected clock divided by 64
	 *    7    | Selected clock divided by 3
	 */
	if (div == 3)
		master->div = MASTER_PRES_MAX;
	else
		master->div = ffs(div) - 1;

	return TEE_SUCCESS;
}

static unsigned long clk_sama7g5_master_get_rate(struct clk *hw,
						 unsigned long parent_rate)
{
	struct clk_master *master = hw->priv;
	unsigned long rate = parent_rate >> master->div;

	if (master->div == 7)
		rate = parent_rate / 3;

	return rate;
}

static const struct clk_ops sama7g5_master_ops = {
	.set_rate = clk_sama7g5_master_set_rate,
	.get_rate = clk_sama7g5_master_get_rate,
	.get_parent = clk_sama7g5_master_get_parent,
	.set_parent = clk_sama7g5_master_set_parent,
};

struct clk *at91_clk_sama7g5_register_master(struct pmc_data *pmc,
					     const char *name,
					     int num_parents,
					     struct clk **parent,
					     uint32_t *mux_table,
					     uint8_t id,
					     int chg_pid)
{
	struct clk_master *master = NULL;
	struct clk *hw = NULL;
	unsigned int val = 0;

	if (!name || !num_parents || !parent || !mux_table ||
	    id > MASTER_MAX_ID)
		return NULL;

	master = calloc(1, sizeof(*master));
	if (!master)
		return NULL;

	hw = clk_alloc(name, &sama7g5_master_ops, parent, num_parents);
	if (!hw) {
		free(master);
		return NULL;
	}

	hw->priv = master;
	master->base = pmc->base;
	master->id = id;
	master->chg_pid = chg_pid;
	master->mux_table = mux_table;

	io_write32(master->base + AT91_PMC_MCR_V2, master->id);
	val = io_read32(master->base + AT91_PMC_MCR_V2);
	master->parent = (val & AT91_PMC_MCR_V2_CSS_MASK) >>
			 AT91_PMC_MCR_V2_CSS_SHIFT;
	master->div = (val & AT91_PMC_MCR_V2_DIV_MASK) >> MASTER_DIV_SHIFT;

	if (clk_register(hw)) {
		clk_free(hw);
		free(master);
		return NULL;
	}

	return hw;
}
