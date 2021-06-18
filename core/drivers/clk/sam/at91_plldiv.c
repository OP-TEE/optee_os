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

static unsigned long clk_plldiv_get_rate(struct clk *clk,
					 unsigned long parent_rate)
{
	struct pmc_data *pmc = clk->priv;
	unsigned int mckr = io_read32(pmc->base + AT91_PMC_MCKR);

	if (mckr & AT91_PMC_PLLADIV2)
		return parent_rate / 2;

	return parent_rate;
}

static TEE_Result clk_plldiv_set_rate(struct clk *clk, unsigned long rate,
				      unsigned long parent_rate)
{
	struct pmc_data *pmc = clk->priv;

	if (parent_rate != rate && (parent_rate / 2 != rate))
		return TEE_ERROR_GENERIC;

	io_clrsetbits32(pmc->base + AT91_PMC_MCKR, AT91_PMC_PLLADIV2,
			parent_rate != rate ? AT91_PMC_PLLADIV2 : 0);

	return TEE_SUCCESS;
}

static const struct clk_ops plldiv_ops = {
	.get_rate = clk_plldiv_get_rate,
	.set_rate = clk_plldiv_set_rate,
};

struct clk *
at91_clk_register_plldiv(struct pmc_data *pmc, const char *name,
			 struct clk *parent)
{
	struct clk *clk = NULL;

	clk = clk_alloc(name, &plldiv_ops, &parent, 1);
	if (!clk)
		return NULL;

	clk->priv = pmc;
	clk->flags = CLK_SET_RATE_GATE;

	if (clk_register(clk)) {
		clk_free(clk);
		return NULL;
	}

	return clk;
}
