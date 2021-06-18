// SPDX-License-Identifier: GPL-2.0+ or BSD-3-Clause
/*
 *  Copyright (C) 2014 Atmel
 *
 * Alexandre Belloni <alexandre.belloni@free-electrons.com>
 */

#include <io.h>
#include <kernel/delay.h>
#include <mm/core_memprot.h>
#include <types_ext.h>

#include "at91_clk.h"

#define H32MX_MAX_FREQ	90000000

static unsigned long clk_sama5d4_h32mx_get_rate(struct clk *clk,
						unsigned long parent_rate)
{
	struct pmc_data *pmc = clk->priv;
	unsigned int mckr = io_read32(pmc->base + AT91_PMC_MCKR);

	if (mckr & AT91_PMC_H32MXDIV)
		return parent_rate / 2;

	if (parent_rate > H32MX_MAX_FREQ)
		IMSG("H32MX clock is too fast");

	return parent_rate;
}

static TEE_Result clk_sama5d4_h32mx_set_rate(struct clk *clk,
					     unsigned long rate,
					     unsigned long parent_rate)
{
	struct pmc_data *pmc = clk->priv;
	uint32_t mckr = 0;

	if (parent_rate != rate && (parent_rate / 2) != rate)
		return TEE_ERROR_BAD_PARAMETERS;

	if ((parent_rate / 2) == rate)
		mckr = AT91_PMC_H32MXDIV;

	io_clrsetbits32(pmc->base + AT91_PMC_MCKR, AT91_PMC_H32MXDIV, mckr);

	return TEE_SUCCESS;
}

static const struct clk_ops h32mx_ops = {
	.get_rate = clk_sama5d4_h32mx_get_rate,
	.set_rate = clk_sama5d4_h32mx_set_rate,
};

struct clk *
at91_clk_register_h32mx(struct pmc_data *pmc, const char *name,
			struct clk *parent)
{
	struct clk *clk = NULL;

	clk = clk_alloc(name, &h32mx_ops, &parent, 1);
	if (!clk)
		return NULL;

	clk->ops = &h32mx_ops;
	clk->priv = pmc;
	clk->name = name;
	clk->flags = CLK_SET_RATE_GATE;

	if (clk_register(clk)) {
		clk_free(clk);
		return NULL;
	}

	return clk;
}
