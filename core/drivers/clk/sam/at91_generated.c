// SPDX-License-Identifier: GPL-2.0+ or BSD-3-Clause
/*
 *  Copyright (C) 2015 - 2021 Atmel Corporation,
 *                            Nicolas Ferre <nicolas.ferre@atmel.com>
 *
 * Based on clk-programmable & clk-peripheral drivers by Boris BREZILLON.
 */

#include <io.h>
#include <kernel/delay.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <string.h>
#include <types_ext.h>

#include "at91_clk.h"

#define GENERATED_MAX_DIV	255

struct clk_generated {
	vaddr_t base;
	struct clk_range range;
	uint32_t *mux_table;
	uint32_t id;
	uint32_t gckdiv;
	const struct clk_pcr_layout *layout;
	uint8_t parent_id;
	int chg_pid;
};

static TEE_Result clk_generated_enable(struct clk *clk)
{
	struct clk_generated *gck = clk->priv;

	io_write32(gck->base + gck->layout->offset,
		   (gck->id & gck->layout->pid_mask));
	io_clrsetbits32(gck->base + gck->layout->offset,
			AT91_PMC_PCR_GCKDIV_MASK | gck->layout->gckcss_mask |
			gck->layout->cmd | AT91_PMC_PCR_GCKEN,
			field_prep(gck->layout->gckcss_mask, gck->parent_id) |
			gck->layout->cmd |
			((gck->gckdiv << AT91_PMC_PCR_GCKDIV_SHIFT) &
			 AT91_PMC_PCR_GCKDIV_MASK) |
			AT91_PMC_PCR_GCKEN);

	return TEE_SUCCESS;
}

static void clk_generated_disable(struct clk *clk)
{
	struct clk_generated *gck = clk->priv;

	io_write32(gck->base + gck->layout->offset,
		   gck->id & gck->layout->pid_mask);
	io_clrsetbits32(gck->base + gck->layout->offset, AT91_PMC_PCR_GCKEN,
			gck->layout->cmd);
}

static unsigned long
clk_generated_get_rate(struct clk *clk, unsigned long parent_rate)
{
	struct clk_generated *gck = clk->priv;

	return UDIV_ROUND_NEAREST(parent_rate, gck->gckdiv + 1);
}

/* No modification of hardware as we have the flag CLK_SET_PARENT_GATE set */
static TEE_Result clk_generated_set_parent(struct clk *clk, size_t index)
{
	struct clk_generated *gck = clk->priv;

	if (index >= clk_get_num_parents(clk))
		return TEE_ERROR_BAD_PARAMETERS;

	gck->parent_id = index;

	return TEE_SUCCESS;
}

static size_t clk_generated_get_parent(struct clk *clk)
{
	struct clk_generated *gck = clk->priv;

	return gck->parent_id;
}

/* No modification of hardware as we have the flag CLK_SET_RATE_GATE set */
static TEE_Result clk_generated_set_rate(struct clk *clk, unsigned long rate,
					 unsigned long parent_rate)
{
	struct clk_generated *gck = clk->priv;
	uint32_t div = 1;

	if (!rate)
		return TEE_ERROR_BAD_PARAMETERS;

	if (gck->range.max && rate > gck->range.max)
		return TEE_ERROR_BAD_PARAMETERS;

	div = UDIV_ROUND_NEAREST(parent_rate, rate);
	if (div > GENERATED_MAX_DIV + 1 || !div)
		return TEE_ERROR_GENERIC;

	gck->gckdiv = div - 1;
	return TEE_SUCCESS;
}

static const struct clk_ops generated_ops = {
	.enable = clk_generated_enable,
	.disable = clk_generated_disable,
	.get_rate = clk_generated_get_rate,
	.get_parent = clk_generated_get_parent,
	.set_parent = clk_generated_set_parent,
	.set_rate = clk_generated_set_rate,
};

/**
 * clk_generated_startup - Initialize a given clock to its default parent and
 * divisor parameter.
 *
 * @gck:	Generated clock to set the startup parameters for.
 *
 * Take parameters from the hardware and update local clock configuration
 * accordingly.
 */
static void clk_generated_startup(struct clk_generated *gck)
{
	uint32_t tmp = 0;

	io_write32(gck->base + gck->layout->offset,
		   (gck->id & gck->layout->pid_mask));
	tmp = io_read32(gck->base + gck->layout->offset);

	gck->parent_id = field_get(gck->layout->gckcss_mask, tmp);
	gck->gckdiv = (tmp & AT91_PMC_PCR_GCKDIV_MASK) >>
		      AT91_PMC_PCR_GCKDIV_SHIFT;
}

struct clk *
at91_clk_register_generated(struct pmc_data *pmc,
			    const struct clk_pcr_layout *layout,
			    const char *name, struct clk **parents,
			    uint8_t num_parents, uint8_t id,
			    const struct clk_range *range,
			    int chg_pid)
{
	struct clk_generated *gck = NULL;
	struct clk *clk = NULL;

	clk = clk_alloc(name, &generated_ops, parents, num_parents);
	if (!clk)
		return NULL;

	gck = calloc(1, sizeof(*gck));
	if (!gck) {
		clk_free(clk);
		return NULL;
	}

	clk->flags = CLK_SET_RATE_GATE | CLK_SET_PARENT_GATE;

	gck->id = id;
	gck->base = pmc->base;
	memcpy(&gck->range, range, sizeof(gck->range));
	gck->chg_pid = chg_pid;
	gck->layout = layout;

	clk->priv = gck;

	clk_generated_startup(gck);

	if (clk_register(clk)) {
		clk_free(clk);
		free(gck);
		return NULL;
	}

	return clk;
}
