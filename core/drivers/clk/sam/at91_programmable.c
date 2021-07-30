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

#define PROG_ID_MAX		7

#define PROG_STATUS_MASK(id)	(1 << ((id) + 8))
#define PROG_PRES(layout, pckr)	\
	({ \
		typeof(layout) __layout = layout; \
		\
		(((pckr) >> (__layout)->pres_shift) & (__layout)->pres_mask); \
	})
#define PROG_MAX_RM9200_CSS	3

struct clk_programmable {
	vaddr_t base;
	uint8_t id;
	const struct clk_programmable_layout *layout;
};

static unsigned long clk_programmable_get_rate(struct clk *clk,
					       unsigned long parent_rate)
{
	struct clk_programmable *prog = clk->priv;
	const struct clk_programmable_layout *layout = prog->layout;
	unsigned int pckr = io_read32(prog->base + AT91_PMC_PCKR(prog->id));
	unsigned long rate = 0;

	if (layout->is_pres_direct)
		rate = parent_rate / (PROG_PRES(layout, pckr) + 1);
	else
		rate = parent_rate >> PROG_PRES(layout, pckr);

	return rate;
}

static TEE_Result clk_programmable_set_parent(struct clk *clk, size_t index)
{
	struct clk_programmable *prog = clk->priv;
	const struct clk_programmable_layout *layout = prog->layout;
	unsigned int mask = layout->css_mask;
	unsigned int pckr = index;

	if (layout->have_slck_mck)
		mask |= AT91_PMC_CSSMCK_MCK;

	if (index > layout->css_mask) {
		if (index > PROG_MAX_RM9200_CSS && !layout->have_slck_mck)
			return TEE_ERROR_BAD_PARAMETERS;

		pckr |= AT91_PMC_CSSMCK_MCK;
	}

	io_clrsetbits32(prog->base + AT91_PMC_PCKR(prog->id), mask, pckr);

	return TEE_SUCCESS;
}

static size_t clk_programmable_get_parent(struct clk *clk)
{
	struct clk_programmable *prog = clk->priv;
	const struct clk_programmable_layout *layout = prog->layout;
	unsigned int pckr = io_read32(prog->base + AT91_PMC_PCKR(prog->id));
	size_t ret = 0;

	ret = pckr & layout->css_mask;

	if (layout->have_slck_mck && (pckr & AT91_PMC_CSSMCK_MCK) && !ret)
		ret = PROG_MAX_RM9200_CSS + 1;

	return ret;
}

static unsigned int flsi(unsigned int val)
{
	if (val == 0)
		return 0;

	return sizeof(unsigned int) * 8 - __builtin_clz(val);
}

static TEE_Result clk_programmable_set_rate(struct clk *clk, unsigned long rate,
					    unsigned long parent_rate)
{
	struct clk_programmable *prog = clk->priv;
	const struct clk_programmable_layout *layout = prog->layout;
	unsigned long div = parent_rate / rate;
	int shift = 0;

	if (!div)
		return TEE_ERROR_BAD_PARAMETERS;

	if (layout->is_pres_direct) {
		shift = div - 1;

		if (shift > layout->pres_mask)
			return TEE_ERROR_BAD_PARAMETERS;
	} else {
		shift = flsi(div) - 1;

		if (div != (1ULL << shift))
			return TEE_ERROR_BAD_PARAMETERS;

		if (shift >= layout->pres_mask)
			return TEE_ERROR_BAD_PARAMETERS;
	}

	io_clrsetbits32(prog->base + AT91_PMC_PCKR(prog->id),
			layout->pres_mask << layout->pres_shift,
			shift << layout->pres_shift);

	return TEE_SUCCESS;
}

static const struct clk_ops programmable_ops = {
	.get_rate = clk_programmable_get_rate,
	.get_parent = clk_programmable_get_parent,
	.set_parent = clk_programmable_set_parent,
	.set_rate = clk_programmable_set_rate,
};

struct clk *
at91_clk_register_programmable(struct pmc_data *pmc,
			       const char *name, struct clk **parents,
			       uint8_t num_parents, uint8_t id,
			       const struct clk_programmable_layout *layout)
{
	struct clk_programmable *prog = NULL;
	struct clk *clk = NULL;

	assert(id <= PROG_ID_MAX);

	clk = clk_alloc(name, &programmable_ops, parents, num_parents);
	prog = calloc(1, sizeof(*prog));
	if (!prog || !clk)
		return NULL;

	prog->id = id;
	prog->layout = layout;
	prog->base = pmc->base;

	clk->priv = prog;
	clk->flags = CLK_SET_RATE_GATE | CLK_SET_PARENT_GATE;

	if (clk_register(clk)) {
		clk_free(clk);
		free(prog);
		return NULL;
	}

	pmc_register_pck(id);

	return clk;
}
