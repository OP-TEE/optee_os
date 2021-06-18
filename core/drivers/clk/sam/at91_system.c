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

#define SYSTEM_MAX_ID		31

#define SYSTEM_MAX_NAME_SZ	32

struct clk_system {
	vaddr_t base;
	uint8_t id;
};

static bool is_pck(int id)
{
	return (id >= 8) && (id <= 15);
}

static bool clk_system_ready(vaddr_t base, int id)
{
	uint32_t status = io_read32(base + AT91_PMC_SR);

	return status & BIT(id);
}

static TEE_Result clk_system_enable(struct clk *clk)
{
	struct clk_system *sys = clk->priv;

	io_write32(sys->base + AT91_PMC_SCER, 1 << sys->id);

	if (!is_pck(sys->id))
		return TEE_SUCCESS;

	while (!clk_system_ready(sys->base, sys->id))
		;

	return TEE_SUCCESS;
}

static void clk_system_disable(struct clk *clk)
{
	struct clk_system *sys = clk->priv;

	io_write32(sys->base + AT91_PMC_SCDR, 1 << sys->id);
}

static const struct clk_ops system_ops = {
	.enable = clk_system_enable,
	.disable = clk_system_disable,
};

struct clk *
at91_clk_register_system(struct pmc_data *pmc, const char *name,
			 struct clk *parent, uint8_t id)
{
	struct clk_system *sys = NULL;
	struct clk *clk = NULL;

	if (!parent || id > SYSTEM_MAX_ID)
		return NULL;

	clk = clk_alloc(name, &system_ops, &parent, 1);
	if (!clk)
		return NULL;

	sys = calloc(1, sizeof(*sys));
	if (!sys) {
		clk_free(clk);
		return NULL;
	}

	sys->id = id;
	sys->base = pmc->base;

	clk->priv = sys;

	if (clk_register(clk)) {
		clk_free(clk);
		free(sys);
		return NULL;
	}

	return clk;
}
