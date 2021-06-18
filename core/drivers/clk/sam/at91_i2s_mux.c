// SPDX-License-Identifier: GPL-2.0+ or BSD-3-Clause
/*
 *  Copyright (C) 2018 Microchip Technology Inc,
 *                     Codrin Ciubotariu <codrin.ciubotariu@microchip.com>
 */

#include <io.h>
#include <kernel/delay.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <sam_sfr.h>
#include <types_ext.h>

#include "at91_clk.h"

struct clk_i2s_mux {
	vaddr_t sfr_base;
	uint8_t bus_id;
};

static size_t clk_i2s_mux_get_parent(struct clk *clk)
{
	struct clk_i2s_mux *mux = clk->priv;
	uint32_t val = io_read32(mux->sfr_base + AT91_SFR_I2SCLKSEL);

	return (val & BIT(mux->bus_id)) >> mux->bus_id;
}

static TEE_Result clk_i2s_mux_set_parent(struct clk *clk, size_t index)
{
	struct clk_i2s_mux *mux = clk->priv;

	io_clrsetbits32(mux->sfr_base + AT91_SFR_I2SCLKSEL,
			BIT(mux->bus_id), index << mux->bus_id);

	return TEE_SUCCESS;
}

static const struct clk_ops clk_i2s_mux_ops = {
	.get_parent = clk_i2s_mux_get_parent,
	.set_parent = clk_i2s_mux_set_parent,
};

struct clk *
at91_clk_i2s_mux_register(const char *name, struct clk **parents,
			  unsigned int num_parents, uint8_t bus_id)
{
	struct clk_i2s_mux *i2s_ck = NULL;
	struct clk *clk = NULL;

	clk = clk_alloc(name, &clk_i2s_mux_ops, parents, num_parents);
	if (!clk)
		return NULL;

	i2s_ck = calloc(1, sizeof(*i2s_ck));
	if (!i2s_ck) {
		clk_free(clk);
		return NULL;
	}

	i2s_ck->bus_id = bus_id;
	i2s_ck->sfr_base = sam_sfr_base();

	clk->priv = i2s_ck;

	if (clk_register(clk)) {
		clk_free(clk);
		free(i2s_ck);
		return NULL;
	}

	return clk;
}
