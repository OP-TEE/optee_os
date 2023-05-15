// SPDX-License-Identifier: GPL-2.0+ or BSD-3-Clause
/*
 *  Copyright (C) 2016 Atmel Corporation,
 *		       Songjun Wu <songjun.wu@atmel.com>,
 *		       Nicolas Ferre <nicolas.ferre@atmel.com>
 *  Copyright (C) 2017 Free Electrons,
 *		       Quentin Schulz <quentin.schulz@free-electrons.com>
 *
 * The Sama5d2 SoC has two audio PLLs (PMC and PAD) that shares the same parent
 * (FRAC). FRAC can output between 620 and 700MHz and only multiply the rate of
 * its own parent. PMC and PAD can then divide the FRAC rate to best match the
 * asked rate.
 *
 * Traits of FRAC clock:
 * enable - clk_enable writes nd, fracr parameters and enables PLL
 * rate - rate is adjustable.
 *        clk->rate = parent->rate * ((nd + 1) + (fracr / 2^22))
 * parent - fixed parent.  No clk_set_parent support
 *
 * Traits of PMC clock:
 * enable - clk_enable writes qdpmc, and enables PMC output
 * rate - rate is adjustable.
 *        clk->rate = parent->rate / (qdpmc + 1)
 * parent - fixed parent.  No clk_set_parent support
 *
 * Traits of PAD clock:
 * enable - clk_enable writes divisors and enables PAD output
 * rate - rate is adjustable.
 *        clk->rate = parent->rate / (qdaudio * div))
 * parent - fixed parent.  No clk_set_parent support
 */

#include <io.h>
#include <kernel/delay.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <string.h>
#include <types_ext.h>

#include "at91_clk.h"

#define AUDIO_PLL_DIV_FRAC	BIT(22)
#define AUDIO_PLL_ND_MAX	(AT91_PMC_AUDIO_PLL_ND_MASK >> \
					AT91_PMC_AUDIO_PLL_ND_OFFSET)

#define AUDIO_PLL_QDPAD(qd, div) \
				((AT91_PMC_AUDIO_PLL_QDPAD_EXTDIV(qd) & \
				  AT91_PMC_AUDIO_PLL_QDPAD_EXTDIV_MASK) | \
				 (AT91_PMC_AUDIO_PLL_QDPAD_DIV(div) & \
				  AT91_PMC_AUDIO_PLL_QDPAD_DIV_MASK))

#define AUDIO_PLL_QDPMC_MAX		(AT91_PMC_AUDIO_PLL_QDPMC_MASK >> \
						AT91_PMC_AUDIO_PLL_QDPMC_OFFSET)

#define AUDIO_PLL_FOUT_MIN	620000000UL
#define AUDIO_PLL_FOUT_MAX	700000000UL

struct clk_audio_frac {
	vaddr_t base;
	uint32_t fracr;
	uint8_t nd;
};

struct clk_audio_pad {
	vaddr_t base;
	uint8_t qdaudio;
	uint8_t div;
};

struct clk_audio_pmc {
	vaddr_t base;
	uint8_t qdpmc;
};

static TEE_Result clk_audio_pll_frac_enable(struct clk *clk)
{
	struct clk_audio_frac *frac = clk->priv;

	io_clrbits32(frac->base + AT91_PMC_AUDIO_PLL0,
		     AT91_PMC_AUDIO_PLL_RESETN);
	io_setbits32(frac->base + AT91_PMC_AUDIO_PLL0,
		     AT91_PMC_AUDIO_PLL_RESETN);
	io_clrsetbits32(frac->base + AT91_PMC_AUDIO_PLL1,
			AT91_PMC_AUDIO_PLL_FRACR_MASK, frac->fracr);

	/*
	 * reset and enable have to be done in 2 separated writes
	 * for AT91_PMC_AUDIO_PLL0
	 */
	io_clrsetbits32(frac->base + AT91_PMC_AUDIO_PLL0,
			AT91_PMC_AUDIO_PLL_PLLEN |
			AT91_PMC_AUDIO_PLL_ND_MASK,
			AT91_PMC_AUDIO_PLL_PLLEN |
			AT91_PMC_AUDIO_PLL_ND(frac->nd));

	return TEE_SUCCESS;
}

static TEE_Result clk_audio_pll_pad_enable(struct clk *clk)
{
	struct clk_audio_pad *apad_ck = clk->priv;

	io_clrsetbits32(apad_ck->base + AT91_PMC_AUDIO_PLL1,
			AT91_PMC_AUDIO_PLL_QDPAD_MASK,
			AUDIO_PLL_QDPAD(apad_ck->qdaudio, apad_ck->div));
	io_clrsetbits32(apad_ck->base + AT91_PMC_AUDIO_PLL0,
			AT91_PMC_AUDIO_PLL_PADEN, AT91_PMC_AUDIO_PLL_PADEN);

	return TEE_SUCCESS;
}

static TEE_Result clk_audio_pll_pmc_enable(struct clk *clk)
{
	struct clk_audio_pmc *apmc_ck = clk->priv;

	io_clrsetbits32(apmc_ck->base + AT91_PMC_AUDIO_PLL0,
			AT91_PMC_AUDIO_PLL_PMCEN |
			AT91_PMC_AUDIO_PLL_QDPMC_MASK,
			AT91_PMC_AUDIO_PLL_PMCEN |
			AT91_PMC_AUDIO_PLL_QDPMC(apmc_ck->qdpmc));
	return TEE_SUCCESS;
}

static void clk_audio_pll_frac_disable(struct clk *clk)
{
	struct clk_audio_frac *frac = clk->priv;

	io_clrbits32(frac->base + AT91_PMC_AUDIO_PLL0,
		     AT91_PMC_AUDIO_PLL_PLLEN);
	/* Requires 2 separated writes */
	io_clrbits32(frac->base + AT91_PMC_AUDIO_PLL0,
		     AT91_PMC_AUDIO_PLL_RESETN);
}

static void clk_audio_pll_pad_disable(struct clk *clk)
{
	struct clk_audio_pad *apad_ck = clk->priv;

	io_clrbits32(apad_ck->base + AT91_PMC_AUDIO_PLL0,
		     AT91_PMC_AUDIO_PLL_PADEN);
}

static void clk_audio_pll_pmc_disable(struct clk *clk)
{
	struct clk_audio_pmc *apmc_ck = clk->priv;

	io_clrbits32(apmc_ck->base + AT91_PMC_AUDIO_PLL0,
		     AT91_PMC_AUDIO_PLL_PMCEN);
}

static unsigned long clk_audio_pll_fout(unsigned long parent_rate,
					unsigned long nd, unsigned long fracr)
{
	unsigned long long fr = (unsigned long long)parent_rate * fracr;

	fr = UDIV_ROUND_NEAREST(fr, AUDIO_PLL_DIV_FRAC);

	return parent_rate * (nd + 1) + fr;
}

static unsigned long clk_audio_pll_frac_get_rate(struct clk *clk,
						 unsigned long parent_rate)
{
	struct clk_audio_frac *frac = clk->priv;

	return clk_audio_pll_fout(parent_rate, frac->nd, frac->fracr);
}

static unsigned long clk_audio_pll_pad_get_rate(struct clk *clk,
						unsigned long parent_rate)
{
	struct clk_audio_pad *apad_ck = clk->priv;
	unsigned long apad_rate = 0;

	if (apad_ck->qdaudio && apad_ck->div)
		apad_rate = parent_rate / (apad_ck->qdaudio * apad_ck->div);

	return apad_rate;
}

static unsigned long clk_audio_pll_pmc_get_rate(struct clk *clk,
						unsigned long parent_rate)
{
	struct clk_audio_pmc *apmc_ck = clk->priv;

	return parent_rate / (apmc_ck->qdpmc + 1);
}

static TEE_Result clk_audio_pll_frac_compute_frac(unsigned long rate,
						  unsigned long parent_rate,
						  unsigned long *nd,
						  unsigned long *fracr)
{
	unsigned long long tmp = 0;
	unsigned long long rem = 0;

	if (!rate || !parent_rate)
		return TEE_ERROR_BAD_PARAMETERS;

	tmp = rate;
	rem = tmp % parent_rate;
	tmp /= parent_rate;
	if (!tmp || tmp >= AUDIO_PLL_ND_MAX)
		return TEE_ERROR_BAD_PARAMETERS;

	*nd = tmp - 1;

	tmp = rem * AUDIO_PLL_DIV_FRAC;
	tmp = UDIV_ROUND_NEAREST(tmp, parent_rate);
	if (tmp > AT91_PMC_AUDIO_PLL_FRACR_MASK)
		return TEE_ERROR_BAD_PARAMETERS;

	/* we can cast here as we verified the bounds just above */
	*fracr = (unsigned long)tmp;

	return TEE_SUCCESS;
}

static TEE_Result clk_audio_pll_frac_set_rate(struct clk *clk,
					      unsigned long rate,
					      unsigned long parent_rate)
{
	struct clk_audio_frac *frac = clk->priv;
	unsigned long fracr = 0;
	unsigned long nd = 0;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (rate < AUDIO_PLL_FOUT_MIN || rate > AUDIO_PLL_FOUT_MAX)
		return TEE_ERROR_BAD_PARAMETERS;

	res = clk_audio_pll_frac_compute_frac(rate, parent_rate, &nd, &fracr);
	if (res)
		return res;

	frac->nd = nd;
	frac->fracr = fracr;

	return TEE_SUCCESS;
}

static TEE_Result clk_audio_pll_pad_set_rate(struct clk *clk,
					     unsigned long rate,
					     unsigned long parent_rate)
{
	struct clk_audio_pad *apad_ck = clk->priv;
	uint8_t tmp_div = 1;

	if (!rate)
		return TEE_ERROR_BAD_PARAMETERS;

	tmp_div = parent_rate / rate;
	if (tmp_div % 3 == 0) {
		apad_ck->qdaudio = tmp_div / 3;
		apad_ck->div = 3;
	} else {
		apad_ck->qdaudio = tmp_div / 2;
		apad_ck->div = 2;
	}

	return TEE_SUCCESS;
}

static TEE_Result clk_audio_pll_pmc_set_rate(struct clk *clk,
					     unsigned long rate,
					     unsigned long parent_rate)
{
	struct clk_audio_pmc *apmc_ck = clk->priv;

	if (!rate)
		return TEE_ERROR_BAD_PARAMETERS;

	apmc_ck->qdpmc = parent_rate / rate - 1;

	return TEE_SUCCESS;
}

static const struct clk_ops audio_pll_frac_ops = {
	.enable = clk_audio_pll_frac_enable,
	.disable = clk_audio_pll_frac_disable,
	.get_rate = clk_audio_pll_frac_get_rate,
	.set_rate = clk_audio_pll_frac_set_rate,
};

static const struct clk_ops audio_pll_pad_ops = {
	.enable = clk_audio_pll_pad_enable,
	.disable = clk_audio_pll_pad_disable,
	.get_rate = clk_audio_pll_pad_get_rate,
	.set_rate = clk_audio_pll_pad_set_rate,
};

static const struct clk_ops audio_pll_pmc_ops = {
	.enable = clk_audio_pll_pmc_enable,
	.disable = clk_audio_pll_pmc_disable,
	.get_rate = clk_audio_pll_pmc_get_rate,
	.set_rate = clk_audio_pll_pmc_set_rate,
};

struct clk *
at91_clk_register_audio_pll_frac(struct pmc_data *pmc, const char *name,
				 struct clk *parent)
{
	struct clk_audio_frac *frac_ck = NULL;
	struct clk *clk = NULL;

	clk = clk_alloc(name, &audio_pll_frac_ops, &parent, 1);
	if (!clk)
		return NULL;

	frac_ck = calloc(1, sizeof(*frac_ck));
	if (!frac_ck) {
		clk_free(clk);
		return NULL;
	}

	clk->flags = CLK_SET_RATE_GATE;

	frac_ck->base = pmc->base;

	clk->priv = frac_ck;
	if (clk_register(clk)) {
		clk_free(clk);
		free(frac_ck);
		return NULL;
	}

	return clk;
}

struct clk *
at91_clk_register_audio_pll_pad(struct pmc_data *pmc, const char *name,
				struct clk *parent)
{
	struct clk_audio_pad *apad_ck = NULL;
	struct clk *clk = NULL;

	clk = clk_alloc(name, &audio_pll_pad_ops, &parent, 1);
	if (!clk)
		return NULL;

	apad_ck = calloc(1, sizeof(*apad_ck));
	if (!apad_ck) {
		clk_free(clk);
		return NULL;
	}

	clk->flags = CLK_SET_RATE_GATE | CLK_SET_PARENT_GATE;

	apad_ck->base = pmc->base;

	clk->priv = apad_ck;
	if (clk_register(clk)) {
		clk_free(clk);
		free(apad_ck);
		return NULL;
	}

	return clk;
}

struct clk *
at91_clk_register_audio_pll_pmc(struct pmc_data *pmc, const char *name,
				struct clk *parent)
{
	struct clk_audio_pmc *apmc_ck = NULL;
	struct clk *clk = NULL;

	clk = clk_alloc(name, &audio_pll_pmc_ops, &parent, 1);
	if (!clk)
		return NULL;

	apmc_ck = calloc(1, sizeof(*apmc_ck));
	if (!apmc_ck) {
		clk_free(clk);
		return NULL;
	}

	clk->flags = CLK_SET_RATE_GATE | CLK_SET_PARENT_GATE;

	apmc_ck->base = pmc->base;

	clk->priv = apmc_ck;

	if (clk_register(clk)) {
		clk_free(clk);
		free(apmc_ck);
		return NULL;
	}

	return clk;
}
