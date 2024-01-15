// SPDX-License-Identifier: GPL-2.0+ or BSD-3-Clause
/*
 *  Copyright (C) 2013 Boris BREZILLON <b.brezillon@overkiz.com>
 *  Copyright (C) 2021 Microchip
 */

#include <io.h>
#include <kernel/delay.h>
#include <mm/core_memprot.h>
#include <sam_sfr.h>
#include <types_ext.h>

#include "at91_clk.h"

/*
 * The purpose of this clock is to generate a 480 MHz signal. A different
 * rate can't be configured.
 */
#define UTMI_RATE	480000000

struct clk_utmi {
	vaddr_t pmc_base;
	vaddr_t sfr_base;
};

static bool clk_utmi_ready(vaddr_t pmc_base)
{
	uint32_t status = io_read32(pmc_base + AT91_PMC_SR);

	return status & AT91_PMC_LOCKU;
}

static TEE_Result clk_utmi_enable(struct clk *clk)
{
	struct clk *clk_parent = NULL;
	struct clk_utmi *utmi = clk->priv;
	unsigned int uckr = AT91_PMC_UPLLEN | AT91_PMC_UPLLCOUNT |
			    AT91_PMC_BIASEN;
	unsigned int utmi_ref_clk_freq = 0;
	unsigned long parent_rate = 0;

	/*
	 * If mainck rate is different from 12 MHz, we have to configure the
	 * FREQ field of the SFR_UTMICKTRIM register to generate properly
	 * the utmi clock.
	 */
	clk_parent = clk_get_parent(clk);
	parent_rate = clk_get_rate(clk_parent);

	switch (parent_rate) {
	case 12000000:
		utmi_ref_clk_freq = 0;
		break;
	case 16000000:
		utmi_ref_clk_freq = 1;
		break;
	case 24000000:
		utmi_ref_clk_freq = 2;
		break;
	/*
	 * Not supported on SAMA5D2 but it's not an issue since MAINCK
	 * maximum value is 24 MHz.
	 */
	case 48000000:
		utmi_ref_clk_freq = 3;
		break;
	default:
		EMSG("UTMICK: unsupported mainck rate");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (utmi->sfr_base) {
		io_clrsetbits32(utmi->sfr_base + AT91_SFR_UTMICKTRIM,
				AT91_UTMICKTRIM_FREQ, utmi_ref_clk_freq);
	} else if (utmi_ref_clk_freq) {
		EMSG("UTMICK: sfr node required");
		return TEE_ERROR_BAD_STATE;
	}

	io_clrsetbits32(utmi->pmc_base + AT91_CKGR_UCKR, uckr, uckr);

	while (!clk_utmi_ready(utmi->pmc_base))
		;

	return TEE_SUCCESS;
}

static void clk_utmi_disable(struct clk *clk)
{
	struct clk_utmi *utmi = clk->priv;

	io_clrbits32(utmi->pmc_base + AT91_CKGR_UCKR, AT91_PMC_UPLLEN);
}

static unsigned long clk_utmi_get_rate(struct clk *clk __unused,
				       unsigned long parent_rate __unused)
{
	/* UTMI clk rate is fixed. */
	return UTMI_RATE;
}

static const struct clk_ops utmi_ops = {
	.enable = clk_utmi_enable,
	.disable = clk_utmi_disable,
	.get_rate = clk_utmi_get_rate,
};

static struct clk *at91_clk_register_utmi_internal(struct pmc_data *pmc,
						   const char *name,
						   const struct clk_ops *ops,
						   struct clk *parent)
{
	struct clk_utmi *utmi = NULL;
	struct clk *clk = NULL;

	clk = clk_alloc(name, ops, &parent, 1);
	if (!clk)
		return NULL;

	utmi = calloc(1, sizeof(*utmi));
	if (!utmi) {
		clk_free(clk);
		return NULL;
	}

	utmi->pmc_base = pmc->base;
	utmi->sfr_base = sam_sfr_base();
	clk->flags = CLK_SET_RATE_GATE;

	clk->priv = utmi;

	if (clk_register(clk)) {
		clk_free(clk);
		free(utmi);
		return NULL;
	}

	return clk;
}

struct clk *at91_clk_register_utmi(struct pmc_data *pmc,
				   const char *name,
				   struct clk *parent)
{
	return at91_clk_register_utmi_internal(pmc, name, &utmi_ops, parent);
}

static TEE_Result clk_utmi_sama7g5_prepare(struct clk *clk)
{
	struct clk *clk_parent = NULL;
	struct clk_utmi *utmi = clk->priv;
	unsigned long parent_rate = 0;
	uint32_t val = 0;

	clk_parent = clk_get_parent(clk);
	parent_rate = clk_get_rate(clk_parent);

	switch (parent_rate) {
	case 16000000:
		val = 0;
		break;
	case 20000000:
		val = 2;
		break;
	case 24000000:
		val = 3;
		break;
	case 32000000:
		val = 5;
		break;
	default:
		EMSG("UTMICK: unsupported main_xtal rate");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	io_clrsetbits32(utmi->pmc_base + AT91_PMC_XTALF, AT91_PMC_XTALF_XTALF,
			val);

	return TEE_SUCCESS;
}

static const struct clk_ops sama7g5_utmi_ops = {
	.enable = clk_utmi_sama7g5_prepare,
	.get_rate = clk_utmi_get_rate,
};

struct clk *at91_clk_sama7g5_register_utmi(struct pmc_data *pmc,
					   const char *name,
					   struct clk *parent)
{
	return at91_clk_register_utmi_internal(pmc, name, &sama7g5_utmi_ops,
					       parent);
}
