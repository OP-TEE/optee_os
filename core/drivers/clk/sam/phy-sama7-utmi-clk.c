// SPDX-License-Identifier: BSD-2-Clause
/*
 * Driver for the Microchip SAMA7 USB 2.0 PHY Clock
 *
 * Copyright (C) 2024 Microchip Technology, Inc. and its subsidiaries
 *
 * Author: Tony Han <tony.han@microchip.com>
 *
 */

#include <drivers/atmel_rstc.h>
#include <io.h>
#include <kernel/delay.h>
#include <mm/core_memprot.h>
#include <sam_sfr.h>
#include "at91_clk.h"

#define SAMA7_SFR_UTMI0R(x) (0x2040 + 4 * (x)) /* offset of SFR_UTMI0Rx */
#define SAMA7_SFR_UTMI_COMMONON BIT(3) /* PLL Common ON bit */

struct sama7_utmi_clk {
	vaddr_t base;
	uint8_t id;
};

static TEE_Result sama7_utmi_clk_enable(struct clk *hw)
{
	struct sama7_utmi_clk *utmi = hw->priv;
	uint8_t id = utmi->id;

	sam_rstc_usb_por(id, true);
	io_clrbits32(utmi->base + SAMA7_SFR_UTMI0R(id),
		     SAMA7_SFR_UTMI_COMMONON);
	sam_rstc_usb_por(id, false);

	/* Datasheet states a minimum of 45 us before any USB operation */
	udelay(50);

	return TEE_SUCCESS;
}

static void sama7_utmi_clk_disable(struct clk *hw)
{
	struct sama7_utmi_clk *utmi = hw->priv;
	uint8_t id = utmi->id;

	sam_rstc_usb_por(id, true);
	io_setbits32(utmi->base + SAMA7_SFR_UTMI0R(id),
		     SAMA7_SFR_UTMI_COMMONON);
}

static const struct clk_ops sama7_utmi_ops = {
	.enable = sama7_utmi_clk_enable,
	.disable = sama7_utmi_clk_disable,
};

struct clk *sama7_utmi_clk_register(const char *name,
				    struct clk *parent,
				    uint8_t id)
{
	struct clk *hw = NULL;
	struct sama7_utmi_clk *utmi_clk = NULL;

	hw = clk_alloc(name, &sama7_utmi_ops, &parent, 1);
	if (!hw)
		return NULL;

	utmi_clk = calloc(1, sizeof(*utmi_clk));
	if (!utmi_clk) {
		clk_free(hw);
		return NULL;
	}

	utmi_clk->base = sam_sfr_base();
	utmi_clk->id = id;
	hw->priv = utmi_clk;

	if (clk_register(hw)) {
		clk_free(hw);
		free(utmi_clk);
		return NULL;
	}

	return hw;
}
