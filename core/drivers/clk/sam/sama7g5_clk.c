// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2024, Microchip
 */

#include <assert.h>
#include <dt-bindings/clock/at91.h>
#include <io.h>
#include <kernel/boot.h>
#include <kernel/dt.h>
#include <kernel/panic.h>
#include <libfdt.h>
#include <matrix.h>
#include <sama7g5.h>
#include <stdint.h>
#include <util.h>
#include "at91_clk.h"

#define CLK_IS_CRITICAL 0

/* PLL clocks identifiers */
enum pll_ids {
	PLL_ID_CPU,
	PLL_ID_SYS,
	PLL_ID_DDR,
	PLL_ID_IMG,
	PLL_ID_BAUD,
	PLL_ID_AUDIO,
	PLL_ID_ETH,
	PLL_ID_MAX,
};

/* PLL type identifiers */
enum pll_type {
	PLL_TYPE_FRAC,
	PLL_TYPE_DIV,
	PLL_TYPE_CNT,
};

/* Layout for fractional PLLs */
static const struct clk_pll_layout pll_layout_frac = {
	.mul_mask	= GENMASK_32(31, 24),
	.frac_mask	= GENMASK_32(21, 0),
	.mul_shift	= 24,
	.frac_shift	= 0,
};

/* Layout for DIVPMC dividers */
static const struct clk_pll_layout pll_layout_divpmc = {
	.div_mask	= GENMASK_32(7, 0),
	.endiv_mask	= BIT(29),
	.div_shift	= 0,
	.endiv_shift	= 29,
};

/* Layout for DIVIO dividers */
static const struct clk_pll_layout pll_layout_divio = {
	.div_mask	= GENMASK_32(19, 12),
	.endiv_mask	= BIT(30),
	.div_shift	= 12,
	.endiv_shift	= 30,
};

/*
 * CPU PLL output range
 * Notice: The upper limit has been setup to 1000000002 due to hardware
 * block which cannot output exactly 1GHz.
 */
static const struct clk_range cpu_pll_output[] = {
	{ .min = 2343750, .max = 1000000002 },
};

/* PLL output range */
static const struct clk_range pll_output[] = {
	{ .min = 2343750, .max = 1200000000 },
};

/* CPU PLL characteristics */
static const struct clk_pll_charac cpu_pll_characteristics = {
	.input = { .min = 12000000, .max = 50000000 },
	.num_output = ARRAY_SIZE(cpu_pll_output),
	.output = cpu_pll_output,
};

/* PLL characteristics */
static const struct clk_pll_charac pll_characteristics = {
	.input = { .min = 12000000, .max = 50000000 },
	.num_output = ARRAY_SIZE(pll_output),
	.output = pll_output,
};

/* PLL clocks description */
struct sama7g5_pll {
	const char *name;
	const char *parent;
	const struct clk_pll_layout *layout;
	const struct clk_pll_charac *charac;
	unsigned long flags;
	uint8_t type;
	uint8_t eid; /* export index in sama7g5->chws[] array */
	uint8_t safe_div; /* intermediate divider need to be set on
			   * PRE_RATE_CHANGE notification
			   */
};

static const struct sama7g5_pll sama7g5_plls[][PLL_ID_MAX] = {
	[PLL_ID_CPU] = {
		{
			.name = "cpupll_fracck",
			.parent = "mainck",
			.layout = &pll_layout_frac,
			.charac = &cpu_pll_characteristics,
			.type = PLL_TYPE_FRAC,
			/*
			 * This feeds cpupll_divpmcck which feeds CPU. It
			 * should not be disabled.
			 */
			.flags = CLK_IS_CRITICAL,
		},
		{
			.name = "cpupll_divpmcck",
			.parent = "cpupll_fracck",
			.layout = &pll_layout_divpmc,
			.charac = &cpu_pll_characteristics,
			.type = PLL_TYPE_DIV,
			/* This feeds CPU. It should not be disabled. */
			.flags = CLK_IS_CRITICAL,
			.eid = PMC_CPUPLL,
			/*
			 * Safe div=15 should be safe even for switching b/w
			 * 1GHz and 90MHz (frac pll might go up to 1.2GHz).
			 */
			.safe_div = 15,
		},
	},

	[PLL_ID_SYS] = {
		{
			.name = "syspll_fracck",
			.parent = "mainck",
			.layout = &pll_layout_frac,
			.charac = &pll_characteristics,
			.type = PLL_TYPE_FRAC,
			/*
			 * This feeds syspll_divpmcck which may feed critical
			 * parts of the systems like timers. Therefore it
			 * should not be disabled.
			 */
			.flags = CLK_IS_CRITICAL | CLK_SET_RATE_GATE,
		},
		{
			.name = "syspll_divpmcck",
			.parent = "syspll_fracck",
			.layout = &pll_layout_divpmc,
			.charac = &pll_characteristics,
			.type = PLL_TYPE_DIV,
			/*
			 * This may feed critical parts of the systems like
			 * timers. Therefore it should not be disabled.
			 */
			.flags = CLK_IS_CRITICAL | CLK_SET_RATE_GATE,
			.eid = PMC_SYSPLL,
		},
	},

	[PLL_ID_DDR] = {
		{
			.name = "ddrpll_fracck",
			.parent = "mainck",
			.layout = &pll_layout_frac,
			.charac = &pll_characteristics,
			.type = PLL_TYPE_FRAC,
			/*
			 * This feeds ddrpll_divpmcck which feeds DDR. It
			 * should not be disabled.
			 */
			.flags = CLK_IS_CRITICAL | CLK_SET_RATE_GATE,
		},
		{
			.name = "ddrpll_divpmcck",
			.parent = "ddrpll_fracck",
			.layout = &pll_layout_divpmc,
			.charac = &pll_characteristics,
			.type = PLL_TYPE_DIV,
			/* This feeds DDR. It should not be disabled. */
			.flags = CLK_IS_CRITICAL | CLK_SET_RATE_GATE,
			.eid = PMC_DDRPLL,
		},
	},

	[PLL_ID_IMG] = {
		{
			.name = "imgpll_fracck",
			.parent = "mainck",
			.layout = &pll_layout_frac,
			.charac = &pll_characteristics,
			.type = PLL_TYPE_FRAC,
			.flags = CLK_SET_RATE_GATE,
		},
		{
			.name = "imgpll_divpmcck",
			.parent = "imgpll_fracck",
			.layout = &pll_layout_divpmc,
			.charac = &pll_characteristics,
			.type = PLL_TYPE_DIV,
			.flags = CLK_SET_RATE_GATE | CLK_SET_PARENT_GATE,
			.eid = PMC_IMGPLL,
		},
	},

	[PLL_ID_BAUD] = {
		{
			.name = "baudpll_fracck",
			.parent = "mainck",
			.layout = &pll_layout_frac,
			.charac = &pll_characteristics,
			.type = PLL_TYPE_FRAC,
			.flags = CLK_SET_RATE_GATE,
		},
		{
			.name = "baudpll_divpmcck",
			.parent = "baudpll_fracck",
			.layout = &pll_layout_divpmc,
			.charac = &pll_characteristics,
			.type = PLL_TYPE_DIV,
			.flags = CLK_SET_RATE_GATE | CLK_SET_PARENT_GATE,
			.eid = PMC_BAUDPLL,
		},
	},

	[PLL_ID_AUDIO] = {
		{
			.name = "audiopll_fracck",
			.parent = "main_xtal",
			.layout = &pll_layout_frac,
			.charac = &pll_characteristics,
			.type = PLL_TYPE_FRAC,
			.flags = CLK_SET_RATE_GATE,
		},
		{
			.name = "audiopll_divck",
			.parent = "audiopll_fracck",
			.layout = &pll_layout_divpmc,
			.charac = &pll_characteristics,
			.type = PLL_TYPE_DIV,
			.flags = CLK_SET_RATE_GATE | CLK_SET_PARENT_GATE,
			.eid = PMC_AUDIOPMCPLL,
		},
		{
			.name = "audiopll_diviock",
			.parent = "audiopll_fracck",
			.layout = &pll_layout_divio,
			.charac = &pll_characteristics,
			.type = PLL_TYPE_DIV,
			.flags = CLK_SET_RATE_GATE | CLK_SET_PARENT_GATE,
			.eid = PMC_AUDIOIOPLL,
		},
	},

	[PLL_ID_ETH] = {
		{
			.name = "ethpll_fracck",
			.parent = "main_xtal",
			.layout = &pll_layout_frac,
			.charac = &pll_characteristics,
			.type = PLL_TYPE_FRAC,
			.flags = CLK_SET_RATE_GATE,
		},
		{
			.name = "ethpll_divpmcck",
			.parent = "ethpll_fracck",
			.layout = &pll_layout_divpmc,
			.charac = &pll_characteristics,
			.type = PLL_TYPE_DIV,
			.flags = CLK_SET_RATE_GATE | CLK_SET_PARENT_GATE,
			.eid = PMC_ETHPLL,
		},
	},
};

/*
 * Master clock (MCK[1..4]) description
 * @eparents:		extra parents names array
 * @eparents_chg_id:	index in parents array that specifies the changeable
 *			parent
 * @eparents_count:	extra parents count
 * @eparents_mux_table:	mux table for extra parents
 * @id:			clock id
 * @eid:		export index in sama7g5->chws[] array
 */
struct sama7g5_mck {
	const char *name;
	const char *eparents[4];
	int eparents_chg_id;
	uint8_t eparents_count;
	uint8_t eparents_mux_table[4];
	uint8_t id;
	uint8_t eid;
};

static const struct sama7g5_mck sama7g5_mckx[] = {
	{
		.name = "mck1",
		.id = 1,
		.eparents = { "syspll_divpmcck", },
		.eparents_mux_table = { 5, },
		.eparents_count = 1,
		.eparents_chg_id = INT_MIN,
		.eid = PMC_MCK1,
	},
	{
		.name = "mck2",
		.id = 2,
		.eparents = { "ddrpll_divpmcck", },
		.eparents_mux_table = { 6, },
		.eparents_count = 1,
		.eparents_chg_id = INT_MIN,
	},
	{
		.name = "mck3",
		.id = 3,
		.eparents = { "syspll_divpmcck",
			"ddrpll_divpmcck",
			"imgpll_divpmcck", },
		.eparents_mux_table = { 5, 6, 7, },
		.eparents_count = 3,
		.eparents_chg_id = 5,
	},
	{
		.name = "mck4",
		.id = 4,
		.eparents = { "syspll_divpmcck", },
		.eparents_mux_table = { 5, },
		.eparents_count = 1,
		.eparents_chg_id = INT_MIN,
	},
};

/* System clock description */
static const struct {
	const char *name;
	const char *parent;
	uint8_t id;
} sama7g5_systemck[] = {
	{ .name = "pck0", .parent = "prog0", .id = 8, },
	{ .name = "pck1", .parent = "prog1", .id = 9, },
	{ .name = "pck2", .parent = "prog2", .id = 10, },
	{ .name = "pck3", .parent = "prog3", .id = 11, },
	{ .name = "pck4", .parent = "prog4", .id = 12, },
	{ .name = "pck5", .parent = "prog5", .id = 13, },
	{ .name = "pck6", .parent = "prog6", .id = 14, },
	{ .name = "pck7", .parent = "prog7", .id = 15, },
};

/* Peripheral clock description */
static const struct {
	const char *name;
	const char *parent;
	struct clk_range output;
	uint8_t id;
} peri_clks[] = {
	{
		.name = "pioA_clk",
		.parent = "mck0",
		.id = 11,
	},
	{
		.name = "securam_clk",
		.parent = "mck0",
		.id = 18,
	},
	{
		.name = "sfr_clk",
		.parent = "mck1",
		.id = 19,
	},
	{
		.name = "hsmc_clk",
		.parent = "mck1",
		.id = 21,
	},
	{
		.name = "xdmac0_clk",
		.parent = "mck1",
		.id = 22,
	},
	{
		.name = "xdmac1_clk",
		.parent = "mck1",
		.id = 23,
	},
	{
		.name = "xdmac2_clk",
		.parent = "mck1",
		.id = 24,
	},
	{
		.name = "acc_clk",
		.parent = "mck1",
		.id = 25,
	},
	{
		.name = "aes_clk",
		.parent = "mck1",
		.id = 27,
	},
	{
		.name = "tzaesbasc_clk",
		.parent = "mck1",
		.id = 28,
	},
	{
		.name = "asrc_clk",
		.parent = "mck1",
		.id = 30,
		.output = { .max = 200000000, },
	},
	{
		.name = "cpkcc_clk",
		.parent = "mck0",
		.id = 32,
	},
	{
		.name = "csi_clk",
		.parent = "mck3",
		.id = 33,
		.output = { .max = 266000000, },
	},
	{
		.name = "csi2dc_clk",
		.parent = "mck3",
		.id = 34,
		.output = { .max = 266000000, },
	},
	{
		.name = "eic_clk",
		.parent = "mck1",
		.id = 37,
	},
	{
		.name = "flex0_clk",
		.parent = "mck1",
		.id = 38,
	},
	{
		.name = "flex1_clk",
		.parent = "mck1",
		.id = 39,
	},
	{
		.name = "flex2_clk",
		.parent = "mck1",
		.id = 40,
	},
	{
		.name = "flex3_clk",
		.parent = "mck1",
		.id = 41,
	},
	{
		.name = "flex4_clk",
		.parent = "mck1",
		.id = 42,
	},
	{
		.name = "flex5_clk",
		.parent = "mck1",
		.id = 43,
	},
	{
		.name = "flex6_clk",
		.parent = "mck1",
		.id = 44,
	},
	{
		.name = "flex7_clk",
		.parent = "mck1",
		.id = 45,
	},
	{
		.name = "flex8_clk",
		.parent = "mck1",
		.id = 46,
	},
	{
		.name = "flex9_clk",
		.parent = "mck1",
		.id = 47,
	},
	{
		.name = "flex10_clk",
		.parent = "mck1",
		.id = 48,
	},
	{
		.name = "flex11_clk",
		.parent = "mck1",
		.id = 49,
	},
	{
		.name = "gmac0_clk",
		.parent = "mck1",
		.id = 51,
	},
	{
		.name = "gmac1_clk",
		.parent = "mck1",
		.id = 52,
	},
	{
		.name = "icm_clk",
		.parent = "mck1",
		.id = 55,
	},
	{
		.name = "isc_clk",
		.parent = "mck3",
		.id = 56,
		.output = { .max = 266000000, },
	},
	{
		.name = "i2smcc0_clk",
		.parent = "mck1",
		.id = 57,
		.output = { .max = 200000000, },
	},
	{
		.name = "i2smcc1_clk",
		.parent = "mck1",
		.id = 58,
		.output = { .max = 200000000, },
	},
	{
		.name = "matrix_clk",
		.parent = "mck1",
		.id = 60, },
	{
		.name = "mcan0_clk",
		.parent = "mck1",
		.id = 61,
		.output = { .max = 200000000, },
	},
	{
		.name = "mcan1_clk",
		.parent = "mck1",
		.id = 62,
		.output = { .max = 200000000, },
	},
	{
		.name = "mcan2_clk",
		.parent = "mck1",
		.id = 63,
		.output = { .max = 200000000, },
	},
	{
		.name = "mcan3_clk",
		.parent = "mck1",
		.id = 64,
		.output = { .max = 200000000, },
	},
	{
		.name = "mcan4_clk",
		.parent = "mck1",
		.id = 65,
		.output = { .max = 200000000, },
	},
	{
		.name = "mcan5_clk",
		.parent = "mck1",
		.id = 66,
		.output = { .max = 200000000, },
	},
	{
		.name = "pdmc0_clk",
		.parent = "mck1",
		.id = 68,
		.output = { .max = 200000000, },
	},
	{
		.name = "pdmc1_clk",
		.parent = "mck1",
		.id = 69,
		.output = { .max = 200000000, },
	},
	{
		.name = "pit64b0_clk",
		.parent = "mck1",
		.id = 70,
	},
	{
		.name = "pit64b1_clk",
		.parent = "mck1",
		.id = 71,
	},
	{
		.name = "pit64b2_clk",
		.parent = "mck1",
		.id = 72,
	},
	{
		.name = "pit64b3_clk",
		.parent = "mck1",
		.id = 73,
	},
	{
		.name = "pit64b4_clk",
		.parent = "mck1",
		.id = 74,
	},
	{
		.name = "pit64b5_clk",
		.parent = "mck1",
		.id = 75,
	},
	{
		.name = "pwm_clk",
		.parent = "mck1",
		.id = 77,
	},
	{
		.name = "qspi0_clk",
		.parent = "mck1",
		.id = 78,
	},
	{
		.name = "qspi1_clk",
		.parent = "mck1",
		.id = 79,
	},
	{
		.name = "sdmmc0_clk",
		.parent = "mck1",
		.id = 80,
	},
	{
		.name = "sdmmc1_clk",
		.parent = "mck1",
		.id = 81,
	},
	{
		.name = "sdmmc2_clk",
		.parent = "mck1",
		.id = 82,
	},
	{
		.name = "sha_clk",
		.parent = "mck1",
		.id = 83,
	},
	{
		.name = "spdifrx_clk",
		.parent = "mck1",
		.id = 84,
		.output = { .max = 200000000, },
	},
	{
		.name = "spdiftx_clk",
		.parent = "mck1",
		.id = 85,
		.output = { .max = 200000000, },
	},
	{
		.name = "ssc0_clk",
		.parent = "mck1",
		.id = 86,
		.output = { .max = 200000000, },
	},
	{
		.name = "ssc1_clk",
		.parent = "mck1",
		.id = 87,
		.output = { .max = 200000000, },
	},
	{
		.name = "tcb0_ch0_clk",
		.parent = "mck1",
		.id = 88,
		.output = { .max = 200000000, },
	},
	{
		.name = "tcb0_ch1_clk",
		.parent = "mck1",
		.id = 89,
		.output = { .max = 200000000, },
	},
	{
		.name = "tcb0_ch2_clk",
		.parent = "mck1",
		.id = 90,
		.output = { .max = 200000000, },
	},
	{
		.name = "tcb1_ch0_clk",
		.parent = "mck1",
		.id = 91,
		.output = { .max = 200000000, },
	},
	{
		.name = "tcb1_ch1_clk",
		.parent = "mck1",
		.id = 92,
		.output = { .max = 200000000, },
	},
	{
		.name = "tcb1_ch2_clk",
		.parent = "mck1",
		.id = 93,
		.output = { .max = 200000000, },
	},
	{
		.name = "tcpca_clk",
		.parent = "mck1",
		.id = 94,
	},
	{
		.name = "tcpcb_clk",
		.parent = "mck1",
		.id = 95,
	},
	{
		.name = "tdes_clk",
		.parent = "mck1",
		.id = 96,
	},
	{
		.name = "trng_clk",
		.parent = "mck1",
		.id = 97,
	},
	{
		.name = "udphsa_clk",
		.parent = "mck1",
		.id = 104,
	},
	{
		.name = "udphsb_clk",
		.parent = "mck1",
		.id = 105,
	},
	{
		.name = "uhphs_clk",
		.parent = "mck1",
		.id = 106,
	},
};

/* UTMI clock description */
static struct {
	const char *name;
	const char *parent;
	uint8_t id;
} sama7_utmick[] = {
	{ .name = "utmi1", .parent = "utmick", .id = 0, },
	{ .name = "utmi2", .parent = "utmi1", .id = 1, },
	{ .name = "utmi3", .parent = "utmi1", .id = 2, },
};

/* Generic clock description */
struct sama7g5_gck {
	const char *name;
	const char *parents[8];
	const char parents_mux_table[8];
	struct clk_range output;
	int parents_chg_id; /* id in parent array of changeable PLL parent */
	uint8_t parents_count;
	uint8_t id;
};

static const struct sama7g5_gck sama7g5_gcks[] = {
	{
		.name  = "adc_gclk",
		.id = 26,
		.output = { .max = 100000000, },
		.parents = { "syspll_divpmcck",
			     "imgpll_divpmcck",
			     "audiopll_divck", },
		.parents_mux_table = { 5, 7, 9, },
		.parents_count = 3,
		.parents_chg_id = INT_MIN,
	},
	{
		.name  = "asrc_gclk",
		.id = 30,
		.output = { .max = 200000000 },
		.parents = { "audiopll_divck", },
		.parents_mux_table = { 9, },
		.parents_count = 1,
		.parents_chg_id = INT_MIN,
	},
	{
		.name  = "csi_gclk",
		.id = 33,
		.output = { .max = 27000000  },
		.parents = { "ddrpll_divpmcck", "imgpll_divpmcck", },
		.parents_mux_table = { 6, 7, },
		.parents_count = 2,
		.parents_chg_id = INT_MIN,
	},
	{
		.name  = "flex0_gclk",
		.id = 38,
		.output = { .max = 200000000 },
		.parents = { "syspll_divpmcck", "baudpll_divpmcck", },
		.parents_mux_table = { 5, 8, },
		.parents_count = 2,
		.parents_chg_id = INT_MIN,
	},
	{
		.name  = "flex1_gclk",
		.id = 39,
		.output = { .max = 200000000 },
		.parents = { "syspll_divpmcck", "baudpll_divpmcck", },
		.parents_mux_table = { 5, 8, },
		.parents_count = 2,
		.parents_chg_id = INT_MIN,
	},
	{
		.name  = "flex2_gclk",
		.id = 40,
		.output = { .max = 200000000 },
		.parents = { "syspll_divpmcck", "baudpll_divpmcck", },
		.parents_mux_table = { 5, 8, },
		.parents_count = 2,
		.parents_chg_id = INT_MIN,
	},
	{
		.name  = "flex3_gclk",
		.id = 41,
		.output = { .max = 200000000 },
		.parents = { "syspll_divpmcck", "baudpll_divpmcck", },
		.parents_mux_table = { 5, 8, },
		.parents_count = 2,
		.parents_chg_id = INT_MIN,
	},
	{
		.name  = "flex4_gclk",
		.id = 42,
		.output = { .max = 200000000 },
		.parents = { "syspll_divpmcck", "baudpll_divpmcck", },
		.parents_mux_table = { 5, 8, },
		.parents_count = 2,
		.parents_chg_id = INT_MIN,
	},
	{
		.name  = "flex5_gclk",
		.id = 43,
		.output = { .max = 200000000 },
		.parents = { "syspll_divpmcck", "baudpll_divpmcck", },
		.parents_mux_table = { 5, 8, },
		.parents_count = 2,
		.parents_chg_id = INT_MIN,
	},
	{
		.name  = "flex6_gclk",
		.id = 44,
		.output = { .max = 200000000 },
		.parents = { "syspll_divpmcck", "baudpll_divpmcck", },
		.parents_mux_table = { 5, 8, },
		.parents_count = 2,
		.parents_chg_id = INT_MIN,
	},
	{
		.name  = "flex7_gclk",
		.id = 45,
		.output = { .max = 200000000 },
		.parents = { "syspll_divpmcck", "baudpll_divpmcck", },
		.parents_mux_table = { 5, 8, },
		.parents_count = 2,
		.parents_chg_id = INT_MIN,
	},
	{
		.name  = "flex8_gclk",
		.id = 46,
		.output = { .max = 200000000 },
		.parents = { "syspll_divpmcck", "baudpll_divpmcck", },
		.parents_mux_table = { 5, 8, },
		.parents_count = 2,
		.parents_chg_id = INT_MIN,
	},
	{
		.name  = "flex9_gclk",
		.id = 47,
		.output = { .max = 200000000 },
		.parents = { "syspll_divpmcck", "baudpll_divpmcck", },
		.parents_mux_table = { 5, 8, },
		.parents_count = 2,
		.parents_chg_id = INT_MIN,
	},
	{
		.name  = "flex10_gclk",
		.id = 48,
		.output = { .max = 200000000 },
		.parents = { "syspll_divpmcck", "baudpll_divpmcck", },
		.parents_mux_table = { 5, 8, },
		.parents_count = 2,
		.parents_chg_id = INT_MIN,
	},
	{
		.name  = "flex11_gclk",
		.id = 49,
		.output = { .max = 200000000 },
		.parents = { "syspll_divpmcck", "baudpll_divpmcck", },
		.parents_mux_table = { 5, 8, },
		.parents_count = 2,
		.parents_chg_id = INT_MIN,
	},
	{
		.name  = "gmac0_gclk",
		.id = 51,
		.output = { .max = 125000000 },
		.parents = { "ethpll_divpmcck", },
		.parents_mux_table = { 10, },
		.parents_count = 1,
		.parents_chg_id = 3,
	},
	{
		.name  = "gmac1_gclk",
		.id = 52,
		.output = { .max = 50000000  },
		.parents = { "ethpll_divpmcck", },
		.parents_mux_table = { 10, },
		.parents_count = 1,
		.parents_chg_id = INT_MIN,
	},
	{
		.name  = "gmac0_tsu_gclk",
		.id = 53,
		.output = { .max = 300000000 },
		.parents = { "audiopll_divck", "ethpll_divpmcck", },
		.parents_mux_table = { 9, 10, },
		.parents_count = 2,
		.parents_chg_id = INT_MIN,
	},
	{
		.name  = "gmac1_tsu_gclk",
		.id = 54,
		.output = { .max = 300000000 },
		.parents = { "audiopll_divck", "ethpll_divpmcck", },
		.parents_mux_table = { 9, 10, },
		.parents_count = 2,
		.parents_chg_id = INT_MIN,
	},
	{
		.name  = "i2smcc0_gclk",
		.id = 57,
		.output = { .max = 100000000 },
		.parents = { "syspll_divpmcck", "audiopll_divck", },
		.parents_mux_table = { 5, 9, },
		.parents_count = 2,
		.parents_chg_id = INT_MIN,
	},
	{
		.name  = "i2smcc1_gclk",
		.id = 58,
		.output = { .max = 100000000 },
		.parents = { "syspll_divpmcck", "audiopll_divck", },
		.parents_mux_table = { 5, 9, },
		.parents_count = 2,
		.parents_chg_id = INT_MIN,
	},
	{
		.name  = "mcan0_gclk",
		.id = 61,
		.output = { .max = 200000000 },
		.parents = { "syspll_divpmcck", "baudpll_divpmcck", },
		.parents_mux_table = { 5, 8, },
		.parents_count = 2,
		.parents_chg_id = INT_MIN,
	},
	{
		.name  = "mcan1_gclk",
		.id = 62,
		.output = { .max = 200000000 },
		.parents = { "syspll_divpmcck", "baudpll_divpmcck", },
		.parents_mux_table = { 5, 8, },
		.parents_count = 2,
		.parents_chg_id = INT_MIN,
	},
	{
		.name  = "mcan2_gclk",
		.id = 63,
		.output = { .max = 200000000 },
		.parents = { "syspll_divpmcck", "baudpll_divpmcck", },
		.parents_mux_table = { 5, 8, },
		.parents_count = 2,
		.parents_chg_id = INT_MIN,
	},
	{
		.name  = "mcan3_gclk",
		.id = 64,
		.output = { .max = 200000000 },
		.parents = { "syspll_divpmcck", "baudpll_divpmcck", },
		.parents_mux_table = { 5, 8, },
		.parents_count = 2,
		.parents_chg_id = INT_MIN,
	},
	{
		.name  = "mcan4_gclk",
		.id = 65,
		.output = { .max = 200000000 },
		.parents = { "syspll_divpmcck", "baudpll_divpmcck", },
		.parents_mux_table = { 5, 8, },
		.parents_count = 2,
		.parents_chg_id = INT_MIN,
	},
	{
		.name  = "mcan5_gclk",
		.id = 66,
		.output = { .max = 200000000 },
		.parents = { "syspll_divpmcck", "baudpll_divpmcck", },
		.parents_mux_table = { 5, 8, },
		.parents_count = 2,
		.parents_chg_id = INT_MIN,
	},
	{
		.name  = "pdmc0_gclk",
		.id = 68,
		.output = { .max = 50000000  },
		.parents = { "syspll_divpmcck", "audiopll_divck", },
		.parents_mux_table = { 5, 9, },
		.parents_count = 2,
		.parents_chg_id = INT_MIN,
	},
	{
		.name  = "pdmc1_gclk",
		.id = 69,
		.output = { .max = 50000000, },
		.parents = { "syspll_divpmcck", "audiopll_divck", },
		.parents_mux_table = { 5, 9, },
		.parents_count = 2,
		.parents_chg_id = INT_MIN,
	},
	{
		.name  = "pit64b0_gclk",
		.id = 70,
		.output = { .max = 200000000 },
		.parents = { "syspll_divpmcck", "imgpll_divpmcck",
			     "baudpll_divpmcck", "audiopll_divck",
			     "ethpll_divpmcck", },
		.parents_mux_table = { 5, 7, 8, 9, 10, },
		.parents_count = 5,
		.parents_chg_id = INT_MIN,
	},
	{
		.name  = "pit64b1_gclk",
		.id = 71,
		.output = { .max = 200000000 },
		.parents = { "syspll_divpmcck", "imgpll_divpmcck",
			     "baudpll_divpmcck", "audiopll_divck",
			     "ethpll_divpmcck", },
		.parents_mux_table = { 5, 7, 8, 9, 10, },
		.parents_count = 5,
		.parents_chg_id = INT_MIN,
	},
	{
		.name  = "pit64b2_gclk",
		.id = 72,
		.output = { .max = 200000000 },
		.parents = { "syspll_divpmcck", "imgpll_divpmcck",
			     "baudpll_divpmcck", "audiopll_divck",
			     "ethpll_divpmcck", },
		.parents_mux_table = { 5, 7, 8, 9, 10, },
		.parents_count = 5,
		.parents_chg_id = INT_MIN,
	},
	{
		.name  = "pit64b3_gclk",
		.id = 73,
		.output = { .max = 200000000 },
		.parents = { "syspll_divpmcck", "imgpll_divpmcck",
			     "baudpll_divpmcck", "audiopll_divck",
			     "ethpll_divpmcck", },
		.parents_mux_table = { 5, 7, 8, 9, 10, },
		.parents_count = 5,
		.parents_chg_id = INT_MIN,
	},
	{
		.name  = "pit64b4_gclk",
		.id = 74,
		.output = { .max = 200000000 },
		.parents = { "syspll_divpmcck", "imgpll_divpmcck",
			     "baudpll_divpmcck", "audiopll_divck",
			     "ethpll_divpmcck", },
		.parents_mux_table = { 5, 7, 8, 9, 10, },
		.parents_count = 5,
		.parents_chg_id = INT_MIN,
	},
	{
		.name  = "pit64b5_gclk",
		.id = 75,
		.output = { .max = 200000000 },
		.parents = { "syspll_divpmcck", "imgpll_divpmcck",
			     "baudpll_divpmcck", "audiopll_divck",
			     "ethpll_divpmcck", },
		.parents_mux_table = { 5, 7, 8, 9, 10, },
		.parents_count = 5,
		.parents_chg_id = INT_MIN,
	},
	{
		.name  = "qspi0_gclk",
		.id = 78,
		.output = { .max = 200000000 },
		.parents = { "syspll_divpmcck", "baudpll_divpmcck", },
		.parents_mux_table = { 5, 8, },
		.parents_count = 2,
		.parents_chg_id = INT_MIN,
	},
	{
		.name  = "qspi1_gclk",
		.id = 79,
		.output = { .max = 200000000 },
		.parents = { "syspll_divpmcck", "baudpll_divpmcck", },
		.parents_mux_table = { 5, 8, },
		.parents_count = 2,
		.parents_chg_id = INT_MIN,
	},
	{
		.name  = "sdmmc0_gclk",
		.id = 80,
		.output = { .max = 208000000 },
		.parents = { "syspll_divpmcck", "baudpll_divpmcck", },
		.parents_mux_table = { 5, 8, },
		.parents_count = 2,
		.parents_chg_id = 4,
	},
	{
		.name  = "sdmmc1_gclk",
		.id = 81,
		.output = { .max = 208000000 },
		.parents = { "syspll_divpmcck", "baudpll_divpmcck", },
		.parents_mux_table = { 5, 8, },
		.parents_count = 2,
		.parents_chg_id = 4,
	},
	{
		.name  = "sdmmc2_gclk",
		.id = 82,
		.output = { .max = 208000000 },
		.parents = { "syspll_divpmcck", "baudpll_divpmcck", },
		.parents_mux_table = { 5, 8, },
		.parents_count = 2,
		.parents_chg_id = 4,
	},
	{
		.name  = "spdifrx_gclk",
		.id = 84,
		.output = { .max = 150000000 },
		.parents = { "syspll_divpmcck", "audiopll_divck", },
		.parents_mux_table = { 5, 9, },
		.parents_count = 2,
		.parents_chg_id = INT_MIN,
	},
	{
		.name = "spdiftx_gclk",
		.id = 85,
		.output = { .max = 25000000  },
		.parents = { "syspll_divpmcck", "audiopll_divck", },
		.parents_mux_table = { 5, 9, },
		.parents_count = 2,
		.parents_chg_id = INT_MIN,
	},
	{
		.name  = "tcb0_ch0_gclk",
		.id = 88,
		.output = { .max = 200000000 },
		.parents = { "syspll_divpmcck", "imgpll_divpmcck",
			     "baudpll_divpmcck", "audiopll_divck",
			     "ethpll_divpmcck", },
		.parents_mux_table = { 5, 7, 8, 9, 10, },
		.parents_count = 5,
		.parents_chg_id = INT_MIN,
	},
	{
		.name  = "tcb1_ch0_gclk",
		.id = 91,
		.output = { .max = 200000000 },
		.parents = { "syspll_divpmcck", "imgpll_divpmcck",
			     "baudpll_divpmcck", "audiopll_divck",
			     "ethpll_divpmcck", },
		.parents_mux_table = { 5, 7, 8, 9, 10, },
		.parents_count = 5,
		.parents_chg_id = INT_MIN,
	},
	{
		.name  = "tcpca_gclk",
		.id = 94,
		.output = { .max = 32768, },
		.parents_chg_id = INT_MIN,
	},
	{
		.name  = "tcpcb_gclk",
		.id = 95,
		.output = { .max = 32768, },
		.parents_chg_id = INT_MIN,
	},
};

/* MCK0 characteristics */
static const struct clk_master_charac mck0_characteristics = {
	.output = { .min = 32768, .max = 200000000 },
	.divisors = { 1, 2, 4, 3, 5 },
	.have_div3_pres = 1,
};

/* MCK0 layout */
static const struct clk_master_layout mck0_layout = {
	.mask = 0x773,
	.pres_shift = 4,
	.offset = 0x28,
};

/* Peripheral clock layout */
static const struct clk_pcr_layout sama7g5_pcr_layout = {
	.offset = 0x88,
	.cmd = BIT(31),
	.div_mask = GENMASK_32(27, 20),
	.gckcss_mask = GENMASK_32(12, 8),
	.pid_mask = GENMASK_32(6, 0),
};

static const struct clk_programmable_layout sama7g5_prog_layout = {
	.pres_mask = 0xff,
	.pres_shift = 8,
	.css_mask = GENMASK_32(4, 0),
	.have_slck_mck = 0,
	.is_pres_direct = 1,
};

static const struct {
	const char *name;
	uint8_t id;
} sama7g5_progck[] = {
	{ .name = "prog0", .id = 0 },
	{ .name = "prog1", .id = 1 },
	{ .name = "prog2", .id = 2 },
	{ .name = "prog3", .id = 3 },
	{ .name = "prog4", .id = 4 },
	{ .name = "prog5", .id = 5 },
	{ .name = "prog6", .id = 6 },
	{ .name = "prog7", .id = 7 },
};

static struct pmc_data *sama7g5_pmc;

vaddr_t at91_pmc_get_base(void)
{
	assert(sama7g5_pmc);

	return sama7g5_pmc->base;
}

TEE_Result at91_pmc_clk_get(unsigned int type, unsigned int idx,
			    struct clk **clk)
{
	return pmc_clk_get(sama7g5_pmc, type, idx, clk);
}

static TEE_Result pmc_setup_sama7g5(const void *fdt, int nodeoffset,
				    const void *data __unused)
{
	struct clk *pll_frac_clk[PLL_ID_MAX] = { };
	struct clk *pll_div_clk[PLL_ID_MAX] = { };
	TEE_Result res = TEE_ERROR_GENERIC;
	const uint32_t *fdt_prop = NULL;
	struct pmc_clk *pmc_clk = NULL;
	struct clk *parents[11] = { };
	struct clk *main_xtal_clk = NULL;
	struct clk *main_rc_osc = NULL;
	struct clk *main_osc = NULL;
	struct clk *mck0_clk = NULL;
	struct clk *main_clk = NULL;
	struct clk *md_slck = NULL;
	struct clk *td_slck = NULL;
	struct clk *parent = NULL;
	struct clk *clk = NULL;
	unsigned int i = 0;
	unsigned int j = 0;
	vaddr_t base = 0;
	size_t size = 0;
	int bypass = 0;

	if (dt_map_dev(fdt, nodeoffset, &base, &size, DT_MAP_AUTO) < 0)
		panic();

	if (fdt_get_status(fdt, nodeoffset) == DT_STATUS_OK_SEC)
		matrix_configure_periph_secure(ID_PMC);

	res = clk_dt_get_by_name(fdt, nodeoffset, "md_slck", &md_slck);
	if (res)
		return res;

	res = clk_dt_get_by_name(fdt, nodeoffset, "td_slck", &td_slck);
	if (res)
		return res;

	res = clk_dt_get_by_name(fdt, nodeoffset, "main_xtal", &main_xtal_clk);
	if (res)
		return res;

	sama7g5_pmc = pmc_data_allocate(PMC_SAMA7G5_CORE_CLK_COUNT,
					ARRAY_SIZE(sama7g5_systemck),
					ARRAY_SIZE(peri_clks),
					ARRAY_SIZE(sama7g5_gcks), 8);
	if (!sama7g5_pmc)
		panic();

	sama7g5_pmc->base = base;

	main_rc_osc = pmc_register_main_rc_osc(sama7g5_pmc, "main_rc_osc",
					       12000000);
	if (!main_rc_osc)
		panic();

	fdt_prop = fdt_getprop(fdt, nodeoffset, "atmel,osc-bypass", NULL);
	if (fdt_prop)
		bypass = fdt32_to_cpu(*fdt_prop);

	main_osc = pmc_register_main_osc(sama7g5_pmc, "main_osc",
					 main_xtal_clk, bypass);
	if (!main_osc)
		panic();

	parents[0] = main_rc_osc;
	parents[1] = main_osc;
	main_clk = at91_clk_register_sam9x5_main(sama7g5_pmc, "mainck",
						 parents, 2);
	if (!main_clk)
		panic();
	pmc_clk = &sama7g5_pmc->chws[PMC_MAIN];
	pmc_clk->clk = main_clk;
	pmc_clk->id = PMC_MAIN;

	for (i = 0; i < PLL_ID_MAX; i++) {
		struct pmc_data *pmc = sama7g5_pmc;
		const struct sama7g5_pll *p = NULL;

		for (j = 0; j < 3; j++) {
			p = &sama7g5_plls[i][j];
			if (!p->name)
				continue;

			switch (p->type) {
			case PLL_TYPE_FRAC:
				if (!strcmp(p->parent, "mainck"))
					parent = main_clk;
				else if (!strcmp(p->parent, "main_xtal"))
					parent = main_xtal_clk;
				else
					parent = pmc_clk_get_by_name(pmc->chws,
								     pmc->ncore,
								     p->parent);
				assert(parent);

				clk = sam9x60_clk_register_frac_pll(sama7g5_pmc,
								    p->name,
								    parent, i,
								    p->charac,
								    p->layout,
								    p->flags);
				pll_frac_clk[i] = clk;
				break;

			case PLL_TYPE_DIV:
				parent = clk;
				clk = sam9x60_clk_register_div_pll(sama7g5_pmc,
								   p->name,
								   parent, i,
								   p->charac,
								   p->layout,
								   p->flags,
								   p->safe_div);
				break;

			default:
				continue;
			}
			if (!clk)
				panic();

			if (p->eid) {
				sama7g5_pmc->chws[p->eid].clk = clk;
				sama7g5_pmc->chws[p->eid].id = p->eid;
			}
		}
		p = &sama7g5_plls[i][PLL_TYPE_DIV];
		pll_div_clk[i] = sama7g5_pmc->chws[p->eid].clk;
	}

	parents[0] = md_slck;
	parents[1] = main_clk;
	parents[2] = pll_div_clk[PLL_ID_CPU];
	parents[3] = pll_div_clk[PLL_ID_SYS];
	clk = at91_clk_register_master_pres(sama7g5_pmc, "fclk", 4,
					    parents,
					    &mck0_layout,
					    &mck0_characteristics, INT_MIN);
	if (!clk)
		panic();
	pmc_clk = &sama7g5_pmc->chws[PMC_MCK_PRES];
	pmc_clk->clk = clk;
	pmc_clk->id = PMC_MCK_PRES;

	mck0_clk = at91_clk_register_master_div(sama7g5_pmc, "mck0",
						clk,
						&mck0_layout,
						&mck0_characteristics);
	if (!mck0_clk)
		panic();
	pmc_clk = &sama7g5_pmc->chws[PMC_MCK];
	pmc_clk->clk = mck0_clk;
	pmc_clk->id = PMC_MCK;

	parents[0] = md_slck;
	parents[1] = td_slck;
	parents[2] = main_clk;
	parents[3] = mck0_clk;
	for (i = 0; i < ARRAY_SIZE(sama7g5_mckx); i++) {
		const struct sama7g5_mck *mck = &sama7g5_mckx[i];
		uint8_t num_parents = 4 + mck->eparents_count;
		uint32_t *mux_table = calloc(num_parents, sizeof(*mux_table));

		if (!mux_table)
			panic();

		mux_table[0] = 0;
		mux_table[1] = 1;
		mux_table[2] = 2;
		mux_table[3] = 3;
		for (j = 0; j < mck->eparents_count; j++) {
			parents[4 + j] = pmc_clk_get_by_name(sama7g5_pmc->chws,
							     sama7g5_pmc->ncore,
							     mck->eparents[j]);
			assert(parents[4 + j]);
			mux_table[4 + j] = mck->eparents_mux_table[j];
		}

		clk = at91_clk_sama7g5_register_master(sama7g5_pmc,
						       mck->name,
						       num_parents, parents,
						       mux_table,
						       mck->id,
						       mck->eparents_chg_id);
		if (!clk)
			panic();

		sama7g5_pmc->chws[PMC_MCK1 + i].clk = clk;
	}

	clk = at91_clk_sama7g5_register_utmi(sama7g5_pmc, "utmick", main_clk);
	if (!clk)
		panic();
	sama7g5_pmc->chws[PMC_UTMI].clk = clk;
	sama7g5_pmc->chws[PMC_UTMI].id = PMC_UTMI;

	for (i = 0; i < ARRAY_SIZE(sama7_utmick); i++) {
		if (strcmp("utmick", sama7_utmick[i].parent) == 0)
			parent = clk;
		else if (strcmp("utmi1", sama7_utmick[i].parent) == 0)
			parent = sama7g5_pmc->chws[PMC_UTMI1].clk;
		else
			panic();
		clk = sama7_utmi_clk_register(sama7_utmick[i].name, parent,
					      sama7_utmick[i].id);
		if (!clk)
			panic();

		pmc_clk = &sama7g5_pmc->chws[PMC_UTMI1 + i];
		pmc_clk->clk = clk;
		pmc_clk->id = PMC_UTMI1 + i;
	}

	parents[0] = md_slck;
	parents[1] = td_slck;
	parents[2] = main_clk;
	parents[3] = pll_div_clk[PLL_ID_SYS];
	parents[4] = pll_div_clk[PLL_ID_DDR];
	parents[5] = pll_div_clk[PLL_ID_IMG];
	parents[6] = pll_div_clk[PLL_ID_BAUD];
	parents[7] = pll_div_clk[PLL_ID_AUDIO];
	parents[8] = pll_div_clk[PLL_ID_ETH];
	for (i = 0; i < ARRAY_SIZE(sama7g5_progck); i++) {
		clk = at91_clk_register_programmable(sama7g5_pmc,
						     sama7g5_progck[i].name,
						     parents, 9, i,
						     &sama7g5_prog_layout);
		if (!clk)
			panic();

		pmc_clk = &sama7g5_pmc->pchws[i];
		pmc_clk->clk = clk;
		pmc_clk->id = sama7g5_progck[i].id;
	}

	for (i = 0; i < ARRAY_SIZE(sama7g5_systemck); i++) {
		clk = at91_clk_register_system(sama7g5_pmc,
					       sama7g5_systemck[i].name,
					       sama7g5_pmc->pchws[i].clk,
					       sama7g5_systemck[i].id);
		if (!clk)
			panic();

		pmc_clk = &sama7g5_pmc->shws[i];
		pmc_clk->clk = clk;
		pmc_clk->id = sama7g5_systemck[i].id;
	}

	for (i = 0; i < ARRAY_SIZE(peri_clks); i++) {
		parent = pmc_clk_get_by_name(sama7g5_pmc->chws,
					     sama7g5_pmc->ncore,
					     peri_clks[i].parent);
		clk = at91_clk_register_sam9x5_periph(sama7g5_pmc,
						      &sama7g5_pcr_layout,
						      peri_clks[i].name,
						      parent,
						      peri_clks[i].id,
						      &peri_clks[i].output);
		if (!clk)
			panic();

		pmc_clk = &sama7g5_pmc->phws[i];
		pmc_clk->clk = clk;
		pmc_clk->id = peri_clks[i].id;
	}

	parents[0] = md_slck;
	parents[1] = td_slck;
	parents[2] = main_clk;
	for (i = 0; i < ARRAY_SIZE(sama7g5_gcks); i++) {
		const struct sama7g5_gck *gck = sama7g5_gcks + i;
		uint8_t num_parents = 3 + gck->parents_count;
		uint32_t *mux_table = calloc(num_parents, sizeof(*mux_table));

		if (!mux_table)
			panic();

		mux_table[0] = 0;
		mux_table[1] = 1;
		mux_table[2] = 2;
		for (j = 0; j < gck->parents_count; j++) {
			parents[3 + j] = pmc_clk_get_by_name(sama7g5_pmc->chws,
							     sama7g5_pmc->ncore,
							     gck->parents[j]);
			assert(parents[3 + j]);
			mux_table[3 + j] = gck->parents_mux_table[j];
		}

		clk = at91_clk_register_generated(sama7g5_pmc,
						  &sama7g5_pcr_layout,
						  gck->name, parents,
						  mux_table,
						  num_parents, gck->id,
						  &gck->output,
						  gck->parents_chg_id);
		if (!clk)
			panic();

		pmc_clk = &sama7g5_pmc->ghws[i];
		pmc_clk->clk = clk;
		pmc_clk->id = gck->id;
	}

	res = clk_set_rate(pll_frac_clk[PLL_ID_ETH], 625000000);
	if (res)
		panic();

	res = clk_set_rate(pll_div_clk[PLL_ID_ETH], 625000000);
	if (res)
		panic();

	res = clk_dt_register_clk_provider(fdt, nodeoffset, clk_dt_pmc_get,
					   sama7g5_pmc);
	if (res)
		panic();

	pmc_register_pm();

	return TEE_SUCCESS;
}

CLK_DT_DECLARE(sama7g5_clk, "microchip,sama7g5-pmc", pmc_setup_sama7g5);
