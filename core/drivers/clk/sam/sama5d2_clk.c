// SPDX-License-Identifier: GPL-2.0+ or BSD-3-Clause
/*
 * Copyright (c) 2021, Microchip
 */
#include <assert.h>
#include <kernel/boot.h>
#include <libfdt.h>
#include <kernel/dt.h>
#include <kernel/panic.h>
#include <matrix.h>
#include <sama5d2.h>
#include <stdint.h>
#include <util.h>

#include "at91_clk.h"

#include <dt-bindings/clock/at91.h>

#define PROGCK_PARENT_COUNT	6
#define PARENT_SIZE		ARRAY_SIZE(sama5d2_systemck)

struct sam_clk {
	const char *n;
	uint8_t id;
};

static const struct clk_master_charac mck_charac = {
	.output = { .min = 124000000, .max = 166000000 },
	.divisors = { 1, 2, 4, 3 },
};

static uint8_t plla_out[1];

static uint16_t plla_icpll[1];

static const struct clk_range plla_outputs[] = {
	{ .min = 600000000, .max = 1200000000 },
};

static const struct clk_pll_charac plla_charac = {
	.input = { .min = 12000000, .max = 24000000 },
	.num_output = ARRAY_SIZE(plla_outputs),
	.output = plla_outputs,
	.icpll = plla_icpll,
	.out = plla_out,
};

static const struct clk_pcr_layout sama5d2_pcr_layout = {
	.offset = 0x10c,
	.cmd = BIT(12),
	.gckcss_mask = GENMASK_32(10, 8),
	.pid_mask = GENMASK_32(6, 0),
};

static const struct clk_programmable_layout sama5d2_prog_layout = {
	.pres_mask = 0xff,
	.pres_shift = 4,
	.css_mask = 0x7,
	.have_slck_mck = 0,
	.is_pres_direct = 1,
};

static const struct sam_clk sama5d2_systemck[] = {
	{ .n = "ddrck", .id = 2 },
	{ .n = "lcdck", .id = 3 },
	{ .n = "uhpck", .id = 6 },
	{ .n = "udpck", .id = 7 },
	{ .n = "pck0",  .id = 8 },
	{ .n = "pck1",  .id = 9 },
	{ .n = "pck2",  .id = 10 },
	{ .n = "iscck", .id = 18 },
};

static const struct {
	struct sam_clk clk;
	struct clk_range r;
} sama5d2_peri32ck[] = {
	{
		.clk = { .n = "macb0_clk", .id = 5 },
		.r = { .min = 0, .max = 83000000 },
	},
	{
		.clk = { .n = "tdes_clk", .id = 11 },
		.r = { .min = 0, .max = 83000000 },
	},
	{
		.clk = { .n = "matrix1_clk", .id = 14 },
	},
	{
		.clk = { .n = "hsmc_clk", .id = 17 },
	},
	{
		.clk = { .n = "pioA_clk", .id = 18 },
		.r = { .min = 0, .max = 83000000 },
	},
	{
		.clk = { .n = "flx0_clk", .id = 19 },
		.r = { .min = 0, .max = 83000000 },
	},
	{
		.clk = { .n = "flx1_clk", .id = 20 },
		.r = { .min = 0, .max = 83000000 },
	},
	{
		.clk = { .n = "flx2_clk", .id = 21 },
		.r = { .min = 0, .max = 83000000 },
	},
	{
		.clk = { .n = "flx3_clk", .id = 22 },
		.r = { .min = 0, .max = 83000000 },
	},
	{
		.clk = { .n = "flx4_clk", .id = 23 },
		.r = { .min = 0, .max = 83000000 },
	},
	{
		.clk = { .n = "uart0_clk", .id = 24 },
		.r = { .min = 0, .max = 83000000 },
	},
	{
		.clk = { .n = "uart1_clk", .id = 25 },
		.r = { .min = 0, .max = 83000000 },
	},
	{
		.clk = { .n = "uart2_clk", .id = 26 },
		.r = { .min = 0, .max = 83000000 },
	},
	{
		.clk = { .n = "uart3_clk", .id = 27 },
		.r = { .min = 0, .max = 83000000 },
	},
	{
		.clk = { .n = "uart4_clk", .id = 28 },
		.r = { .min = 0, .max = 83000000 },
	},
	{
		.clk = { .n = "twi0_clk", .id = 29 },
		.r = { .min = 0, .max = 83000000 },
	},
	{
		.clk = { .n = "twi1_clk", .id = 30 },
		.r = { .min = 0, .max = 83000000 },
	},
	{
		.clk = { .n = "spi0_clk", .id = 33 },
		.r = { .min = 0, .max = 83000000 },
	},
	{
		.clk = { .n = "spi1_clk", .id = 34 },
		.r = { .min = 0, .max = 83000000 },
	},
	{
		.clk = { .n = "tcb0_clk", .id = 35 },
		.r = { .min = 0, .max = 83000000 },
	},
	{
		.clk = { .n = "tcb1_clk", .id = 36 },
		.r = { .min = 0, .max = 83000000 },
	},
	{
		.clk = { .n = "pwm_clk", .id = 38 },
		.r = { .min = 0, .max = 83000000 },
	},
	{
		.clk = { .n = "adc_clk", .id = 40 },
		.r = { .min = 0, .max = 83000000 },
	},
	{
		.clk = { .n = "uhphs_clk", .id = 41 },
		.r = { .min = 0, .max = 83000000 },
	},
	{
		.clk = { .n = "udphs_clk", .id = 42 },
		.r = { .min = 0, .max = 83000000 },
	},
	{
		.clk = { .n = "ssc0_clk", .id = 43 },
		.r = { .min = 0, .max = 83000000 },
	},
	{
		.clk = { .n = "ssc1_clk", .id = 44 },
		.r = { .min = 0, .max = 83000000 },
	},
	{
		.clk = { .n = "trng_clk", .id = 47 },
		.r = { .min = 0, .max = 83000000 },
	},
	{
		.clk = { .n = "pdmic_clk", .id = 48 },
		.r = { .min = 0, .max = 83000000 },
	},
	{
		.clk = { .n = "securam_clk", .id = 51 }, },
	{
		.clk = { .n = "i2s0_clk", .id = 54 },
		.r = { .min = 0, .max = 83000000 },
	},
	{
		.clk = { .n = "i2s1_clk", .id = 55 },
		.r = { .min = 0, .max = 83000000 },
	},
	{
		.clk = { .n = "can0_clk", .id = 56 },
		.r = { .min = 0, .max = 83000000 },
	},
	{
		.clk = { .n = "can1_clk", .id = 57 },
		.r = { .min = 0, .max = 83000000 },
	},
	{
		.clk = { .n = "ptc_clk", .id = 58 },
		.r = { .min = 0, .max = 83000000 },
	},
	{
		.clk = { .n = "classd_clk", .id = 59 },
		.r = { .min = 0, .max = 83000000 },
	},
};

static const struct sam_clk sama5d2_perick[] = {
	{ .n = "dma0_clk",    .id = 6 },
	{ .n = "dma1_clk",    .id = 7 },
	{ .n = "aes_clk",     .id = 9 },
	{ .n = "aesb_clk",    .id = 10 },
	{ .n = "sha_clk",     .id = 12 },
	{ .n = "mpddr_clk",   .id = 13 },
	{ .n = "matrix0_clk", .id = 15 },
	{ .n = "sdmmc0_hclk", .id = 31 },
	{ .n = "sdmmc1_hclk", .id = 32 },
	{ .n = "lcdc_clk",    .id = 45 },
	{ .n = "isc_clk",     .id = 46 },
	{ .n = "qspi0_clk",   .id = 52 },
	{ .n = "qspi1_clk",   .id = 53 },
};

static const struct {
	struct sam_clk clk;
	struct clk_range r;
	int chg_pid;
} sama5d2_gck[] = {
	{
		.clk = { .n = "sdmmc0_gclk", .id = 31 },
		.chg_pid = INT_MIN,
	},
	{
		.clk = { .n = "sdmmc1_gclk", .id = 32 },
		.chg_pid = INT_MIN,
	},
	{
		.clk = { .n = "tcb0_gclk", .id = 35 },
		.r = { .min = 0, .max = 83000000 },
		.chg_pid = INT_MIN,
	},
	{
		.clk = { .n = "tcb1_gclk", .id = 36 },
		.r = { .min = 0, .max = 83000000 },
		.chg_pid = INT_MIN,
	},
	{
		.clk = { .n = "pwm_gclk", .id = 38 },
		.r = { .min = 0, .max = 83000000 },
		.chg_pid = INT_MIN,
	},
	{
		.clk = { .n = "isc_gclk", .id = 46 },
		.chg_pid = INT_MIN,
	},
	{
		.clk = { .n = "pdmic_gclk", .id = 48 },
		.chg_pid = INT_MIN,
	},
	{
		.clk = { .n = "i2s0_gclk", .id = 54 },
		.chg_pid = 5,
	},
	{
		.clk = { .n = "i2s1_gclk", .id = 55 },
		.chg_pid = 5,
	},
	{
		.clk = { .n = "can0_gclk", .id = 56 },
		.r = { .min = 0, .max = 80000000 },
		.chg_pid = INT_MIN,
	},
	{
		.clk = { .n = "can1_gclk",   .id = 57 },
		.r = { .min = 0, .max = 80000000 },
		.chg_pid = INT_MIN,
	},
	{
		.clk = { .n = "classd_gclk", .id = 59 },
		.chg_pid = 5,
		.r = { .min = 0, .max = 100000000 },
	},
};

static const struct sam_clk sama5d2_progck[] = {
	{ .n = "prog0", .id = 0 },
	{ .n = "prog1", .id = 1 },
	{ .n = "prog2", .id = 2 },
};

static struct pmc_data *pmc;

vaddr_t at91_pmc_get_base(void)
{
	assert(pmc);

	return pmc->base;
}

static TEE_Result pmc_setup(const void *fdt, int nodeoffset,
			    const void *data __unused)
{
	size_t size = 0;
	vaddr_t base = 0;
	unsigned int i = 0;
	int bypass = 0;
	const uint32_t *fdt_prop = NULL;
	struct pmc_clk *pmc_clk = NULL;
	const struct sam_clk *sam_clk = NULL;
	struct clk_range range = CLK_RANGE(0, 0);
	struct clk *h32mxck = NULL;
	struct clk *mckdivck = NULL;
	struct clk *plladivck = NULL;
	struct clk *usbck = NULL;
	struct clk *audiopll_pmcck = NULL;
	struct clk *parents[PARENT_SIZE] = {NULL};
	struct clk *main_clk = NULL;
	struct clk *utmi_clk = NULL;
	struct clk *slow_clk = NULL;
	struct clk *clk = NULL;
	struct clk *main_rc_osc = NULL;
	struct clk *main_osc = NULL;
	struct clk *main_xtal_clk = NULL;
	struct clk *audiopll_fracck = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;

	/*
	 * We want PARENT_SIZE to be MAX(ARRAY_SIZE(sama5d2_systemck),6)
	 * but using this define won't allow static initialization of parents
	 * due to dynamic size.
	 */
	COMPILE_TIME_ASSERT(ARRAY_SIZE(sama5d2_systemck) == PARENT_SIZE);
	COMPILE_TIME_ASSERT(PARENT_SIZE >= 6);

	if (dt_map_dev(fdt, nodeoffset, &base, &size) < 0)
		panic();

	if (_fdt_get_status(fdt, nodeoffset) == DT_STATUS_OK_SEC)
		matrix_configure_periph_secure(AT91C_ID_PMC);

	res = clk_dt_get_by_name(fdt, nodeoffset, "slow_clk", &slow_clk);
	if (res)
		panic();

	res = clk_dt_get_by_name(fdt, nodeoffset, "main_xtal", &main_xtal_clk);
	if (res)
		panic();

	pmc = pmc_data_allocate(PMC_MCK_PRES + 1,
				ARRAY_SIZE(sama5d2_systemck),
				ARRAY_SIZE(sama5d2_perick) +
				ARRAY_SIZE(sama5d2_peri32ck),
				ARRAY_SIZE(sama5d2_gck),
				ARRAY_SIZE(sama5d2_progck));
	if (!pmc)
		panic();
	pmc->base = base;

	main_rc_osc = pmc_register_main_rc_osc(pmc, "main_rc_osc", 12000000);
	if (!main_rc_osc)
		panic();

	fdt_prop = fdt_getprop(fdt, nodeoffset, "atmel,osc-bypass", NULL);
	if (fdt_prop)
		bypass = fdt32_to_cpu(*fdt_prop);

	main_osc = pmc_register_main_osc(pmc, "main_osc", main_xtal_clk,
					 bypass);
	if (!main_osc)
		panic();

	parents[0] = main_rc_osc;
	parents[1] = main_osc;
	main_clk = at91_clk_register_sam9x5_main(pmc, "mainck", parents, 2);
	if (!main_clk)
		panic();

	pmc_clk = &pmc->chws[PMC_MAIN];
	pmc_clk->clk = main_clk;
	pmc_clk->id = PMC_MAIN;

	clk = at91_clk_register_pll(pmc, "pllack", main_clk, 0,
				    &sama5d3_pll_layout, &plla_charac);
	if (!clk)
		panic();

	plladivck = at91_clk_register_plldiv(pmc, "plladivck", clk);
	if (!plladivck)
		panic();

	pmc_clk = &pmc->chws[PMC_PLLACK];
	pmc_clk->clk = plladivck;
	pmc_clk->id = PMC_PLLACK;

	audiopll_fracck = at91_clk_register_audio_pll_frac(pmc,
							   "audiopll_fracck",
							   main_clk);
	if (!audiopll_fracck)
		panic();

	clk = at91_clk_register_audio_pll_pad(pmc, "audiopll_padck",
					      audiopll_fracck);
	if (!clk)
		panic();

	audiopll_pmcck = at91_clk_register_audio_pll_pmc(pmc, "audiopll_pmcck",
							 audiopll_fracck);
	if (!audiopll_pmcck)
		panic();

	pmc_clk = &pmc->chws[PMC_AUDIOPLLCK];
	pmc_clk->clk = audiopll_pmcck;
	pmc_clk->id = PMC_AUDIOPLLCK;

	utmi_clk = at91_clk_register_utmi(pmc, "utmick", main_clk);
	if (!utmi_clk)
		panic();

	pmc_clk = &pmc->chws[PMC_UTMI];
	pmc_clk->clk = utmi_clk;
	pmc_clk->id = PMC_UTMI;

	parents[0] = slow_clk;
	parents[1] = main_clk;
	parents[2] = plladivck;
	parents[3] = utmi_clk;

	clk = at91_clk_register_master_pres(pmc, "masterck_pres", 4,
					    parents,
					    &at91sam9x5_master_layout,
					    &mck_charac, INT_MIN);
	if (!clk)
		panic();

	pmc_clk = &pmc->chws[PMC_MCK_PRES];
	pmc_clk->clk = clk;
	pmc_clk->id = PMC_MCK_PRES;

	mckdivck = at91_clk_register_master_div(pmc, "masterck_div",
						clk,
						&at91sam9x5_master_layout,
						&mck_charac);
	if (!mckdivck)
		panic();

	pmc_clk = &pmc->chws[PMC_MCK];
	pmc_clk->clk = mckdivck;
	pmc_clk->id = PMC_MCK;

	h32mxck = at91_clk_register_h32mx(pmc, "h32mxck", mckdivck);
	if (!h32mxck)
		panic();

	pmc_clk = &pmc->chws[PMC_MCK2];
	pmc_clk->clk = h32mxck;
	pmc_clk->id = PMC_MCK2;

	parents[0] = plladivck;
	parents[1] = utmi_clk;
	usbck = at91sam9x5_clk_register_usb(pmc, "usbck", parents, 2);
	if (!usbck)
		panic();

	if (clk_set_parent(usbck, utmi_clk) != TEE_SUCCESS)
		panic();

	clk_set_rate(usbck, 48000000);

	parents[0] = slow_clk;
	parents[1] = main_clk;
	parents[2] = plladivck;
	parents[3] = utmi_clk;
	parents[4] = mckdivck;
	parents[5] = audiopll_pmcck;
	for (i = 0; i < ARRAY_SIZE(sama5d2_progck); i++) {
		sam_clk = &sama5d2_progck[i];
		clk = at91_clk_register_programmable(pmc, sam_clk->n,
						     parents,
						     PROGCK_PARENT_COUNT, i,
						     &sama5d2_prog_layout);
		if (!clk)
			panic();

		pmc_clk = &pmc->pchws[i];
		pmc_clk->clk = clk;
		pmc_clk->id = sam_clk->id;
	}

	/* This array order must match the one in sama5d2_systemck */
	parents[0] = mckdivck;
	parents[1] = mckdivck;
	parents[2] = usbck;
	parents[3] = usbck;
	parents[4] = pmc->pchws[0].clk;
	parents[5] = pmc->pchws[1].clk;
	parents[6] = pmc->pchws[2].clk;
	parents[7] = mckdivck;
	for (i = 0; i < ARRAY_SIZE(sama5d2_systemck); i++) {
		sam_clk = &sama5d2_systemck[i];
		clk = at91_clk_register_system(pmc, sam_clk->n,
					       parents[i],
					       sam_clk->id);
		if (!clk)
			panic();

		pmc_clk = &pmc->shws[i];
		pmc_clk->clk = clk;
		pmc_clk->id = sam_clk->id;
	}

	for (i = 0; i < ARRAY_SIZE(sama5d2_perick); i++) {
		sam_clk = &sama5d2_perick[i];
		clk = at91_clk_register_sam9x5_periph(pmc,
						      &sama5d2_pcr_layout,
						      sam_clk->n,
						      mckdivck,
						      sam_clk->id,
						      &range);
		if (!clk)
			panic();

		pmc_clk = &pmc->phws[i];
		pmc_clk->clk = clk;
		pmc_clk->id = sam_clk->id;
	}

	for (i = 0; i < ARRAY_SIZE(sama5d2_peri32ck); i++) {
		sam_clk = &sama5d2_peri32ck[i].clk;
		clk = at91_clk_register_sam9x5_periph(pmc,
						      &sama5d2_pcr_layout,
						      sam_clk->n,
						      h32mxck,
						      sam_clk->id,
						      &sama5d2_peri32ck[i].r);
		if (!clk)
			panic();

		pmc_clk = &pmc->phws[ARRAY_SIZE(sama5d2_perick) + i];
		pmc_clk->clk = clk;
		pmc_clk->id = sam_clk->id;
	}

	parents[0] = slow_clk;
	parents[1] = main_clk;
	parents[2] = plladivck;
	parents[3] = utmi_clk;
	parents[4] = mckdivck;
	parents[5] = audiopll_pmcck;
	for (i = 0; i < ARRAY_SIZE(sama5d2_gck); i++) {
		sam_clk = &sama5d2_gck[i].clk;
		clk = at91_clk_register_generated(pmc,
						  &sama5d2_pcr_layout,
						  sam_clk->n,
						  parents, 6,
						  sam_clk->id,
						  &sama5d2_gck[i].r,
						  sama5d2_gck[i].chg_pid);
		if (!clk)
			panic();

		pmc_clk = &pmc->ghws[i];
		pmc_clk->clk = clk;
		pmc_clk->id = sam_clk->id;
	}

	parents[0] = pmc_clk_get_by_name(pmc->phws, pmc->nperiph, "i2s0_clk");
	parents[1] = pmc_clk_get_by_name(pmc->ghws, pmc->ngck, "i2s0_gclk");
	clk = at91_clk_i2s_mux_register("i2s0_muxclk", parents, 2, 0);
	if (!clk)
		panic();

	pmc->chws[PMC_I2S0_MUX].clk = clk;
	pmc->chws[PMC_I2S0_MUX].id = PMC_I2S0_MUX;

	parents[0] = pmc_clk_get_by_name(pmc->phws, pmc->nperiph, "i2s1_clk");
	parents[1] = pmc_clk_get_by_name(pmc->ghws, pmc->ngck, "i2s1_gclk");
	clk = at91_clk_i2s_mux_register("i2s1_muxclk", parents, 2, 1);
	if (!clk)
		panic();

	pmc->chws[PMC_I2S1_MUX].clk = clk;
	pmc->chws[PMC_I2S1_MUX].id = PMC_I2S1_MUX;

	clk_dt_register_clk_provider(fdt, nodeoffset, clk_dt_pmc_get, pmc);

	pmc_register_pm();

	return TEE_SUCCESS;
}

CLK_DT_DECLARE(sama5d2_clk, "atmel,sama5d2-pmc", pmc_setup);
