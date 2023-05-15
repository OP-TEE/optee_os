/* SPDX-License-Identifier: GPL-2.0+ or BSD-3-Clause */
/*
 * include/linux/clk/at91_pmc.h
 *
 * Copyright (C) 2005 Ivan Kokshaysky
 * Copyright (C) SAN People
 * Copyright (C) 2021 Microchip
 *
 * Power Management Controller (PMC) - System peripherals registers.
 * Based on AT91RM9200 datasheet revision E.
 */

#ifndef AT91_CLK_H
#define AT91_CLK_H

#include <drivers/clk.h>
#include <drivers/clk_dt.h>

#include "at91_pmc.h"

#define ffs(x)	__builtin_ffs(x)

#define field_get(_mask, _reg) \
	({ \
		typeof(_mask) __mask = _mask; \
		\
		(((_reg) & (__mask)) >> (ffs(__mask) - 1)); \
	})
#define field_prep(_mask, _val)  \
	({ \
		typeof(_mask) __mask = _mask; \
		\
		(((_val) << (ffs(__mask) - 1)) & (__mask)); \
	})

struct clk_range {
	unsigned long min;
	unsigned long max;
};

#define CLK_RANGE(MIN, MAX) {.min = MIN, .max = MAX,}

struct pmc_clk {
	struct clk *clk;
	uint8_t id;
};

struct pmc_data {
	vaddr_t base;
	unsigned int ncore;
	struct pmc_clk *chws;
	unsigned int nsystem;
	struct pmc_clk *shws;
	unsigned int nperiph;
	struct pmc_clk *phws;
	unsigned int ngck;
	struct pmc_clk *ghws;
	unsigned int npck;
	struct pmc_clk *pchws;

	struct pmc_clk hwtable[];
};

/* PLL */
struct clk_pll_layout {
	uint32_t pllr_mask;
	uint32_t mul_mask;
	uint32_t frac_mask;
	uint32_t div_mask;
	uint32_t endiv_mask;
	uint8_t mul_shift;
	uint8_t frac_shift;
	uint8_t div_shift;
	uint8_t endiv_shift;
};

struct clk_pcr_layout {
	uint32_t offset;
	uint32_t cmd;
	uint32_t div_mask;
	uint32_t gckcss_mask;
	uint32_t pid_mask;
};

struct clk_pll_charac {
	struct clk_range input;
	int num_output;
	const struct clk_range *output;
	uint16_t *icpll;
	uint8_t *out;
	uint8_t upll : 1;
};

extern const struct clk_pll_layout sama5d3_pll_layout;

/* Master */
struct clk_master_charac {
	struct clk_range output;
	uint32_t divisors[5];
	uint8_t have_div3_pres;
};

struct clk_master_layout {
	uint32_t offset;
	uint32_t mask;
	uint8_t pres_shift;
};

struct clk_programmable_layout {
	uint8_t pres_mask;
	uint8_t pres_shift;
	uint8_t css_mask;
	uint8_t have_slck_mck;
	uint8_t is_pres_direct;
};

extern const struct clk_master_layout at91sam9x5_master_layout;

vaddr_t at91_pmc_get_base(void);

struct pmc_data *pmc_data_allocate(unsigned int ncore, unsigned int nsystem,
				   unsigned int nperiph, unsigned int ngck,
				   unsigned int npck);

struct clk *clk_dt_pmc_get(struct dt_driver_phandle_args *args, void *data,
			   TEE_Result *res);

struct clk *pmc_clk_get_by_name(struct pmc_clk *clks, unsigned int nclk,
				const char *name);

/* Main clock */
struct clk *pmc_register_main_rc_osc(struct pmc_data *pmc, const char *name,
				     unsigned long freq);

struct clk *pmc_register_main_osc(struct pmc_data *pmc, const char *name,
				  struct clk *parent, bool bypass);

struct clk *at91_clk_register_sam9x5_main(struct pmc_data *pmc,
					  const char *name,
					  struct clk **parent_clocks,
					  unsigned int num_parents);

/* PLL */
struct clk *
at91_clk_register_pll(struct pmc_data *pmc, const char *name,
		      struct clk *parent, uint8_t id,
		      const struct clk_pll_layout *layout,
		      const struct clk_pll_charac *charac);

struct clk *
at91_clk_register_plldiv(struct pmc_data *pmc, const char *name,
			 struct clk *parent);

/* UTMI */
struct clk *
at91_clk_register_utmi(struct pmc_data *pmc, const char *name,
		       struct clk *parent);

/* Master */
struct clk *
at91_clk_register_master_pres(struct pmc_data *pmc,
			      const char *name, int num_parents,
			      struct clk **parents,
			      const struct clk_master_layout *layout,
			      const struct clk_master_charac *charac,
			      int chg_pid);

struct clk *
at91_clk_register_master_div(struct pmc_data *pmc,
			     const char *name, struct clk *parent,
			     const struct clk_master_layout *layout,
			     const struct clk_master_charac *charac);

/* H32MX */
struct clk *
at91_clk_register_h32mx(struct pmc_data *pmc, const char *name,
			struct clk *parent);

/* USB */
struct clk *
at91sam9x5_clk_register_usb(struct pmc_data *pmc, const char *name,
			    struct clk **parents, uint8_t num_parents);

/* Programmable */
struct clk *
at91_clk_register_programmable(struct pmc_data *pmc,
			       const char *name, struct clk **parents,
			       uint8_t num_parents, uint8_t id,
			       const struct clk_programmable_layout *layout);

struct clk *
at91_clk_register_system(struct pmc_data *pmc, const char *name,
			 struct clk *parent, uint8_t id);

struct clk *
at91_clk_register_sam9x5_periph(struct pmc_data *pmc,
				const struct clk_pcr_layout *layout,
				const char *name, struct clk *parent,
				uint32_t id, const struct clk_range *range);

struct clk *
at91_clk_register_generated(struct pmc_data *pmc,
			    const struct clk_pcr_layout *layout,
			    const char *name, struct clk **parents,
			    uint8_t num_parents, uint8_t id,
			    const struct clk_range *range,
			    int chg_pid);

struct clk *
at91_clk_i2s_mux_register(const char *name, struct clk **parents,
			  unsigned int num_parents, uint8_t bus_id);

/* Audio PLL */
struct clk *
at91_clk_register_audio_pll_frac(struct pmc_data *pmc, const char *name,
				 struct clk *parent);

struct clk *
at91_clk_register_audio_pll_pad(struct pmc_data *pmc, const char *name,
				struct clk *parent);

struct clk *
at91_clk_register_audio_pll_pmc(struct pmc_data *pmc, const char *name,
				struct clk *parent);

#ifdef CFG_PM_ARM32
void pmc_register_id(uint8_t id);
void pmc_register_pck(uint8_t pck);
void pmc_register_pm(void);
#else
static inline void pmc_register_id(uint8_t id __unused) {}
static inline void pmc_register_pck(uint8_t pck __unused) {}
static inline void pmc_register_pm(void) {}
#endif

#endif
