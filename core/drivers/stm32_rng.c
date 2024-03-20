// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2018-2023, STMicroelectronics
 */

#include <assert.h>
#include <drivers/clk.h>
#include <drivers/clk_dt.h>
#include <drivers/rstctrl.h>
#include <io.h>
#include <kernel/boot.h>
#include <kernel/delay.h>
#include <kernel/dt.h>
#include <kernel/dt_driver.h>
#include <kernel/panic.h>
#include <kernel/pm.h>
#include <kernel/thread.h>
#include <libfdt.h>
#include <mm/core_memprot.h>
#include <rng_support.h>
#include <stdbool.h>
#include <stm32_util.h>
#include <string.h>
#include <tee/tee_cryp_utl.h>
#include <util.h>

#define RNG_CR			U(0x00)
#define RNG_SR			U(0x04)
#define RNG_DR			U(0x08)
#define RNG_NSCR		U(0x0C)
#define RNG_HTCR		U(0x10)
#define RNG_VERR		U(0x3F4)

#define RNG_CR_RNGEN		BIT(2)
#define RNG_CR_IE		BIT(3)
#define RNG_CR_CED		BIT(5)
#define RNG_CR_CONFIG1		GENMASK_32(11, 8)
#define RNG_CR_NISTC		BIT(12)
#define RNG_CR_POWER_OPTIM	BIT(13)
#define RNG_CR_CONFIG2		GENMASK_32(15, 13)
#define RNG_CR_CLKDIV		GENMASK_32(19, 16)
#define RNG_CR_CLKDIV_SHIFT	U(16)
#define RNG_CR_CONFIG3		GENMASK_32(25, 20)
#define RNG_CR_CONDRST		BIT(30)
#define RNG_CR_ENTROPY_SRC_MASK	(RNG_CR_CONFIG1 | RNG_CR_NISTC | \
				 RNG_CR_CONFIG2 | RNG_CR_CONFIG3)

#define RNG_SR_DRDY		BIT(0)
#define RNG_SR_CECS		BIT(1)
#define RNG_SR_SECS		BIT(2)
#define RNG_SR_CEIS		BIT(5)
#define RNG_SR_SEIS		BIT(6)

#define RNG_NSCR_MASK		GENMASK_32(17, 0)

#define RNG_VERR_MINOR_MASK	GENMASK_32(3, 0)
#define RNG_VERR_MAJOR_MASK	GENMASK_32(7, 4)
#define RNG_VERR_MAJOR_SHIFT	U(4)

#if TRACE_LEVEL > TRACE_DEBUG
#define RNG_READY_TIMEOUT_US	U(100000)
#else
#define RNG_READY_TIMEOUT_US	U(10000)
#endif
#define RNG_RESET_TIMEOUT_US	U(1000)

#define RNG_FIFO_BYTE_DEPTH	U(16)

#define RNG_CONFIG_MASK		(RNG_CR_ENTROPY_SRC_MASK | RNG_CR_CED | \
				 RNG_CR_CLKDIV)

struct stm32_rng_driver_data {
	unsigned long max_noise_clk_freq;
	unsigned long nb_clock;
	uint32_t cr;
	uint32_t nscr;
	uint32_t htcr;
	bool has_power_optim;
	bool has_cond_reset;
};

struct stm32_rng_instance {
	struct io_pa_va base;
	struct clk *clock;
	struct clk *bus_clock;
	struct rstctrl *rstctrl;
	const struct stm32_rng_driver_data *ddata;
	unsigned int lock;
	uint64_t error_to_ref;
	uint32_t pm_cr;
	uint32_t pm_health;
	uint32_t pm_noise_ctrl;
	uint32_t health_test_conf;
	uint32_t noise_ctrl_conf;
	uint32_t rng_config;
	bool release_post_boot;
	bool clock_error;
	bool error_conceal;
};

/* Expect at most a single RNG instance */
static struct stm32_rng_instance *stm32_rng;

static vaddr_t get_base(void)
{
	assert(stm32_rng);

	return io_pa_or_va(&stm32_rng->base, 1);
}

/*
 * Extracts from the STM32 RNG specification when RNG supports CONDRST.
 *
 * When a noise source (or seed) error occurs, the RNG stops generating
 * random numbers and sets to “1” both SEIS and SECS bits to indicate
 * that a seed error occurred. (...)
 *
 * 1. Software reset by writing CONDRST at 1 and at 0 (see bitfield
 * description for details). This step is needed only if SECS is set.
 * Indeed, when SEIS is set and SECS is cleared it means RNG performed
 * the reset automatically (auto-reset).
 * 2. If SECS was set in step 1 (no auto-reset) wait for CONDRST
 * to be cleared in the RNG_CR register, then confirm that SEIS is
 * cleared in the RNG_SR register. Otherwise just clear SEIS bit in
 * the RNG_SR register.
 * 3. If SECS was set in step 1 (no auto-reset) wait for SECS to be
 * cleared by RNG. The random number generation is now back to normal.
 */
static void conceal_seed_error_cond_reset(void)
{
	struct stm32_rng_instance *dev = stm32_rng;
	vaddr_t rng_base = get_base();

	if (!dev->error_conceal) {
		uint32_t sr = io_read32(rng_base + RNG_SR);

		if (sr & RNG_SR_SECS) {
			/* Conceal by resetting the subsystem (step 1.) */
			io_setbits32(rng_base + RNG_CR, RNG_CR_CONDRST);
			io_clrbits32(rng_base + RNG_CR, RNG_CR_CONDRST);

			/* Arm timeout for error_conceal sequence */
			dev->error_to_ref =
				timeout_init_us(RNG_READY_TIMEOUT_US);
			dev->error_conceal = true;
		} else {
			/* RNG auto-reset (step 2.) */
			io_clrbits32(rng_base + RNG_SR, RNG_SR_SEIS);
		}
	} else {
		/* Measure time before possible reschedule */
		bool timed_out = timeout_elapsed(dev->error_to_ref);

		/* Wait CONDRST is cleared (step 2.) */
		if (io_read32(rng_base + RNG_CR) & RNG_CR_CONDRST) {
			if (timed_out)
				panic();

			/* Wait subsystem reset cycle completes */
			return;
		}

		/* Check SEIS is cleared (step 2.) */
		if (io_read32(rng_base + RNG_SR) & RNG_SR_SEIS)
			panic();

		/* Wait SECS is cleared (step 3.) */
		if (io_read32(rng_base + RNG_SR) & RNG_SR_SECS) {
			if (timed_out)
				panic();

			/* Wait subsystem reset cycle completes */
			return;
		}

		dev->error_conceal = false;
	}
}

/*
 * Extracts from the STM32 RNG specification, when CONDRST is not supported
 *
 * When a noise source (or seed) error occurs, the RNG stops generating
 * random numbers and sets to “1” both SEIS and SECS bits to indicate
 * that a seed error occurred. (...)
 *
 * The following sequence shall be used to fully recover from a seed
 * error after the RNG initialization:
 * 1. Clear the SEIS bit by writing it to “0”.
 * 2. Read out 12 words from the RNG_DR register, and discard each of
 * them in order to clean the pipeline.
 * 3. Confirm that SEIS is still cleared. Random number generation is
 * back to normal.
 */
static void conceal_seed_error_sw_reset(void)
{
	vaddr_t rng_base = get_base();
	size_t i = 0;

	io_clrbits32(rng_base + RNG_SR, RNG_SR_SEIS);

	for (i = 12; i != 0; i--)
		(void)io_read32(rng_base + RNG_DR);

	if (io_read32(rng_base + RNG_SR) & RNG_SR_SEIS)
		panic("RNG noise");
}

static void conceal_seed_error(void)
{
	if (stm32_rng->ddata->has_cond_reset)
		conceal_seed_error_cond_reset();
	else
		conceal_seed_error_sw_reset();
}

static TEE_Result read_available(vaddr_t rng_base, uint8_t *out, size_t *size)
{
	struct stm32_rng_instance *dev = stm32_rng;
	uint8_t *buf = NULL;
	size_t req_size = 0;
	size_t len = 0;

	if (dev->error_conceal || io_read32(rng_base + RNG_SR) & RNG_SR_SEIS)
		conceal_seed_error();

	if (!(io_read32(rng_base + RNG_SR) & RNG_SR_DRDY)) {
		FMSG("RNG not ready");
		return TEE_ERROR_NO_DATA;
	}

	if (io_read32(rng_base + RNG_SR) & RNG_SR_SEIS) {
		FMSG("RNG noise error");
		return TEE_ERROR_NO_DATA;
	}

	buf = out;
	req_size = MIN(RNG_FIFO_BYTE_DEPTH, *size);
	len = req_size;

	/* RNG is ready: read up to 4 32bit words */
	while (len) {
		uint32_t data32 = 0;
		size_t sz = MIN(len, sizeof(uint32_t));

		if (!(io_read32(rng_base + RNG_SR) & RNG_SR_DRDY))
			break;
		data32 = io_read32(rng_base + RNG_DR);

		/* Late seed error case: DR being 0 is an error status */
		if (!data32) {
			conceal_seed_error();
			return TEE_ERROR_NO_DATA;
		}

		memcpy(buf, &data32, sz);
		buf += sz;
		len -= sz;
	}

	*size = req_size - len;

	return TEE_SUCCESS;
}

static uint32_t stm32_rng_clock_freq_restrain(void)
{
	struct stm32_rng_instance *dev = stm32_rng;
	unsigned long clock_rate = 0;
	uint32_t clock_div = 0;

	clock_rate = clk_get_rate(dev->clock);

	/*
	 * Get the exponent to apply on the CLKDIV field in RNG_CR register
	 * No need to handle the case when clock-div > 0xF as it is physically
	 * impossible
	 */
	while ((clock_rate >> clock_div) > dev->ddata->max_noise_clk_freq)
		clock_div++;

	DMSG("RNG clk rate : %lu", clk_get_rate(dev->clock) >> clock_div);

	return clock_div;
}

static TEE_Result init_rng(void)
{
	vaddr_t rng_base = get_base();
	uint32_t cr_ced_mask = 0;
	uint32_t value = 0;

	if (!stm32_rng->clock_error)
		cr_ced_mask = RNG_CR_CED;

	/* Clean error indications */
	io_write32(rng_base + RNG_SR, 0);

	if (stm32_rng->ddata->has_cond_reset) {
		uint32_t clock_div = stm32_rng_clock_freq_restrain();

		/*
		 * Keep default RNG configuration if none was specified.
		 * 0 is an invalid value as it disables all entropy sources.
		 */
		if (!stm32_rng->rng_config)
			stm32_rng->rng_config = io_read32(rng_base + RNG_CR) &
						RNG_CR_ENTROPY_SRC_MASK;

		/*
		 * Configuration must be set in the same access that sets
		 * RNG_CR_CONDRST bit. Otherwise, the configuration setting is
		 * not taken into account. CONFIGLOCK bit is always cleared at
		 * this stage.
		 */
		io_clrsetbits32(rng_base + RNG_CR, RNG_CONFIG_MASK,
				stm32_rng->rng_config | RNG_CR_CONDRST |
				cr_ced_mask |
				SHIFT_U32(clock_div, RNG_CR_CLKDIV_SHIFT));

		/*
		 * Write health test and noise source control configuration
		 * according to current RNG entropy source configuration
		 */
		if (stm32_rng->noise_ctrl_conf)
			io_write32(rng_base + RNG_NSCR,
				   stm32_rng->noise_ctrl_conf);

		if (stm32_rng->health_test_conf)
			io_write32(rng_base + RNG_HTCR,
				   stm32_rng->health_test_conf);

		io_clrsetbits32(rng_base + RNG_CR, RNG_CR_CONDRST,
				RNG_CR_RNGEN);

		if (IO_READ32_POLL_TIMEOUT(rng_base + RNG_CR, value,
					   !(value & RNG_CR_CONDRST), 0,
					   RNG_READY_TIMEOUT_US))
			panic();

		DMSG("RNG control register %#"PRIx32,
		     io_read32(rng_base + RNG_CR));
		DMSG("RNG noise source control register %#"PRIx32,
		     io_read32(rng_base + RNG_NSCR));
		DMSG("RNG health test register %#"PRIx32,
		     io_read32(rng_base + RNG_HTCR));
	} else {
		io_setbits32(rng_base + RNG_CR, RNG_CR_RNGEN | cr_ced_mask);
	}

	if (IO_READ32_POLL_TIMEOUT(rng_base + RNG_SR, value,
				   value & RNG_SR_DRDY, 0,
				   RNG_READY_TIMEOUT_US))
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

static TEE_Result stm32_rng_read(uint8_t *out, size_t size)
{
	TEE_Result rc = TEE_ERROR_GENERIC;
	bool burst_timeout = false;
	uint64_t timeout_ref = 0;
	uint32_t exceptions = 0;
	uint8_t *out_ptr = out;
	vaddr_t rng_base = 0;
	size_t out_size = 0;

	if (!stm32_rng) {
		DMSG("No RNG");
		return TEE_ERROR_NOT_SUPPORTED;
	}

	rc = clk_enable(stm32_rng->clock);
	if (rc)
		return rc;

	if (stm32_rng->bus_clock) {
		rc = clk_enable(stm32_rng->bus_clock);
		if (rc) {
			clk_disable(stm32_rng->clock);
			return rc;
		}
	}

	rng_base = get_base();

	/* Arm timeout */
	timeout_ref = timeout_init_us(RNG_READY_TIMEOUT_US);
	burst_timeout = false;

	while (out_size < size) {
		/* Read by chunks of the size the RNG FIFO depth */
		size_t sz = size - out_size;

		exceptions = may_spin_lock(&stm32_rng->lock);

		rc = read_available(rng_base, out_ptr, &sz);

		/* Raise timeout only if we failed to get some samples */
		assert(!rc || rc == TEE_ERROR_NO_DATA);
		if (rc)
			burst_timeout = timeout_elapsed(timeout_ref);

		may_spin_unlock(&stm32_rng->lock, exceptions);

		if (burst_timeout) {
			rc = TEE_ERROR_GENERIC;
			goto out;
		}

		if (!rc) {
			out_size += sz;
			out_ptr += sz;
			/* Re-arm timeout */
			timeout_ref = timeout_init_us(RNG_READY_TIMEOUT_US);
			burst_timeout = false;
		}
	}

out:
	assert(!rc || rc == TEE_ERROR_GENERIC);
	clk_disable(stm32_rng->clock);
	if (stm32_rng->bus_clock)
		clk_disable(stm32_rng->bus_clock);

	return rc;
}

#ifdef CFG_WITH_SOFTWARE_PRNG
/* Override weak plat_rng_init with platform handler to seed PRNG */
void plat_rng_init(void)
{
	uint8_t seed[RNG_FIFO_BYTE_DEPTH] = { };

	if (stm32_rng_read(seed, sizeof(seed)))
		panic();

	if (crypto_rng_init(seed, sizeof(seed)))
		panic();

	DMSG("PRNG seeded with RNG");
}
#else
TEE_Result hw_get_random_bytes(void *out, size_t size)
{
	return stm32_rng_read(out, size);
}

void plat_rng_init(void)
{
}
#endif

static TEE_Result stm32_rng_pm_resume(void)
{
	vaddr_t base = get_base();

	/* Clean error indications */
	io_write32(base + RNG_SR, 0);

	if (stm32_rng->ddata->has_cond_reset) {
		uint64_t timeout_ref = 0;

		/*
		 * Configuration must be set in the same access that sets
		 * RNG_CR_CONDRST bit. Otherwise, the configuration setting is
		 * not taken into account. CONFIGLOCK bit is always cleared in
		 * this configuration.
		 */
		io_write32(base + RNG_CR, stm32_rng->pm_cr | RNG_CR_CONDRST);

		/* Restore health test and noise control configuration */
		io_write32(base + RNG_NSCR, stm32_rng->pm_noise_ctrl);
		io_write32(base + RNG_HTCR, stm32_rng->pm_health);

		io_clrsetbits32(base + RNG_CR, RNG_CR_CONDRST, RNG_CR_RNGEN);

		timeout_ref = timeout_init_us(RNG_READY_TIMEOUT_US);
		while (io_read32(base + RNG_CR) & RNG_CR_CONDRST)
			if (timeout_elapsed(timeout_ref))
				break;
		if (io_read32(base + RNG_CR) & RNG_CR_CONDRST)
			panic();
	} else {
		io_write32(base + RNG_CR, RNG_CR_RNGEN | stm32_rng->pm_cr);
	}

	return TEE_SUCCESS;
}

static TEE_Result stm32_rng_pm_suspend(void)
{
	vaddr_t rng_base = get_base();

	stm32_rng->pm_cr = io_read32(rng_base + RNG_CR);

	if (stm32_rng->ddata->has_cond_reset) {
		stm32_rng->pm_health = io_read32(rng_base + RNG_HTCR);
		stm32_rng->pm_noise_ctrl = io_read32(rng_base + RNG_NSCR);
	}

	if (stm32_rng->ddata->has_power_optim) {
		uint64_t timeout_ref = 0;

		/*
		 * As per reference manual, it is recommended to set
		 * RNG_CONFIG2[bit0] when RNG power consumption is critical.
		 */
		io_setbits32(rng_base + RNG_CR, RNG_CR_POWER_OPTIM |
				RNG_CR_CONDRST);
		io_clrbits32(rng_base + RNG_CR, RNG_CR_CONDRST);

		timeout_ref = timeout_init_us(RNG_READY_TIMEOUT_US);
		while (io_read32(rng_base + RNG_CR) & RNG_CR_CONDRST)
			if (timeout_elapsed(timeout_ref))
				break;
		if (io_read32(rng_base + RNG_CR) & RNG_CR_CONDRST)
			panic();
	} else {
		io_clrbits32(rng_base + RNG_CR, RNG_CR_RNGEN);
	}

	return TEE_SUCCESS;
}

static TEE_Result
stm32_rng_pm(enum pm_op op, unsigned int pm_hint __unused,
	     const struct pm_callback_handle *pm_handle __unused)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	assert(stm32_rng && (op == PM_OP_SUSPEND || op == PM_OP_RESUME));

	res = clk_enable(stm32_rng->clock);
	if (res)
		return res;

	if (stm32_rng->bus_clock) {
		res = clk_enable(stm32_rng->bus_clock);
		if (res) {
			clk_disable(stm32_rng->clock);
			return res;
		}
	}

	if (op == PM_OP_RESUME)
		res = stm32_rng_pm_resume();
	else
		res = stm32_rng_pm_suspend();

	clk_disable(stm32_rng->clock);
	if (stm32_rng->bus_clock)
		clk_disable(stm32_rng->bus_clock);

	return res;
}
DECLARE_KEEP_PAGER(stm32_rng_pm);

static TEE_Result stm32_rng_parse_fdt(const void *fdt, int node)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct dt_node_info dt_rng = { };

	fdt_fill_device_info(fdt, &dt_rng, node);
	if (dt_rng.reg == DT_INFO_INVALID_REG)
		return TEE_ERROR_BAD_PARAMETERS;

	stm32_rng->base.pa = dt_rng.reg;
	stm32_rng->base.va = io_pa_or_va_secure(&stm32_rng->base,
						dt_rng.reg_size);
	assert(stm32_rng->base.va);

	res = rstctrl_dt_get_by_index(fdt, node, 0, &stm32_rng->rstctrl);
	if (res != TEE_SUCCESS && res != TEE_ERROR_ITEM_NOT_FOUND)
		return res;

	if (stm32_rng->ddata->nb_clock > 1) {
		res = clk_dt_get_by_name(fdt, node, "rng_clk",
					 &stm32_rng->clock);
		if (res)
			return res;

		res = clk_dt_get_by_name(fdt, node, "rng_hclk",
					 &stm32_rng->bus_clock);
		if (res)
			return res;
	} else {
		res = clk_dt_get_by_index(fdt, node, 0, &stm32_rng->clock);
		if (res)
			return res;
	}

	if (fdt_getprop(fdt, node, "clock-error-detect", NULL))
		stm32_rng->clock_error = true;

	/* Release device if not used after initialization */
	stm32_rng->release_post_boot = IS_ENABLED(CFG_WITH_SOFTWARE_PRNG);

	stm32_rng->rng_config = stm32_rng->ddata->cr;
	if (stm32_rng->rng_config & ~RNG_CR_ENTROPY_SRC_MASK)
		panic("Incorrect entropy source configuration");
	stm32_rng->health_test_conf = stm32_rng->ddata->htcr;
	stm32_rng->noise_ctrl_conf = stm32_rng->ddata->nscr;
	if (stm32_rng->noise_ctrl_conf & ~RNG_NSCR_MASK)
		panic("Incorrect noise source control configuration");

	return TEE_SUCCESS;
}

static TEE_Result stm32_rng_probe(const void *fdt, int offs,
				  const void *compat_data)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	unsigned int __maybe_unused version = 0;

	/* Expect a single RNG instance */
	assert(!stm32_rng);

	stm32_rng = calloc(1, sizeof(*stm32_rng));
	if (!stm32_rng)
		panic();

	stm32_rng->ddata = compat_data;
	assert(stm32_rng->ddata);

	res = stm32_rng_parse_fdt(fdt, offs);
	if (res)
		goto err;

	res = clk_enable(stm32_rng->clock);
	if (res)
		goto err;

	if (stm32_rng->bus_clock) {
		res = clk_enable(stm32_rng->bus_clock);
		if (res) {
			clk_disable(stm32_rng->clock);
			goto err;
		}
	}

	version = io_read32(get_base() + RNG_VERR);
	DMSG("RNG version Major %u, Minor %u",
	     (version & RNG_VERR_MAJOR_MASK) >> RNG_VERR_MAJOR_SHIFT,
	     version & RNG_VERR_MINOR_MASK);

	if (stm32_rng->rstctrl &&
	    rstctrl_assert_to(stm32_rng->rstctrl, RNG_RESET_TIMEOUT_US)) {
		res = TEE_ERROR_GENERIC;
		goto err_clk;
	}

	if (stm32_rng->rstctrl &&
	    rstctrl_deassert_to(stm32_rng->rstctrl, RNG_RESET_TIMEOUT_US)) {
		res = TEE_ERROR_GENERIC;
		goto err_clk;
	}

	res = init_rng();
	if (res)
		goto err_clk;

	clk_disable(stm32_rng->clock);
	if (stm32_rng->bus_clock)
		clk_disable(stm32_rng->bus_clock);

	if (stm32_rng->release_post_boot)
		stm32mp_register_non_secure_periph_iomem(stm32_rng->base.pa);
	else
		stm32mp_register_secure_periph_iomem(stm32_rng->base.pa);

	/* Power management implementation expects both or none are set */
	assert(stm32_rng->ddata->has_power_optim ==
	       stm32_rng->ddata->has_cond_reset);

	register_pm_core_service_cb(stm32_rng_pm, &stm32_rng, "rng-service");

	return TEE_SUCCESS;

err_clk:
	clk_disable(stm32_rng->clock);
	if (stm32_rng->bus_clock)
		clk_disable(stm32_rng->bus_clock);
err:
	free(stm32_rng);
	stm32_rng = NULL;

	return res;
}

static const struct stm32_rng_driver_data mp13_data[] = {
	{
		.max_noise_clk_freq = U(48000000),
		.nb_clock = 1,
		.has_cond_reset = true,
		.has_power_optim = true,
		.cr = 0x00F00D00,
		.nscr = 0x2B5BB,
		.htcr = 0x969D,
	},
};

static const struct stm32_rng_driver_data mp15_data[] = {
	{
		.max_noise_clk_freq = U(48000000),
		.nb_clock = 1,
		.has_cond_reset = false,
		.has_power_optim = false,
	},
};
DECLARE_KEEP_PAGER(mp15_data);

static const struct stm32_rng_driver_data mp25_data[] = {
	{
		.max_noise_clk_freq = U(48000000),
		.nb_clock = 2,
		.has_cond_reset = true,
		.has_power_optim = true,
		.cr = 0x00F00D00,
		.nscr = 0x2B5BB,
		.htcr = 0x969D,
	},
};

static const struct dt_device_match rng_match_table[] = {
	{ .compatible = "st,stm32-rng", .compat_data = &mp15_data },
	{ .compatible = "st,stm32mp13-rng", .compat_data = &mp13_data },
	{ .compatible = "st,stm32mp25-rng", .compat_data = &mp25_data },
	{ }
};

DEFINE_DT_DRIVER(stm32_rng_dt_driver) = {
	.name = "stm32_rng",
	.match_table = rng_match_table,
	.probe = stm32_rng_probe,
};

static TEE_Result stm32_rng_release(void)
{
	if (stm32_rng && stm32_rng->release_post_boot) {
		DMSG("Release RNG driver");
		free(stm32_rng);
		stm32_rng = NULL;
	}

	return TEE_SUCCESS;
}

release_init_resource(stm32_rng_release);
