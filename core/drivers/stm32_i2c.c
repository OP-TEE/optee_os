// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
/*
 * Copyright (c) 2017-2024, STMicroelectronics
 *
 * The driver API is defined in header file stm32_i2c.h.
 *
 * I2C bus driver does not register to the PM framework. It is the
 * responsibility of the bus owner to call the related STM32 I2C driver
 * API functions when bus suspends or resumes.
 */

#include <arm.h>
#include <drivers/clk.h>
#include <drivers/clk_dt.h>
#include <drivers/pinctrl.h>
#include <drivers/stm32_gpio.h>
#include <drivers/stm32_i2c.h>
#include <io.h>
#include <kernel/boot.h>
#include <kernel/delay.h>
#include <kernel/dt.h>
#include <kernel/dt_driver.h>
#include <kernel/mutex_pm_aware.h>
#include <kernel/panic.h>
#include <libfdt.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stm32_util.h>
#include <trace.h>

/* STM32 I2C registers offsets */
#define I2C_CR1				0x00U
#define I2C_CR2				0x04U
#define I2C_OAR1			0x08U
#define I2C_OAR2			0x0CU
#define I2C_TIMINGR			0x10U
#define I2C_TIMEOUTR			0x14U
#define I2C_ISR				0x18U
#define I2C_ICR				0x1CU
#define I2C_PECR			0x20U
#define I2C_RXDR			0x24U
#define I2C_TXDR			0x28U
#define I2C_SIZE			0x2CU

/* Bit definition for I2C_CR1 register */
#define I2C_CR1_PE			BIT(0)
#define I2C_CR1_TXIE			BIT(1)
#define I2C_CR1_RXIE			BIT(2)
#define I2C_CR1_ADDRIE			BIT(3)
#define I2C_CR1_NACKIE			BIT(4)
#define I2C_CR1_STOPIE			BIT(5)
#define I2C_CR1_TCIE			BIT(6)
#define I2C_CR1_ERRIE			BIT(7)
#define I2C_CR1_DNF			GENMASK_32(11, 8)
#define I2C_CR1_ANFOFF			BIT(12)
#define I2C_CR1_SWRST			BIT(13)
#define I2C_CR1_TXDMAEN			BIT(14)
#define I2C_CR1_RXDMAEN			BIT(15)
#define I2C_CR1_SBC			BIT(16)
#define I2C_CR1_NOSTRETCH		BIT(17)
#define I2C_CR1_WUPEN			BIT(18)
#define I2C_CR1_GCEN			BIT(19)
#define I2C_CR1_SMBHEN			BIT(22)
#define I2C_CR1_SMBDEN			BIT(21)
#define I2C_CR1_ALERTEN			BIT(22)
#define I2C_CR1_PECEN			BIT(23)

/* Bit definition for I2C_CR2 register */
#define I2C_CR2_SADD			GENMASK_32(9, 0)
#define I2C_CR2_RD_WRN			BIT(10)
#define I2C_CR2_RD_WRN_OFFSET		10U
#define I2C_CR2_ADD10			BIT(11)
#define I2C_CR2_HEAD10R			BIT(12)
#define I2C_CR2_START			BIT(13)
#define I2C_CR2_STOP			BIT(14)
#define I2C_CR2_NACK			BIT(15)
#define I2C_CR2_NBYTES			GENMASK_32(23, 16)
#define I2C_CR2_NBYTES_OFFSET		16U
#define I2C_CR2_RELOAD			BIT(24)
#define I2C_CR2_AUTOEND			BIT(25)
#define I2C_CR2_PECBYTE			BIT(26)

/* Bit definition for I2C_OAR1 register */
#define I2C_OAR1_OA1			GENMASK_32(9, 0)
#define I2C_OAR1_OA1MODE		BIT(10)
#define I2C_OAR1_OA1EN			BIT(15)

/* Bit definition for I2C_OAR2 register */
#define I2C_OAR2_OA2			GENMASK_32(7, 1)
#define I2C_OAR2_OA2MSK			GENMASK_32(10, 8)
#define I2C_OAR2_OA2NOMASK		0
#define I2C_OAR2_OA2MASK01		BIT(8)
#define I2C_OAR2_OA2MASK02		BIT(9)
#define I2C_OAR2_OA2MASK03		GENMASK_32(9, 8)
#define I2C_OAR2_OA2MASK04		BIT(10)
#define I2C_OAR2_OA2MASK05		(BIT(8) | BIT(10))
#define I2C_OAR2_OA2MASK06		(BIT(9) | BIT(10))
#define I2C_OAR2_OA2MASK07		GENMASK_32(10, 8)
#define I2C_OAR2_OA2EN			BIT(15)

/* Bit definition for I2C_TIMINGR register */
#define I2C_TIMINGR_SCLL		GENMASK_32(7, 0)
#define I2C_TIMINGR_SCLH		GENMASK_32(15, 8)
#define I2C_TIMINGR_SDADEL		GENMASK_32(19, 16)
#define I2C_TIMINGR_SCLDEL		GENMASK_32(23, 20)
#define I2C_TIMINGR_PRESC		GENMASK_32(31, 28)
#define I2C_TIMINGR_SCLL_MAX		(I2C_TIMINGR_SCLL + 1)
#define I2C_TIMINGR_SCLH_MAX		((I2C_TIMINGR_SCLH >> 8) + 1)
#define I2C_TIMINGR_SDADEL_MAX		((I2C_TIMINGR_SDADEL >> 16) + 1)
#define I2C_TIMINGR_SCLDEL_MAX		((I2C_TIMINGR_SCLDEL >> 20) + 1)
#define I2C_TIMINGR_PRESC_MAX		((I2C_TIMINGR_PRESC >> 28) + 1)
#define I2C_SET_TIMINGR_SCLL(n)		((n) & \
					 (I2C_TIMINGR_SCLL_MAX - 1))
#define I2C_SET_TIMINGR_SCLH(n)		(((n) & \
					  (I2C_TIMINGR_SCLH_MAX - 1)) << 8)
#define I2C_SET_TIMINGR_SDADEL(n)	(((n) & \
					  (I2C_TIMINGR_SDADEL_MAX - 1)) << 16)
#define I2C_SET_TIMINGR_SCLDEL(n)	(((n) & \
					  (I2C_TIMINGR_SCLDEL_MAX - 1)) << 20)
#define I2C_SET_TIMINGR_PRESC(n)	(((n) & \
					  (I2C_TIMINGR_PRESC_MAX - 1)) << 28)

/* Bit definition for I2C_TIMEOUTR register */
#define I2C_TIMEOUTR_TIMEOUTA		GENMASK_32(11, 0)
#define I2C_TIMEOUTR_TIDLE		BIT(12)
#define I2C_TIMEOUTR_TIMOUTEN		BIT(15)
#define I2C_TIMEOUTR_TIMEOUTB		GENMASK_32(27, 16)
#define I2C_TIMEOUTR_TEXTEN		BIT(31)

/* Bit definition for I2C_ISR register */
#define I2C_ISR_TXE			BIT(0)
#define I2C_ISR_TXIS			BIT(1)
#define I2C_ISR_RXNE			BIT(2)
#define I2C_ISR_ADDR			BIT(3)
#define I2C_ISR_NACKF			BIT(4)
#define I2C_ISR_STOPF			BIT(5)
#define I2C_ISR_TC			BIT(6)
#define I2C_ISR_TCR			BIT(7)
#define I2C_ISR_BERR			BIT(8)
#define I2C_ISR_ARLO			BIT(9)
#define I2C_ISR_OVR			BIT(10)
#define I2C_ISR_PECERR			BIT(11)
#define I2C_ISR_TIMEOUT			BIT(12)
#define I2C_ISR_ALERT			BIT(13)
#define I2C_ISR_BUSY			BIT(15)
#define I2C_ISR_DIR			BIT(16)
#define I2C_ISR_ADDCODE			GENMASK_32(23, 17)

/* Bit definition for I2C_ICR register */
#define I2C_ICR_ADDRCF			BIT(3)
#define I2C_ICR_NACKCF			BIT(4)
#define I2C_ICR_STOPCF			BIT(5)
#define I2C_ICR_BERRCF			BIT(8)
#define I2C_ICR_ARLOCF			BIT(9)
#define I2C_ICR_OVRCF			BIT(10)
#define I2C_ICR_PECCF			BIT(11)
#define I2C_ICR_TIMOUTCF		BIT(12)
#define I2C_ICR_ALERTCF			BIT(13)

/* Max data size for a single I2C transfer */
#define MAX_NBYTE_SIZE			255U

#define I2C_NSEC_PER_SEC		1000000000UL
#define I2C_TIMEOUT_BUSY_MS		25
#define I2C_TIMEOUT_BUSY_US		(I2C_TIMEOUT_BUSY_MS * 1000)
#define I2C_TIMEOUT_RXNE_MS		5

#define I2C_TIMEOUT_DEFAULT_MS		100

#define CR2_RESET_MASK			(I2C_CR2_SADD | I2C_CR2_HEAD10R | \
					 I2C_CR2_NBYTES | I2C_CR2_RELOAD | \
					 I2C_CR2_RD_WRN)

#define TIMINGR_CLEAR_MASK		(I2C_TIMINGR_SCLL | I2C_TIMINGR_SCLH | \
					 I2C_TIMINGR_SDADEL | \
					 I2C_TIMINGR_SCLDEL | I2C_TIMINGR_PRESC)

/*
 * I2C transfer modes
 * I2C_RELOAD: Enable Reload mode
 * I2C_AUTOEND_MODE: Enable automatic end mode
 * I2C_SOFTEND_MODE: Enable software end mode
 */
#define I2C_RELOAD_MODE				I2C_CR2_RELOAD
#define I2C_AUTOEND_MODE			I2C_CR2_AUTOEND
#define I2C_SOFTEND_MODE			0x0

/*
 * Start/restart/stop I2C transfer requests.
 *
 * I2C_NO_STARTSTOP: Don't Generate stop and start condition
 * I2C_GENERATE_STOP: Generate stop condition (size should be set to 0)
 * I2C_GENERATE_START_READ: Generate Restart for read request.
 * I2C_GENERATE_START_WRITE: Generate Restart for write request
 */
#define I2C_NO_STARTSTOP			0x0
#define I2C_GENERATE_STOP			(BIT(31) | I2C_CR2_STOP)
#define I2C_GENERATE_START_READ			(BIT(31) | I2C_CR2_START | \
						 I2C_CR2_RD_WRN)
#define I2C_GENERATE_START_WRITE		(BIT(31) | I2C_CR2_START)

/* Memory address byte sizes */
#define I2C_MEMADD_SIZE_8BIT		1
#define I2C_MEMADD_SIZE_16BIT		2

/* Effective rate cannot be lower than 80% target rate */
#define RATE_MIN(rate)			(((rate) * 80U) / 100U)

/*
 * struct i2c_spec_s - Private I2C timing specifications.
 * @rate: I2C bus speed (Hz)
 * @fall_max: Max fall time of both SDA and SCL signals (ns)
 * @rise_max: Max rise time of both SDA and SCL signals (ns)
 * @hddat_min: Min data hold time (ns)
 * @vddat_max: Max data valid time (ns)
 * @sudat_min: Min data setup time (ns)
 * @l_min: Min low period of the SCL clock (ns)
 * @h_min: Min high period of the SCL clock (ns)
 */
struct i2c_spec_s {
	uint32_t rate;
	uint32_t fall_max;
	uint32_t rise_max;
	uint32_t hddat_min;
	uint32_t vddat_max;
	uint32_t sudat_min;
	uint32_t l_min;
	uint32_t h_min;
};

/*
 * struct i2c_timing_s - Private I2C output parameters.
 * @scldel: Data setup time
 * @sdadel: Data hold time
 * @sclh: SCL high period (master mode)
 * @sclh: SCL low period (master mode)
 * @is_saved: True if relating to a configuration candidate
 */
struct i2c_timing_s {
	uint8_t scldel;
	uint8_t sdadel;
	uint8_t sclh;
	uint8_t scll;
	bool is_saved;
};

/* This table must be sorted in increasing value for field @rate */
static const struct i2c_spec_s i2c_specs[] = {
	/* Standard - 100KHz */
	{
		.rate = I2C_STANDARD_RATE,
		.fall_max = 300,
		.rise_max = 1000,
		.hddat_min = 0,
		.vddat_max = 3450,
		.sudat_min = 250,
		.l_min = 4700,
		.h_min = 4000,
	},
	/* Fast - 400KHz */
	{
		.rate = I2C_FAST_RATE,
		.fall_max = 300,
		.rise_max = 300,
		.hddat_min = 0,
		.vddat_max = 900,
		.sudat_min = 100,
		.l_min = 1300,
		.h_min = 600,
	},
	/* FastPlus - 1MHz */
	{
		.rate = I2C_FAST_PLUS_RATE,
		.fall_max = 100,
		.rise_max = 120,
		.hddat_min = 0,
		.vddat_max = 450,
		.sudat_min = 50,
		.l_min = 500,
		.h_min = 260,
	},
};

/*
 * I2C request parameters
 * @dev_addr: I2C address of the target device
 * @mode: Communication mode, one of I2C_MODE_(MASTER|MEM)
 * @mem_addr: Target memory cell accessed in device (memory mode)
 * @mem_addr_size: Byte size of the memory cell address (memory mode)
 * @timeout_ms: Timeout in millisenconds for the request
 */
struct i2c_request {
	uint32_t dev_addr;
	enum i2c_mode_e mode;
	uint32_t mem_addr;
	uint32_t mem_addr_size;
	unsigned int timeout_ms;
};

static vaddr_t get_base(struct i2c_handle_s *hi2c)
{
	return io_pa_or_va_secure(&hi2c->base, hi2c->reg_size);
}

static void notif_i2c_timeout(struct i2c_handle_s *hi2c)
{
	hi2c->i2c_err |= I2C_ERROR_TIMEOUT;
	hi2c->i2c_state = I2C_STATE_READY;
}

static const struct i2c_spec_s *get_specs(uint32_t rate)
{
	size_t i = 0;

	for (i = 0; i < ARRAY_SIZE(i2c_specs); i++)
		if (rate <= i2c_specs[i].rate)
			return i2c_specs + i;

	return NULL;
}

static void save_cfg(struct i2c_handle_s *hi2c, struct i2c_cfg *cfg)
{
	vaddr_t base = get_base(hi2c);

	clk_enable(hi2c->clock);

	cfg->cr1 = io_read32(base + I2C_CR1);
	cfg->cr2 = io_read32(base + I2C_CR2);
	cfg->oar1 = io_read32(base + I2C_OAR1);
	cfg->oar2 = io_read32(base + I2C_OAR2);
	cfg->timingr = io_read32(base + I2C_TIMINGR);

	clk_disable(hi2c->clock);
}

static void restore_cfg(struct i2c_handle_s *hi2c, struct i2c_cfg *cfg)
{
	vaddr_t base = get_base(hi2c);

	clk_enable(hi2c->clock);

	io_clrbits32(base + I2C_CR1, I2C_CR1_PE);
	io_write32(base + I2C_TIMINGR, cfg->timingr & TIMINGR_CLEAR_MASK);
	io_write32(base + I2C_OAR1, cfg->oar1);
	io_write32(base + I2C_CR2, cfg->cr2);
	io_write32(base + I2C_OAR2, cfg->oar2);
	io_write32(base + I2C_CR1, cfg->cr1 & ~I2C_CR1_PE);
	io_setbits32(base + I2C_CR1, cfg->cr1 & I2C_CR1_PE);

	clk_disable(hi2c->clock);
}

static void __maybe_unused dump_cfg(struct i2c_cfg *cfg __maybe_unused)
{
	DMSG("CR1:  %#"PRIx32, cfg->cr1);
	DMSG("CR2:  %#"PRIx32, cfg->cr2);
	DMSG("OAR1: %#"PRIx32, cfg->oar1);
	DMSG("OAR2: %#"PRIx32, cfg->oar2);
	DMSG("TIM:  %#"PRIx32, cfg->timingr);
}

static void __maybe_unused dump_i2c(struct i2c_handle_s *hi2c)
{
	vaddr_t __maybe_unused base = get_base(hi2c);

	clk_enable(hi2c->clock);

	DMSG("CR1:  %#"PRIx32, io_read32(base + I2C_CR1));
	DMSG("CR2:  %#"PRIx32, io_read32(base + I2C_CR2));
	DMSG("OAR1: %#"PRIx32, io_read32(base + I2C_OAR1));
	DMSG("OAR2: %#"PRIx32, io_read32(base + I2C_OAR2));
	DMSG("TIM:  %#"PRIx32, io_read32(base + I2C_TIMINGR));

	clk_disable(hi2c->clock);
}

/*
 * Compute the I2C device timings
 *
 * @init: Ref to the initialization configuration structure
 * @clock_src: I2C clock source frequency (Hz)
 * @timing: Pointer to the final computed timing result
 * Return 0 on success or a negative value
 */
static int i2c_compute_timing(struct stm32_i2c_init_s *init,
			      unsigned long clock_src, uint32_t *timing)
{
	const struct i2c_spec_s *specs = NULL;
	uint32_t speed_freq = 0;
	uint32_t i2cbus = UDIV_ROUND_NEAREST(I2C_NSEC_PER_SEC, speed_freq);
	uint32_t i2cclk = UDIV_ROUND_NEAREST(I2C_NSEC_PER_SEC, clock_src);
	uint32_t p_prev = I2C_TIMINGR_PRESC_MAX;
	uint32_t af_delay_min = 0;
	uint32_t af_delay_max = 0;
	uint32_t dnf_delay = 0;
	uint32_t tsync = 0;
	uint32_t clk_min = 0;
	uint32_t clk_max = 0;
	int clk_error_prev = 0;
	uint16_t p = 0;
	uint16_t l = 0;
	uint16_t a = 0;
	uint16_t h = 0;
	unsigned int sdadel_min = 0;
	unsigned int sdadel_max = 0;
	unsigned int scldel_min = 0;
	unsigned int delay = 0;
	int s = -1;
	struct i2c_timing_s solutions[I2C_TIMINGR_PRESC_MAX] = { 0 };

	specs = get_specs(init->bus_rate);
	if (!specs) {
		DMSG("I2C speed out of bound: %"PRId32"Hz", init->bus_rate);
		return -1;
	}

	speed_freq = specs->rate;
	i2cbus = UDIV_ROUND_NEAREST(I2C_NSEC_PER_SEC, speed_freq);
	clk_error_prev = INT_MAX;

	if (init->rise_time > specs->rise_max ||
	    init->fall_time > specs->fall_max) {
		DMSG("I2C rise{%"PRId32">%"PRId32"}/fall{%"PRId32">%"PRId32"}",
		     init->rise_time, specs->rise_max,
		     init->fall_time, specs->fall_max);
		return -1;
	}

	if (init->digital_filter_coef > STM32_I2C_DIGITAL_FILTER_MAX) {
		DMSG("DNF out of bound %"PRId8"/%d",
		     init->digital_filter_coef, STM32_I2C_DIGITAL_FILTER_MAX);
		return -1;
	}

	/* Analog and Digital Filters */
	if (init->analog_filter) {
		af_delay_min = STM32_I2C_ANALOG_FILTER_DELAY_MIN;
		af_delay_max = STM32_I2C_ANALOG_FILTER_DELAY_MAX;
	}
	dnf_delay = init->digital_filter_coef * i2cclk;

	sdadel_min = specs->hddat_min + init->fall_time;
	delay = af_delay_min - ((init->digital_filter_coef + 3) * i2cclk);
	if (SUB_OVERFLOW(sdadel_min, delay, &sdadel_min))
		sdadel_min = 0;

	sdadel_max = specs->vddat_max - init->rise_time;
	delay = af_delay_max - ((init->digital_filter_coef + 4) * i2cclk);
	if (SUB_OVERFLOW(sdadel_max, delay, &sdadel_max))
		sdadel_max = 0;

	scldel_min = init->rise_time + specs->sudat_min;

	DMSG("I2C SDADEL(min/max): %u/%u, SCLDEL(Min): %u",
	     sdadel_min, sdadel_max, scldel_min);

	/* Compute possible values for PRESC, SCLDEL and SDADEL */
	for (p = 0; p < I2C_TIMINGR_PRESC_MAX; p++) {
		for (l = 0; l < I2C_TIMINGR_SCLDEL_MAX; l++) {
			uint32_t scldel = (l + 1) * (p + 1) * i2cclk;

			if (scldel < scldel_min)
				continue;

			for (a = 0; a < I2C_TIMINGR_SDADEL_MAX; a++) {
				uint32_t sdadel = (a * (p + 1) + 1) * i2cclk;

				if ((sdadel >= sdadel_min) &&
				    (sdadel <= sdadel_max) &&
				    (p != p_prev)) {
					solutions[p].scldel = l;
					solutions[p].sdadel = a;
					solutions[p].is_saved = true;
					p_prev = p;
					break;
				}
			}

			if (p_prev == p)
				break;
		}
	}

	if (p_prev == I2C_TIMINGR_PRESC_MAX) {
		DMSG("I2C no Prescaler solution");
		return -1;
	}

	tsync = af_delay_min + dnf_delay + (2 * i2cclk);
	clk_max = I2C_NSEC_PER_SEC / RATE_MIN(specs->rate);
	clk_min = I2C_NSEC_PER_SEC / specs->rate;

	/*
	 * Among prescaler possibilities discovered above figures out SCL Low
	 * and High Period. Provided:
	 * - SCL Low Period has to be higher than Low Period of the SCL Clock
	 *   defined by I2C Specification. I2C Clock has to be lower than
	 *   (SCL Low Period - Analog/Digital filters) / 4.
	 * - SCL High Period has to be lower than High Period of the SCL Clock
	 *   defined by I2C Specification.
	 * - I2C Clock has to be lower than SCL High Period.
	 */
	for (p = 0; p < I2C_TIMINGR_PRESC_MAX; p++) {
		uint32_t prescaler = (p + 1) * i2cclk;

		if (!solutions[p].is_saved)
			continue;

		for (l = 0; l < I2C_TIMINGR_SCLL_MAX; l++) {
			uint32_t tscl_l = ((l + 1) * prescaler) + tsync;

			if (tscl_l < specs->l_min ||
			    i2cclk >= ((tscl_l - af_delay_min - dnf_delay) / 4))
				continue;

			for (h = 0; h < I2C_TIMINGR_SCLH_MAX; h++) {
				uint32_t tscl_h = ((h + 1) * prescaler) + tsync;
				uint32_t tscl = tscl_l + tscl_h +
						init->rise_time +
						init->fall_time;

				if (tscl >= clk_min && tscl <= clk_max &&
				    tscl_h >= specs->h_min && i2cclk < tscl_h) {
					int clk_error = tscl - i2cbus;

					if (clk_error < 0)
						clk_error = -clk_error;

					if (clk_error < clk_error_prev) {
						clk_error_prev = clk_error;
						solutions[p].scll = l;
						solutions[p].sclh = h;
						s = p;
					}
				}
			}
		}
	}

	if (s < 0) {
		DMSG("I2C no solution at all");
		return -1;
	}

	/* Finalize timing settings */
	*timing = I2C_SET_TIMINGR_PRESC(s) |
		   I2C_SET_TIMINGR_SCLDEL(solutions[s].scldel) |
		   I2C_SET_TIMINGR_SDADEL(solutions[s].sdadel) |
		   I2C_SET_TIMINGR_SCLH(solutions[s].sclh) |
		   I2C_SET_TIMINGR_SCLL(solutions[s].scll);

	DMSG("I2C TIMINGR (PRESC/SCLDEL/SDADEL): %i/%"PRIu8"/%"PRIu8,
	     s, solutions[s].scldel, solutions[s].sdadel);
	DMSG("I2C TIMINGR (SCLH/SCLL): %"PRIu8"/%"PRIu8,
	     solutions[s].sclh, solutions[s].scll);
	DMSG("I2C TIMINGR: 0x%"PRIx32, *timing);

	return 0;
}

/* i2c_specs[] must be sorted by increasing rate */
static bool __maybe_unused i2c_specs_is_consistent(void)
{
	size_t i = 0;

	COMPILE_TIME_ASSERT(ARRAY_SIZE(i2c_specs));

	for (i = 1; i < ARRAY_SIZE(i2c_specs); i++)
		if (i2c_specs[i - 1].rate >= i2c_specs[i].rate)
			return false;

	return true;
}

/*
 * @brief  From requested rate, get the closest I2C rate without exceeding it,
 *         within I2C specification values defined in @i2c_specs.
 * @param  rate: The requested rate.
 * @retval Found rate, else the lowest value supported by platform.
 */
static uint32_t get_lower_rate(uint32_t rate)
{
	size_t i = 0;

	for (i = ARRAY_SIZE(i2c_specs); i > 0; i--)
		if (rate > i2c_specs[i - 1].rate)
			return i2c_specs[i - 1].rate;

	return i2c_specs[0].rate;
}

/*
 * Setup the I2C device timings
 *
 * @hi2c: I2C handle structure
 * @init: Ref to the initialization configuration structure
 * @timing: Output TIMINGR register configuration value
 * @retval 0 if OK, negative value else
 */
static int i2c_setup_timing(struct i2c_handle_s *hi2c,
			    struct stm32_i2c_init_s *init,
			    uint32_t *timing)
{
	int rc = 0;
	unsigned long clock_src = 0;

	assert(i2c_specs_is_consistent());

	clock_src = clk_get_rate(hi2c->clock);
	if (!clock_src) {
		DMSG("Null I2C clock rate");
		return -1;
	}

	/*
	 * If the timing has already been computed, and the frequency is the
	 * same as when it was computed, then use the saved timing.
	 */
	if (clock_src == hi2c->saved_frequency) {
		*timing = hi2c->saved_timing;
		return 0;
	}

	do {
		rc = i2c_compute_timing(init, clock_src, timing);
		if (rc) {
			DMSG("Failed to compute I2C timings");
			if (init->bus_rate > I2C_STANDARD_RATE) {
				init->bus_rate = get_lower_rate(init->bus_rate);
				IMSG("Downgrade I2C speed to %"PRIu32"Hz)",
				     init->bus_rate);
			} else {
				break;
			}
		}
	} while (rc);

	if (rc) {
		DMSG("Impossible to compute I2C timings");
		return rc;
	}

	DMSG("I2C Freq(%"PRIu32"Hz), Clk Source(%lu)",
	     init->bus_rate, clock_src);
	DMSG("I2C Rise(%"PRId32") and Fall(%"PRId32") Time",
	     init->rise_time, init->fall_time);
	DMSG("I2C Analog Filter(%s), DNF(%"PRIu8")",
	     init->analog_filter ? "On" : "Off", init->digital_filter_coef);

	hi2c->saved_timing = *timing;
	hi2c->saved_frequency = clock_src;

	return 0;
}

/*
 * Configure I2C Analog noise filter.
 * @hi2c: I2C handle structure
 * @analog_filter_on: True if enabling analog filter, false otherwise
 */
static void i2c_config_analog_filter(struct i2c_handle_s *hi2c,
				     bool analog_filter_on)
{
	vaddr_t base = get_base(hi2c);

	/* Disable the selected I2C peripheral */
	io_clrbits32(base + I2C_CR1, I2C_CR1_PE);

	/* Reset I2Cx ANOFF bit */
	io_clrbits32(base + I2C_CR1, I2C_CR1_ANFOFF);

	/* Set analog filter bit if filter is disabled */
	if (!analog_filter_on)
		io_setbits32(base + I2C_CR1, I2C_CR1_ANFOFF);

	/* Enable the selected I2C peripheral */
	io_setbits32(base + I2C_CR1, I2C_CR1_PE);
}

TEE_Result stm32_i2c_get_setup_from_fdt(void *fdt, int node,
					struct stm32_i2c_init_s *init,
					struct pinctrl_state **pinctrl,
					struct pinctrl_state **pinctrl_sleep)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	const fdt32_t *cuint = NULL;
	struct dt_node_info info = { .status = 0 };
	int __maybe_unused count = 0;

	/* Default STM32 specific configs caller may need to overwrite */
	memset(init, 0, sizeof(*init));

	fdt_fill_device_info(fdt, &info, node);
	assert(info.reg != DT_INFO_INVALID_REG &&
	       info.reg_size != DT_INFO_INVALID_REG_SIZE);

	init->dt_status = info.status;
	init->pbase = info.reg;
	init->reg_size = info.reg_size;

	res = clk_dt_get_by_index(fdt, node, 0, &init->clock);
	if (res)
		return res;

	cuint = fdt_getprop(fdt, node, "i2c-scl-rising-time-ns", NULL);
	if (cuint)
		init->rise_time = fdt32_to_cpu(*cuint);
	else
		init->rise_time = STM32_I2C_RISE_TIME_DEFAULT;

	cuint = fdt_getprop(fdt, node, "i2c-scl-falling-time-ns", NULL);
	if (cuint)
		init->fall_time = fdt32_to_cpu(*cuint);
	else
		init->fall_time = STM32_I2C_FALL_TIME_DEFAULT;

	cuint = fdt_getprop(fdt, node, "clock-frequency", NULL);
	if (cuint) {
		init->bus_rate = fdt32_to_cpu(*cuint);

		if (init->bus_rate > I2C_FAST_PLUS_RATE) {
			DMSG("Invalid bus speed (%"PRIu32" > %i)",
			     init->bus_rate, I2C_FAST_PLUS_RATE);
			return TEE_ERROR_GENERIC;
		}
	} else {
		init->bus_rate = I2C_STANDARD_RATE;
	}

	if (pinctrl) {
		res = pinctrl_get_state_by_name(fdt, node, "default", pinctrl);
		if (res)
			return res;
	}

	if (pinctrl_sleep) {
		res = pinctrl_get_state_by_name(fdt, node, "sleep",
						pinctrl_sleep);
		if (res == TEE_ERROR_ITEM_NOT_FOUND)
			res = TEE_SUCCESS;
		if (res)
			return res;
	}

	return TEE_SUCCESS;
}

int stm32_i2c_init(struct i2c_handle_s *hi2c,
		   struct stm32_i2c_init_s *init_data)
{
	int rc = 0;
	uint32_t timing = 0;
	vaddr_t base = 0;
	uint32_t val = 0;

	mutex_pm_aware_init(&hi2c->mu);

	rc = i2c_setup_timing(hi2c, init_data, &timing);
	if (rc)
		return rc;

	clk_enable(hi2c->clock);

	base = get_base(hi2c);
	hi2c->i2c_state = I2C_STATE_BUSY;

	/* Disable the selected I2C peripheral */
	io_clrbits32(base + I2C_CR1, I2C_CR1_PE);

	/* Configure I2Cx: Frequency range */
	io_write32(base + I2C_TIMINGR, timing & TIMINGR_CLEAR_MASK);

	/* Disable Own Address1 before set the Own Address1 configuration */
	io_write32(base + I2C_OAR1, 0);

	/* Configure I2Cx: Own Address1 and ack own address1 mode */
	if (init_data->addr_mode_10b_not_7b)
		io_write32(base + I2C_OAR1,
			   I2C_OAR1_OA1EN | I2C_OAR1_OA1MODE |
			   init_data->own_address1);
	else
		io_write32(base + I2C_OAR1,
			   I2C_OAR1_OA1EN | init_data->own_address1);

	/* Configure I2Cx: Addressing Master mode */
	io_write32(base + I2C_CR2, 0);
	if (init_data->addr_mode_10b_not_7b)
		io_setbits32(base + I2C_CR2, I2C_CR2_ADD10);

	/*
	 * Enable the AUTOEND by default, and enable NACK
	 * (should be disabled only during Slave process).
	 */
	io_setbits32(base + I2C_CR2, I2C_CR2_AUTOEND | I2C_CR2_NACK);

	/* Disable Own Address2 before set the Own Address2 configuration */
	io_write32(base + I2C_OAR2, 0);

	/* Configure I2Cx: Dual mode and Own Address2 */
	if (init_data->dual_address_mode)
		io_write32(base + I2C_OAR2,
			   I2C_OAR2_OA2EN | init_data->own_address2 |
			   (init_data->own_address2_masks << 8));

	/* Configure I2Cx: Generalcall and NoStretch mode */
	val = 0;
	if (init_data->general_call_mode)
		val |= I2C_CR1_GCEN;
	if (init_data->no_stretch_mode)
		val |= I2C_CR1_NOSTRETCH;
	io_write32(base + I2C_CR1, val);

	/* Enable the selected I2C peripheral */
	io_setbits32(base + I2C_CR1, I2C_CR1_PE);

	hi2c->i2c_err = I2C_ERROR_NONE;
	hi2c->i2c_state = I2C_STATE_READY;

	i2c_config_analog_filter(hi2c, init_data->analog_filter);

	if (IS_ENABLED(CFG_STM32MP13))
		stm32_pinctrl_set_secure_cfg(hi2c->pinctrl, true);

	clk_disable(hi2c->clock);

	if (hi2c->pinctrl && pinctrl_apply_state(hi2c->pinctrl))
		return -1;

	return 0;
}

/* I2C transmit (TX) data register flush sequence */
static void i2c_flush_txdr(struct i2c_handle_s *hi2c)
{
	vaddr_t base = get_base(hi2c);

	/*
	 * If a pending TXIS flag is set,
	 * write a dummy data in TXDR to clear it.
	 */
	if (io_read32(base + I2C_ISR) & I2C_ISR_TXIS)
		io_write32(base + I2C_TXDR, 0);

	/* Flush TX register if not empty */
	if ((io_read32(base + I2C_ISR) & I2C_ISR_TXE) == 0)
		io_setbits32(base + I2C_ISR, I2C_ISR_TXE);
}

/*
 * Wait for a single target I2C_ISR bit to reach an awaited value (0 or 1)
 *
 * @hi2c: I2C handle structure
 * @bit_mask: Bit mask for the target single bit position to consider
 * @awaited_value: Awaited value of the target bit in I2C_ISR, 0 or 1
 * @timeout_ref: Expriation timeout reference
 * Return 0 on success and a non-zero value on timeout
 */
static int wait_isr_event(struct i2c_handle_s *hi2c, uint32_t bit_mask,
			  unsigned int awaited_value, uint64_t timeout_ref)
{
	vaddr_t isr = get_base(hi2c) + I2C_ISR;

	assert(IS_POWER_OF_TWO(bit_mask) && !(awaited_value & ~1U));

	/* May timeout while TEE thread is suspended */
	while (!timeout_elapsed(timeout_ref))
		if (!!(io_read32(isr) & bit_mask) == awaited_value)
			break;

	if (!!(io_read32(isr) & bit_mask) == awaited_value)
		return 0;

	notif_i2c_timeout(hi2c);
	return -1;
}

/* Handle Acknowledge-Failed sequence detection during an I2C Communication */
static int i2c_ack_failed(struct i2c_handle_s *hi2c, uint64_t timeout_ref)
{
	vaddr_t base = get_base(hi2c);

	if ((io_read32(base + I2C_ISR) & I2C_ISR_NACKF) == 0U)
		return 0;

	/*
	 * Wait until STOP Flag is reset. Use polling method.
	 * AutoEnd should be initiate after AF.
	 * Timeout may elpased while TEE thread is suspended.
	 */
	while (!timeout_elapsed(timeout_ref))
		if (io_read32(base + I2C_ISR) & I2C_ISR_STOPF)
			break;

	if ((io_read32(base + I2C_ISR) & I2C_ISR_STOPF) == 0) {
		notif_i2c_timeout(hi2c);
		return -1;
	}

	io_write32(base + I2C_ICR, I2C_ISR_NACKF);

	io_write32(base + I2C_ICR, I2C_ISR_STOPF);

	i2c_flush_txdr(hi2c);

	io_clrbits32(base + I2C_CR2, CR2_RESET_MASK);

	hi2c->i2c_err |= I2C_ERROR_ACKF;
	hi2c->i2c_state = I2C_STATE_READY;

	return -1;
}

/* Wait TXIS bit is 1 in I2C_ISR register */
static int i2c_wait_txis(struct i2c_handle_s *hi2c, uint64_t timeout_ref)
{
	while (!timeout_elapsed(timeout_ref)) {
		if (io_read32(get_base(hi2c) + I2C_ISR) & I2C_ISR_TXIS)
			break;
		if (i2c_ack_failed(hi2c, timeout_ref))
			return -1;
	}

	if (io_read32(get_base(hi2c) + I2C_ISR) & I2C_ISR_TXIS)
		return 0;

	if (i2c_ack_failed(hi2c, timeout_ref))
		return -1;

	notif_i2c_timeout(hi2c);
	return -1;
}

/* Wait STOPF bit is 1 in I2C_ISR register */
static int i2c_wait_stop(struct i2c_handle_s *hi2c, uint64_t timeout_ref)
{
	while (!timeout_elapsed(timeout_ref)) {
		if (io_read32(get_base(hi2c) + I2C_ISR) & I2C_ISR_STOPF)
			break;

		if (i2c_ack_failed(hi2c, timeout_ref))
			return -1;
	}

	if (io_read32(get_base(hi2c) + I2C_ISR) & I2C_ISR_STOPF)
		return 0;

	if (i2c_ack_failed(hi2c, timeout_ref))
		return -1;

	notif_i2c_timeout(hi2c);
	return -1;
}

/*
 * Load I2C_CR2 register for a I2C transfer
 *
 * @hi2c: I2C handle structure
 * @dev_addr: Slave address to be transferred
 * @size: Number of bytes to be transferred
 * @i2c_mode: One of I2C_{RELOAD|AUTOEND|SOFTEND}_MODE: Enable Reload mode.
 * @startstop: One of I2C_NO_STARTSTOP, I2C_GENERATE_STOP,
 *		I2C_GENERATE_START_{READ|WRITE}
 */
static void i2c_transfer_config(struct i2c_handle_s *hi2c, uint32_t dev_addr,
				uint32_t size, uint32_t i2c_mode,
				uint32_t startstop)
{
	uint32_t clr_value = I2C_CR2_SADD | I2C_CR2_NBYTES | I2C_CR2_RELOAD |
			     I2C_CR2_AUTOEND | I2C_CR2_START | I2C_CR2_STOP |
			     (I2C_CR2_RD_WRN &
			      (startstop >> (31U - I2C_CR2_RD_WRN_OFFSET)));
	uint32_t set_value = (dev_addr & I2C_CR2_SADD) |
			     ((size << I2C_CR2_NBYTES_OFFSET) &
			      I2C_CR2_NBYTES) |
			     i2c_mode | startstop;

	io_clrsetbits32(get_base(hi2c) + I2C_CR2, clr_value, set_value);
}

/*
 * Master sends target device address followed by internal memory
 * address for a memory write request.
 * Function returns 0 on success or a negative value.
 */
static int i2c_request_mem_write(struct i2c_handle_s *hi2c,
				 struct i2c_request *request,
				 uint64_t timeout_ref)
{
	vaddr_t base = get_base(hi2c);

	i2c_transfer_config(hi2c, request->dev_addr, request->mem_addr_size,
			    I2C_RELOAD_MODE, I2C_GENERATE_START_WRITE);

	if (i2c_wait_txis(hi2c, timeout_ref))
		return -1;

	if (request->mem_addr_size == I2C_MEMADD_SIZE_8BIT) {
		/* Send memory address */
		io_write8(base + I2C_TXDR, request->mem_addr & 0x00FFU);
	} else {
		/* Send MSB of memory address */
		io_write8(base + I2C_TXDR, (request->mem_addr & 0xFF00U) >> 8);

		if (i2c_wait_txis(hi2c, timeout_ref))
			return -1;

		/* Send LSB of memory address */
		io_write8(base + I2C_TXDR, request->mem_addr & 0x00FFU);
	}

	if (wait_isr_event(hi2c, I2C_ISR_TCR, 1, timeout_ref))
		return -1;

	return 0;
}

/*
 * Master sends target device address followed by internal memory
 * address to prepare a memory read request.
 * Function returns 0 on success or a negative value.
 */
static int i2c_request_mem_read(struct i2c_handle_s *hi2c,
				struct i2c_request *request,
				uint64_t timeout_ref)
{
	vaddr_t base = get_base(hi2c);

	i2c_transfer_config(hi2c, request->dev_addr, request->mem_addr_size,
			    I2C_SOFTEND_MODE, I2C_GENERATE_START_WRITE);

	if (i2c_wait_txis(hi2c, timeout_ref))
		return -1;

	if (request->mem_addr_size == I2C_MEMADD_SIZE_8BIT) {
		/* Send memory address */
		io_write8(base + I2C_TXDR, request->mem_addr & 0x00FFU);
	} else {
		/* Send MSB of memory address */
		io_write8(base + I2C_TXDR, (request->mem_addr & 0xFF00U) >> 8);

		if (i2c_wait_txis(hi2c, timeout_ref))
			return -1;

		/* Send LSB of memory address */
		io_write8(base + I2C_TXDR, request->mem_addr & 0x00FFU);
	}

	if (wait_isr_event(hi2c, I2C_ISR_TC, 1, timeout_ref))
		return -1;

	return 0;
}

/*
 * Write an amount of data in blocking mode
 *
 * @hi2c: Reference to struct i2c_handle_s
 * @request: I2C request parameters
 * @p_data: Pointer to data buffer
 * @size: Amount of data to be sent
 * Return 0 on success or a negative value
 */
static int do_write(struct i2c_handle_s *hi2c, struct i2c_request *request,
		    uint8_t *p_data, uint16_t size)
{
	uint64_t timeout_ref = 0;
	vaddr_t base = get_base(hi2c);
	int rc = -1;
	uint8_t *p_buff = p_data;
	size_t xfer_size = 0;
	size_t xfer_count = size;

	if (request->mode != I2C_MODE_MASTER && request->mode != I2C_MODE_MEM)
		return -1;

	if (!p_data || !size)
		return -1;

	mutex_pm_aware_lock(&hi2c->mu);

	if (hi2c->i2c_state != I2C_STATE_READY) {
		mutex_pm_aware_unlock(&hi2c->mu);
		return -1;
	}

	clk_enable(hi2c->clock);

	timeout_ref = timeout_init_us(I2C_TIMEOUT_BUSY_MS * 1000);
	if (wait_isr_event(hi2c, I2C_ISR_BUSY, 0, timeout_ref))
		goto bail;

	hi2c->i2c_state = I2C_STATE_BUSY_TX;
	hi2c->i2c_err = I2C_ERROR_NONE;
	timeout_ref = timeout_init_us(request->timeout_ms * 1000);

	if (request->mode == I2C_MODE_MEM) {
		/* In memory mode, send slave address and memory address */
		if (i2c_request_mem_write(hi2c, request, timeout_ref))
			goto bail;

		if (xfer_count > MAX_NBYTE_SIZE) {
			xfer_size = MAX_NBYTE_SIZE;
			i2c_transfer_config(hi2c, request->dev_addr, xfer_size,
					    I2C_RELOAD_MODE, I2C_NO_STARTSTOP);
		} else {
			xfer_size = xfer_count;
			i2c_transfer_config(hi2c, request->dev_addr, xfer_size,
					    I2C_AUTOEND_MODE, I2C_NO_STARTSTOP);
		}
	} else {
		/* In master mode, send slave address */
		if (xfer_count > MAX_NBYTE_SIZE) {
			xfer_size = MAX_NBYTE_SIZE;
			i2c_transfer_config(hi2c, request->dev_addr, xfer_size,
					    I2C_RELOAD_MODE,
					    I2C_GENERATE_START_WRITE);
		} else {
			xfer_size = xfer_count;
			i2c_transfer_config(hi2c, request->dev_addr, xfer_size,
					    I2C_AUTOEND_MODE,
					    I2C_GENERATE_START_WRITE);
		}
	}

	do {
		if (i2c_wait_txis(hi2c, timeout_ref))
			goto bail;

		io_write8(base + I2C_TXDR, *p_buff);
		p_buff++;
		xfer_count--;
		xfer_size--;

		if (xfer_count && !xfer_size) {
			/* Wait until TCR flag is set */
			if (wait_isr_event(hi2c, I2C_ISR_TCR, 1, timeout_ref))
				goto bail;

			if (xfer_count > MAX_NBYTE_SIZE) {
				xfer_size = MAX_NBYTE_SIZE;
				i2c_transfer_config(hi2c, request->dev_addr,
						    xfer_size,
						    I2C_RELOAD_MODE,
						    I2C_NO_STARTSTOP);
			} else {
				xfer_size = xfer_count;
				i2c_transfer_config(hi2c, request->dev_addr,
						    xfer_size,
						    I2C_AUTOEND_MODE,
						    I2C_NO_STARTSTOP);
			}
		}

	} while (xfer_count > 0U);

	/*
	 * No need to Check TC flag, with AUTOEND mode the stop
	 * is automatically generated.
	 * Wait until STOPF flag is reset.
	 */
	if (i2c_wait_stop(hi2c, timeout_ref))
		goto bail;

	io_write32(base + I2C_ICR, I2C_ISR_STOPF);

	io_clrbits32(base + I2C_CR2, CR2_RESET_MASK);

	hi2c->i2c_state = I2C_STATE_READY;

	rc = 0;

bail:
	clk_disable(hi2c->clock);
	mutex_pm_aware_unlock(&hi2c->mu);

	return rc;
}

int stm32_i2c_mem_write(struct i2c_handle_s *hi2c, uint32_t dev_addr,
			uint32_t mem_addr, uint32_t mem_addr_size,
			uint8_t *p_data, size_t size, unsigned int timeout_ms)
{
	struct i2c_request request = {
		.dev_addr = dev_addr,
		.mode = I2C_MODE_MEM,
		.mem_addr = mem_addr,
		.mem_addr_size = mem_addr_size,
		.timeout_ms = timeout_ms,
	};

	return do_write(hi2c, &request, p_data, size);
}

int stm32_i2c_master_transmit(struct i2c_handle_s *hi2c, uint32_t dev_addr,
			      uint8_t *p_data, size_t size,
			      unsigned int timeout_ms)
{
	struct i2c_request request = {
		.dev_addr = dev_addr,
		.mode = I2C_MODE_MASTER,
		.timeout_ms = timeout_ms,
	};

	return do_write(hi2c, &request, p_data, size);
}

int stm32_i2c_read_write_membyte(struct i2c_handle_s *hi2c, uint16_t dev_addr,
				 unsigned int mem_addr, uint8_t *p_data,
				 bool write)
{
	uint64_t timeout_ref = 0;
	uintptr_t base = get_base(hi2c);
	int rc = -1;
	uint8_t *p_buff = p_data;
	uint32_t event_mask = 0;

	mutex_pm_aware_lock(&hi2c->mu);

	if (hi2c->i2c_state != I2C_STATE_READY || !p_data) {
		mutex_pm_aware_unlock(&hi2c->mu);
		return -1;
	}

	clk_enable(hi2c->clock);

	timeout_ref = timeout_init_us(I2C_TIMEOUT_BUSY_US);
	if (wait_isr_event(hi2c, I2C_ISR_BUSY, 0, timeout_ref))
		goto bail;

	hi2c->i2c_state = write ? I2C_STATE_BUSY_TX : I2C_STATE_BUSY_RX;
	hi2c->i2c_err = I2C_ERROR_NONE;

	i2c_transfer_config(hi2c, dev_addr, I2C_MEMADD_SIZE_8BIT,
			    write ? I2C_RELOAD_MODE : I2C_SOFTEND_MODE,
			    I2C_GENERATE_START_WRITE);

	timeout_ref = timeout_init_us(I2C_TIMEOUT_BUSY_US);
	if (i2c_wait_txis(hi2c, timeout_ref))
		goto bail;

	io_write8(base + I2C_TXDR, mem_addr);

	if (write)
		event_mask = I2C_ISR_TCR;
	else
		event_mask = I2C_ISR_TC;

	timeout_ref = timeout_init_us(I2C_TIMEOUT_BUSY_US);
	if (wait_isr_event(hi2c, event_mask, 1, timeout_ref))
		goto bail;

	i2c_transfer_config(hi2c, dev_addr, I2C_MEMADD_SIZE_8BIT,
			    I2C_AUTOEND_MODE,
			    write ? I2C_NO_STARTSTOP : I2C_GENERATE_START_READ);

	timeout_ref = timeout_init_us(I2C_TIMEOUT_BUSY_US);
	if (write) {
		if (i2c_wait_txis(hi2c, timeout_ref))
			goto bail;

		io_write8(base + I2C_TXDR, *p_buff);
	} else {
		if (wait_isr_event(hi2c, I2C_ISR_RXNE, 1, timeout_ref))
			goto bail;

		*p_buff = io_read8(base + I2C_RXDR);
	}

	timeout_ref = timeout_init_us(I2C_TIMEOUT_BUSY_US);
	if (i2c_wait_stop(hi2c, timeout_ref))
		goto bail;

	io_write32(base + I2C_ICR, I2C_ISR_STOPF);
	io_clrbits32(base + I2C_CR2, CR2_RESET_MASK);

	hi2c->i2c_state = I2C_STATE_READY;

	rc = 0;

bail:
	clk_disable(hi2c->clock);
	mutex_pm_aware_unlock(&hi2c->mu);

	return rc;
}

/*
 * Read an amount of data in blocking mode
 *
 * @hi2c: Reference to struct i2c_handle_s
 * @request: I2C request parameters
 * @p_data: Pointer to data buffer
 * @size: Amount of data to be sent
 * Return 0 on success or a negative value
 */
static int do_read(struct i2c_handle_s *hi2c, struct i2c_request *request,
		   uint8_t *p_data, uint32_t size)
{
	vaddr_t base = get_base(hi2c);
	uint64_t timeout_ref = 0;
	int rc = -1;
	uint8_t *p_buff = p_data;
	size_t xfer_count = size;
	size_t xfer_size = 0;

	if (request->mode != I2C_MODE_MASTER && request->mode != I2C_MODE_MEM)
		return -1;

	if (!p_data || !size)
		return -1;

	mutex_pm_aware_lock(&hi2c->mu);

	if (hi2c->i2c_state != I2C_STATE_READY) {
		mutex_pm_aware_unlock(&hi2c->mu);
		return -1;
	}

	clk_enable(hi2c->clock);

	timeout_ref = timeout_init_us(I2C_TIMEOUT_BUSY_MS * 1000);
	if (wait_isr_event(hi2c, I2C_ISR_BUSY, 0, timeout_ref))
		goto bail;

	hi2c->i2c_state = I2C_STATE_BUSY_RX;
	hi2c->i2c_err = I2C_ERROR_NONE;
	timeout_ref = timeout_init_us(request->timeout_ms * 1000);

	if (request->mode == I2C_MODE_MEM) {
		/* Send memory address */
		if (i2c_request_mem_read(hi2c, request, timeout_ref))
			goto bail;
	}

	/*
	 * Send slave address.
	 * Set NBYTES to write and reload if xfer_count > MAX_NBYTE_SIZE
	 * and generate RESTART.
	 */
	if (xfer_count > MAX_NBYTE_SIZE) {
		xfer_size = MAX_NBYTE_SIZE;
		i2c_transfer_config(hi2c, request->dev_addr, xfer_size,
				    I2C_RELOAD_MODE, I2C_GENERATE_START_READ);
	} else {
		xfer_size = xfer_count;
		i2c_transfer_config(hi2c, request->dev_addr, xfer_size,
				    I2C_AUTOEND_MODE, I2C_GENERATE_START_READ);
	}

	do {
		if (wait_isr_event(hi2c, I2C_ISR_RXNE, 1,
				   timeout_init_us(I2C_TIMEOUT_RXNE_MS * 1000)))
			goto bail;

		*p_buff = io_read8(base + I2C_RXDR);
		p_buff++;
		xfer_size--;
		xfer_count--;

		if (xfer_count && !xfer_size) {
			if (wait_isr_event(hi2c, I2C_ISR_TCR, 1, timeout_ref))
				goto bail;

			if (xfer_count > MAX_NBYTE_SIZE) {
				xfer_size = MAX_NBYTE_SIZE;
				i2c_transfer_config(hi2c, request->dev_addr,
						    xfer_size,
						    I2C_RELOAD_MODE,
						    I2C_NO_STARTSTOP);
			} else {
				xfer_size = xfer_count;
				i2c_transfer_config(hi2c, request->dev_addr,
						    xfer_size,
						    I2C_AUTOEND_MODE,
						    I2C_NO_STARTSTOP);
			}
		}
	} while (xfer_count > 0U);

	/*
	 * No need to Check TC flag, with AUTOEND mode the stop
	 * is automatically generated.
	 * Wait until STOPF flag is reset.
	 */
	if (i2c_wait_stop(hi2c, timeout_ref))
		goto bail;

	/* Clear the NACK generated at the end of the transfer */
	if ((io_read32(get_base(hi2c) + I2C_ISR) & I2C_ISR_NACKF))
		io_write32(get_base(hi2c) + I2C_ICR, I2C_ICR_NACKCF);

	io_write32(base + I2C_ICR, I2C_ISR_STOPF);

	io_clrbits32(base + I2C_CR2, CR2_RESET_MASK);

	hi2c->i2c_state = I2C_STATE_READY;

	rc = 0;

bail:
	clk_disable(hi2c->clock);
	mutex_pm_aware_unlock(&hi2c->mu);

	return rc;
}

int stm32_i2c_mem_read(struct i2c_handle_s *hi2c, uint32_t dev_addr,
		       uint32_t mem_addr, uint32_t mem_addr_size,
		       uint8_t *p_data, size_t size, unsigned int timeout_ms)
{
	struct i2c_request request = {
		.dev_addr = dev_addr,
		.mode = I2C_MODE_MEM,
		.mem_addr = mem_addr,
		.mem_addr_size = mem_addr_size,
		.timeout_ms = timeout_ms,
	};

	return do_read(hi2c, &request, p_data, size);
}

int stm32_i2c_master_receive(struct i2c_handle_s *hi2c, uint32_t dev_addr,
			     uint8_t *p_data, size_t size,
			     unsigned int timeout_ms)
{
	struct i2c_request request = {
		.dev_addr = dev_addr,
		.mode = I2C_MODE_MASTER,
		.timeout_ms = timeout_ms,
	};

	return do_read(hi2c, &request, p_data, size);
}

static struct i2c_handle_s *stm32_i2c_dev_to_handle(struct i2c_dev *i2c_dev)
{
	struct stm32_i2c_dev *dev = container_of(i2c_dev, struct stm32_i2c_dev,
						 i2c_dev);

	return dev->handle;
}

static TEE_Result stm32_i2c_read_data(struct i2c_dev *i2c_dev, uint8_t *buf,
				      size_t len)
{
	struct i2c_handle_s *i2c_handle = stm32_i2c_dev_to_handle(i2c_dev);
	int rc = 0;

	rc = stm32_i2c_master_receive(i2c_handle, i2c_dev->addr, buf, len,
				      I2C_TIMEOUT_DEFAULT_MS);
	if (!rc)
		return TEE_SUCCESS;
	else
		return TEE_ERROR_GENERIC;
}

static TEE_Result stm32_i2c_write_data(struct i2c_dev *i2c_dev,
				       const uint8_t *buf, size_t len)
{
	struct i2c_handle_s *i2c_handle = stm32_i2c_dev_to_handle(i2c_dev);
	uint8_t *buf2 = (uint8_t *)buf;
	int rc = 0;

	rc = stm32_i2c_master_transmit(i2c_handle, i2c_dev->addr, buf2, len,
				       I2C_TIMEOUT_DEFAULT_MS);
	if (!rc)
		return TEE_SUCCESS;
	else
		return TEE_ERROR_GENERIC;
}

static const struct i2c_ctrl_ops stm32_i2c_ops = {
	.read = stm32_i2c_read_data,
	.write = stm32_i2c_write_data,
};

bool stm32_i2c_is_device_ready(struct i2c_handle_s *hi2c, uint32_t dev_addr,
			       unsigned int trials, unsigned int timeout_ms)
{
	vaddr_t base = get_base(hi2c);
	unsigned int i2c_trials = 0U;
	bool rc = false;

	mutex_pm_aware_lock(&hi2c->mu);

	if (hi2c->i2c_state != I2C_STATE_READY) {
		mutex_pm_aware_unlock(&hi2c->mu);
		return rc;
	}

	clk_enable(hi2c->clock);

	if (io_read32(base + I2C_ISR) & I2C_ISR_BUSY)
		goto bail;

	hi2c->i2c_state = I2C_STATE_BUSY;
	hi2c->i2c_err = I2C_ERROR_NONE;

	do {
		uint64_t timeout_ref = 0;
		vaddr_t isr = base + I2C_ISR;

		/* Generate Start */
		if ((io_read32(base + I2C_OAR1) & I2C_OAR1_OA1MODE) == 0)
			io_write32(base + I2C_CR2,
				   ((dev_addr & I2C_CR2_SADD) |
				    I2C_CR2_START | I2C_CR2_AUTOEND) &
				   ~I2C_CR2_RD_WRN);
		else
			io_write32(base + I2C_CR2,
				   ((dev_addr & I2C_CR2_SADD) |
				    I2C_CR2_START | I2C_CR2_ADD10) &
				   ~I2C_CR2_RD_WRN);

		/*
		 * No need to Check TC flag, with AUTOEND mode the stop
		 * is automatically generated.
		 * Wait until STOPF flag is set or a NACK flag is set.
		 */
		timeout_ref = timeout_init_us(timeout_ms * 1000);
		while (!timeout_elapsed(timeout_ref))
			if (io_read32(isr) & (I2C_ISR_STOPF | I2C_ISR_NACKF))
				break;

		if ((io_read32(isr) & (I2C_ISR_STOPF | I2C_ISR_NACKF)) == 0) {
			notif_i2c_timeout(hi2c);
			goto bail;
		}

		if ((io_read32(base + I2C_ISR) & I2C_ISR_NACKF) == 0U) {
			if (wait_isr_event(hi2c, I2C_ISR_STOPF, 1, timeout_ref))
				goto bail;

			io_write32(base + I2C_ICR, I2C_ISR_STOPF);

			hi2c->i2c_state = I2C_STATE_READY;

			rc = true;
			goto bail;
		}

		if (wait_isr_event(hi2c, I2C_ISR_STOPF, 1, timeout_ref))
			goto bail;

		io_write32(base + I2C_ICR, I2C_ISR_NACKF);
		io_write32(base + I2C_ICR, I2C_ISR_STOPF);

		if (i2c_trials == trials) {
			io_setbits32(base + I2C_CR2, I2C_CR2_STOP);

			if (wait_isr_event(hi2c, I2C_ISR_STOPF, 1, timeout_ref))
				goto bail;

			io_write32(base + I2C_ICR, I2C_ISR_STOPF);
		}

		i2c_trials++;
	} while (i2c_trials < trials);

	notif_i2c_timeout(hi2c);

bail:
	clk_disable(hi2c->clock);
	mutex_pm_aware_unlock(&hi2c->mu);

	return rc;
}

void stm32_i2c_resume(struct i2c_handle_s *hi2c)
{
	if (hi2c->i2c_state == I2C_STATE_READY)
		return;

	if ((hi2c->i2c_state != I2C_STATE_RESET) &&
	    (hi2c->i2c_state != I2C_STATE_SUSPENDED))
		panic();

	if (pinctrl_apply_state(hi2c->pinctrl))
		panic();

	if (hi2c->i2c_state == I2C_STATE_RESET) {
		/* There is no valid I2C configuration to be loaded yet */
		return;
	}

	restore_cfg(hi2c, &hi2c->sec_cfg);

	if (IS_ENABLED(CFG_STM32MP13))
		stm32_pinctrl_set_secure_cfg(hi2c->pinctrl, true);

	hi2c->i2c_state = I2C_STATE_READY;
}

void stm32_i2c_suspend(struct i2c_handle_s *hi2c)
{
	if (hi2c->i2c_state == I2C_STATE_SUSPENDED)
		return;

	if (hi2c->i2c_state != I2C_STATE_READY)
		panic();

	save_cfg(hi2c, &hi2c->sec_cfg);

	if (hi2c->pinctrl_sleep && pinctrl_apply_state(hi2c->pinctrl_sleep))
		panic();

	hi2c->i2c_state = I2C_STATE_SUSPENDED;
}

static TEE_Result stm32_get_i2c_dev(struct dt_pargs *args, void *data,
				    struct i2c_dev **out_device)
{
	struct stm32_i2c_dev *stm32_i2c_dev = NULL;
	paddr_t addr = 0;

	addr = fdt_reg_base_address(args->fdt, args->phandle_node);
	if (addr == DT_INFO_INVALID_REG) {
		DMSG("Can't get device I2C address");
		return TEE_ERROR_GENERIC;
	}

	stm32_i2c_dev = calloc(1, sizeof(*stm32_i2c_dev));
	if (!stm32_i2c_dev)
		return TEE_ERROR_OUT_OF_MEMORY;

	stm32_i2c_dev->handle = data;
	stm32_i2c_dev->i2c_dev.addr = addr;
	stm32_i2c_dev->i2c_ctrl.ops = &stm32_i2c_ops;
	stm32_i2c_dev->i2c_dev.ctrl = &stm32_i2c_dev->i2c_ctrl;

	*out_device = &stm32_i2c_dev->i2c_dev;

	return TEE_SUCCESS;
}

static TEE_Result stm32_i2c_probe(const void *fdt, int node,
				  const void *compat_data __unused)
{
	TEE_Result res = TEE_SUCCESS;
	int subnode = 0;
	struct i2c_handle_s *i2c_handle_p = NULL;
	struct stm32_i2c_init_s init_data = { };
	struct pinctrl_state *pinctrl_active = NULL;
	struct pinctrl_state *pinctrl_idle = NULL;

	res = stm32_i2c_get_setup_from_fdt((void *)fdt, node, &init_data,
					   &pinctrl_active, &pinctrl_idle);
	if (res)
		return res;

	i2c_handle_p = calloc(1, sizeof(struct i2c_handle_s));
	if (!i2c_handle_p)
		return TEE_ERROR_OUT_OF_MEMORY;

	i2c_handle_p->dt_status = init_data.dt_status;
	i2c_handle_p->reg_size = init_data.reg_size;
	i2c_handle_p->clock = init_data.clock;
	i2c_handle_p->base.pa = init_data.pbase;
	i2c_handle_p->base.va = io_pa_or_va(&i2c_handle_p->base,
					    init_data.reg_size);
	assert(i2c_handle_p->base.va);
	i2c_handle_p->clock = init_data.clock;
	i2c_handle_p->i2c_state = I2C_STATE_RESET;
	i2c_handle_p->pinctrl = pinctrl_active;
	i2c_handle_p->pinctrl_sleep = pinctrl_idle;

	init_data.analog_filter = true;
	init_data.digital_filter_coef = 0;

	if (stm32_i2c_init(i2c_handle_p, &init_data))
		panic("Couldn't initialise I2C");

	res = i2c_register_provider(fdt, node, stm32_get_i2c_dev, i2c_handle_p);
	if (res)
		panic("Couldn't register I2C provider");

	fdt_for_each_subnode(subnode, fdt, node) {
		res = dt_driver_maybe_add_probe_node(fdt, subnode);
		if (res) {
			EMSG("Failed on node %s with %#"PRIx32,
			     fdt_get_name(fdt, subnode, NULL), res);
			panic();
		}
	}

	return res;
}

static const struct dt_device_match stm32_i2c_match_table[] = {
	{ .compatible = "st,stm32mp15-i2c" },
	{ .compatible = "st,stm32mp13-i2c" },
	{ .compatible = "st,stm32mp15-i2c-non-secure" },
	{ }
};

DEFINE_DT_DRIVER(stm32_i2c_dt_driver) = {
	.name = "stm32_i2c",
	.match_table = stm32_i2c_match_table,
	.probe = stm32_i2c_probe,
	.type = DT_DRIVER_I2C
};
