/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef DRIVERS_QCOM_GENI_SPI_H
#define DRIVERS_QCOM_GENI_SPI_H

#include <kernel/mutex.h>
#include <mm/core_memprot.h>
#include <spi.h>
#include <types_ext.h>

struct clk;
struct tlmm_pin_group;
struct pinctrl_state;

/* Wrapper/common clocks per SE: core_2x, core, s_ahb, m_ahb */
#define QUP_SPI_MAX_COMMON_CLKS		4

/* Register window size mapped for each GENI SPI SE. */
#define QUP_SPI_REG_SIZE		0x4000

/* Register window size mapped for the QUPv3 wrapper-common region. */
#define QUP_SPI_COMMON_REG_SIZE		0x1000

struct qup_spi_data {
	struct spi_chip chip;
	vaddr_t base;
	/* QUPv3 wrapper-common register region for this SE's wrapper */
	vaddr_t common_base;
	/* Stable identifier for the SE this instance is bound to */
	unsigned int id;
	/* SE source ("se") clock rate in Hz, fixed by the platform */
	unsigned int clk_hz;
	/* SE source ("se") clock name, used to acquire se_clk */
	const char *se_clock_name;
	/* SE source clock handle, acquired by qup_spi_init() */
	struct clk *se_clk;
	/* NULL-terminated array of wrapper/common clock names */
	const char **common_clocks_name;
	/* Resolved wrapper/common clock handles, acquired by qup_spi_init() */
	struct clk *common_clks[QUP_SPI_MAX_COMMON_CLKS];
	/* Number of entries populated in common_clks[] */
	unsigned int num_common_clks;
	/*
	 * TLMM pin groups for this SE's pads, from the platform cfg. The
	 * resolved pinctrl state is built and applied by start(), then
	 * released by end().
	 */
	const struct tlmm_pin_group *pin_groups;
	unsigned int pin_group_count;
	struct pinctrl_state *pin_state;
	/*
	 * GENI SE firmware image for this SE, from the platform cfg. NULL if
	 * this SE does not need firmware loading (e.g. already loaded by an
	 * earlier boot stage on every boot path).
	 */
	const uint8_t *fw_image;
	size_t fw_image_size;
	/* Set once qup_spi_init() has loaded (or found already-loaded) the
	 * GENI SE firmware; gates re-running the load on repeat init calls.
	 */
	bool fw_loaded;
	/* Requested SPI bus clock in Hz, set before calling configure() */
	unsigned int speed_hz;
	enum spi_mode mode;
	/* Which of the SE's demuxed CS lines (0-3) to drive */
	unsigned int cs;
	/* True if the target's CS input is active-high */
	bool cs_high;
	bool loopback;
	/* SPI word size in bits; txrx8()/txrx16() support 8 or 16 */
	unsigned int bits_per_word;
	/* Cached from SE_HW_PARAM_0/SE_HW_PARAM_1 by configure() */
	unsigned int tx_fifo_depth;
	unsigned int rx_fifo_depth;
	unsigned int fifo_width_bits;

	/* SE interrupt number, filled in by qup_spi_get_platform_data() */
	size_t itr_num;

	/*
	 * Internal driver state. Not to be touched by callers.
	 */
	/*
	 * Serialises the transfer state below between callers. A mutex rather
	 * than a spinlock: this driver is polling-mode, so every access is from
	 * a thread context (there is no interrupt handler to lock against), and
	 * the critical sections must not disable interrupts for the duration.
	 */
	struct mutex lock;
	/* Set on a fully-successful configure(); gates start()/txrx(). */
	bool configured;
	/* Set on a fully-successful start(); gates txrx()/end(). */
	bool started;
	const uint8_t *tx_buf;
	uint8_t *rx_buf;
	size_t tx_rem_bytes;
	size_t rx_rem_bytes;
	unsigned int bytes_per_word;
};

/*
 * Implemented by platform code: fills in base, itr_num, clk_hz (and
 * any other platform-fixed field) in *qs for the given SE id.
 * Returns false if qup_spi_id was not enabled in this build.
 */
bool qup_spi_get_platform_data(unsigned int qup_spi_id,
				struct qup_spi_data *qs);

/*
 * Initializes *qs for the SE identified by qup_spi_id, loading its GENI
 * firmware if needed. Caller-owned fields (cs, mode, speed_hz,
 * bits_per_word, loopback) should be set either before or after this
 * call, but before the first configure()/start()/txrx call.
 */
TEE_Result qup_spi_init(struct qup_spi_data *qs, unsigned int qup_spi_id);

/*
 * Enable or disable internal digital loopback (TX pad looped back to RX)
 * for the SE. Intended for bring-up/self-test, where MOSI is fed back to
 * MISO inside the SE without an external device. Takes effect on the next
 * configure(); call before configure()/start()/txrx.
 */
void qup_spi_set_loopback(struct qup_spi_data *qs, bool enable);

/*
 * Per-SE hardware descriptor. Defined per platform in
 * qcom_geni_spi_config.c; qup_spi_config[] below is the resulting
 * table qup_spi_get_platform_data() looks up by id.
 */
struct qup_spi_platform_cfg {
	unsigned int id;
	paddr_t base;
	/* QUPv3 wrapper-common region physical base for this SE's wrapper */
	paddr_t common_base;
	size_t itr_num;
	unsigned int clk_hz;
	const char *se_clock_name;
	const char **common_clocks_name;
	/*
	 * TLMM pin groups muxing this SE's MISO/MOSI/CLK/CS pads to the
	 * SPI function. Pins that share one config are one group; pins that
	 * differ in any field (e.g. CLK needs no pull) are a separate group.
	 * NULL/0 if the platform sets up pinmux elsewhere.
	 */
	const struct tlmm_pin_group *pin_groups;
	unsigned int pin_group_count;
	/*
	 * GENI SE firmware image to load into this SE, and its size in
	 * bytes. NULL/0 if this SE does not need firmware loading.
	 */
	const uint8_t *fw_image;
	size_t fw_image_size;
};

/* SoC-specific hardware descriptor, defined per platform in qcom_geni_spi_config.c */
extern const struct qup_spi_platform_cfg qup_spi_config[];

extern const size_t qup_spi_config_count;
#endif /* DRIVERS_QCOM_GENI_SPI_H */
