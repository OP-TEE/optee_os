// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016, Linaro Limited
 *
 */

#include <assert.h>
#include <drivers/pl022_spi.h>
#include <initcall.h>
#include <io.h>
#include <keep.h>
#include <kernel/panic.h>
#include <kernel/tee_time.h>
#include <platform_config.h>
#include <trace.h>
#include <util.h>

/* SPI register offsets */
#define SSPCR0		0x000
#define SSPCR1		0x004
#define SSPDR		0x008
#define SSPSR		0x00C
#define SSPCPSR		0x010
#define SSPIMSC		0x014
#define SSPRIS		0x018
#define SSPMIS		0x01C
#define SSPICR		0x020
#define SSPDMACR	0x024

#ifdef PLATFORM_hikey
/* HiKey extensions */
#define SSPTXFIFOCR	0x028
#define SSPRXFIFOCR	0x02C
#define SSPB2BTRANS	0x030
#endif

/* test registers */
#define SSPTCR		0x080
#define SSPITIP		0x084
#define SSPITOP		0x088
#define SSPTDR		0x08C

#define SSPPeriphID0	0xFE0
#define SSPPeriphID1	0xFE4
#define SSPPeriphID2	0xFE8
#define SSPPeriphID3	0xFEC

#define SSPPCellID0	0xFF0
#define SSPPCellID1	0xFF4
#define SSPPCellID2	0xFF8
#define SSPPCellID3	0xFFC

/* SPI register masks */
#define SSPCR0_SCR		SHIFT_U32(0xFF, 8)
#define SSPCR0_SPH		SHIFT_U32(1, 7)
#define SSPCR0_SPH1		SHIFT_U32(1, 7)
#define SSPCR0_SPH0		SHIFT_U32(0, 7)
#define SSPCR0_SPO		SHIFT_U32(1, 6)
#define SSPCR0_SPO1		SHIFT_U32(1, 6)
#define SSPCR0_SPO0		SHIFT_U32(0, 6)
#define SSPCR0_FRF		SHIFT_U32(3, 4)
#define SSPCR0_FRF_SPI		SHIFT_U32(0, 4)
#define SSPCR0_DSS		SHIFT_U32(0xFF, 0)
#define SSPCR0_DSS_16BIT	SHIFT_U32(0xF, 0)
#define SSPCR0_DSS_8BIT		SHIFT_U32(7, 0)

#define SSPCR1_SOD		SHIFT_U32(1, 3)
#define SSPCR1_SOD_ENABLE	SHIFT_U32(1, 3)
#define SSPCR1_SOD_DISABLE	SHIFT_U32(0, 3)
#define SSPCR1_MS		SHIFT_U32(1, 2)
#define SSPCR1_MS_SLAVE		SHIFT_U32(1, 2)
#define SSPCR1_MS_MASTER	SHIFT_U32(0, 2)
#define SSPCR1_SSE		SHIFT_U32(1, 1)
#define SSPCR1_SSE_ENABLE	SHIFT_U32(1, 1)
#define SSPCR1_SSE_DISABLE	SHIFT_U32(0, 1)
#define SSPCR1_LBM		SHIFT_U32(1, 0)
#define SSPCR1_LBM_YES		SHIFT_U32(1, 0)
#define SSPCR1_LBM_NO		SHIFT_U32(0, 0)

#define SSPDR_DATA	SHIFT_U32(0xFFFF, 0)

#define SSPSR_BSY	SHIFT_U32(1, 4)
#define SSPSR_RNF	SHIFT_U32(1, 3)
#define SSPSR_RNE	SHIFT_U32(1, 2)
#define SSPSR_TNF	SHIFT_U32(1, 1)
#define SSPSR_TFE	SHIFT_U32(1, 0)

#define SSPCPSR_CPSDVR	SHIFT_U32(0xFF, 0)

#define SSPIMSC_TXIM	SHIFT_U32(1, 3)
#define SSPIMSC_RXIM	SHIFT_U32(1, 2)
#define SSPIMSC_RTIM	SHIFT_U32(1, 1)
#define SSPIMSC_RORIM	SHIFT_U32(1, 0)

#define SSPRIS_TXRIS	SHIFT_U32(1, 3)
#define SSPRIS_RXRIS	SHIFT_U32(1, 2)
#define SSPRIS_RTRIS	SHIFT_U32(1, 1)
#define SSPRIS_RORRIS	SHIFT_U32(1, 0)

#define SSPMIS_TXMIS	SHIFT_U32(1, 3)
#define SSPMIS_RXMIS	SHIFT_U32(1, 2)
#define SSPMIS_RTMIS	SHIFT_U32(1, 1)
#define SSPMIS_RORMIS	SHIFT_U32(1, 0)

#define SSPICR_RTIC		SHIFT_U32(1, 1)
#define SSPICR_RORIC		SHIFT_U32(1, 0)

#define SSPDMACR_TXDMAE	SHIFT_U32(1, 1)
#define SSPDMACR_RXDMAE	SHIFT_U32(1, 0)

#define SSPPeriphID0_PartNumber0	SHIFT_U32(0xFF, 0) /* 0x22 */
#define SSPPeriphID1_Designer0		SHIFT_U32(0xF, 4) /* 0x1 */
#define SSPPeriphID1_PartNumber1	SHIFT_U32(0xF, 0) /* 0x0 */
#define SSPPeriphID2_Revision		SHIFT_U32(0xF, 4)
#define SSPPeriphID2_Designer1		SHIFT_U32(0xF, 0) /* 0x4 */
#define SSPPeriphID3_Configuration	SHIFT_U32(0xFF, 0) /* 0x00 */

#define SSPPCellID_0	SHIFT_U32(0xFF, 0) /* 0x0D */
#define SSPPCellID_1	SHIFT_U32(0xFF, 0) /* 0xF0 */
#define SSPPPCellID_2	SHIFT_U32(0xFF, 0) /* 0x05 */
#define SSPPPCellID_3	SHIFT_U32(0xFF, 0) /* 0xB1 */

#define MASK_32 0xFFFFFFFF
#define MASK_28 0xFFFFFFF
#define MASK_24 0xFFFFFF
#define MASK_20 0xFFFFF
#define MASK_16 0xFFFF
#define MASK_12 0xFFF
#define MASK_8 0xFF
#define MASK_4 0xF
/* SPI register masks */

#define SSP_CPSDVR_MAX		254
#define SSP_CPSDVR_MIN		2
#define SSP_SCR_MAX		255
#define SSP_SCR_MIN		0
#define SSP_DATASIZE_MAX	16

static enum spi_result pl022_txrx8(struct spi_chip *chip, uint8_t *wdat,
	uint8_t *rdat, size_t num_pkts)
{
	size_t i = 0;
	size_t j = 0;
	struct pl022_data *pd = container_of(chip, struct pl022_data, chip);


	if (pd->data_size_bits != 8) {
		EMSG("data_size_bits should be 8, not %u",
			pd->data_size_bits);
		return SPI_ERR_CFG;
	}

	if (wdat)
		while (i < num_pkts) {
			if (io_read8(pd->base + SSPSR) & SSPSR_TNF) {
				/* tx 1 packet */
				io_write8(pd->base + SSPDR, wdat[i++]);
			}

			if (rdat)
				if (io_read8(pd->base + SSPSR) & SSPSR_RNE) {
					/* rx 1 packet */
					rdat[j++] = io_read8(pd->base + SSPDR);
				}
		}

	/* Capture remaining rdat not read above */
	if (rdat) {
		while ((j < num_pkts) &&
		       (io_read8(pd->base + SSPSR) & SSPSR_RNE)) {
			/* rx 1 packet */
			rdat[j++] = io_read8(pd->base + SSPDR);
		}

		if (j < num_pkts) {
			EMSG("Packets requested %zu, received %zu",
				num_pkts, j);
			return SPI_ERR_PKTCNT;
		}
	}

	return SPI_OK;
}

static enum spi_result pl022_txrx16(struct spi_chip *chip, uint16_t *wdat,
	uint16_t *rdat, size_t num_pkts)
{
	size_t i = 0;
	size_t j = 0;
	struct pl022_data *pd = container_of(chip, struct pl022_data, chip);

	if (pd->data_size_bits != 16) {
		EMSG("data_size_bits should be 16, not %u",
			pd->data_size_bits);
		return SPI_ERR_CFG;
	}

	if (wdat)
		while (i < num_pkts) {
			if (io_read8(pd->base + SSPSR) & SSPSR_TNF) {
				/* tx 1 packet */
				io_write16(pd->base + SSPDR, wdat[i++]);
			}

			if (rdat)
				if (io_read8(pd->base + SSPSR) & SSPSR_RNE) {
					/* rx 1 packet */
					rdat[j++] = io_read16(pd->base + SSPDR);
				}
		}

	/* Capture remaining rdat not read above */
	if (rdat) {
		while ((j < num_pkts) &&
		       (io_read8(pd->base + SSPSR) & SSPSR_RNE)) {
			/* rx 1 packet */
			rdat[j++] = io_read16(pd->base + SSPDR);
		}

		if (j < num_pkts) {
			EMSG("Packets requested %zu, received %zu",
				num_pkts, j);
			return SPI_ERR_PKTCNT;
		}
	}

	return SPI_OK;
}

static void pl022_print_peri_id(struct pl022_data *pd __maybe_unused)
{
	DMSG("Expected: 0x 22 10 ?4 00");
	DMSG("Read: 0x %02x %02x %02x %02x",
		io_read8(pd->base + SSPPeriphID0),
		io_read8(pd->base + SSPPeriphID1),
		io_read8(pd->base + SSPPeriphID2),
		io_read8(pd->base + SSPPeriphID3));
}

static void pl022_print_cell_id(struct pl022_data *pd __maybe_unused)
{
	DMSG("Expected: 0x 0d f0 05 b1");
	DMSG("Read: 0x %02x %02x %02x %02x",
		io_read8(pd->base + SSPPCellID0),
		io_read8(pd->base + SSPPCellID1),
		io_read8(pd->base + SSPPCellID2),
		io_read8(pd->base + SSPPCellID3));
}

static void pl022_sanity_check(struct pl022_data *pd)
{
	assert(pd);
	assert(pd->chip.ops);
	assert(pd->cs_control <= PL022_CS_CTRL_MANUAL);
	switch (pd->cs_control) {
	case PL022_CS_CTRL_AUTO_GPIO:
		assert(pd->cs_data.gpio_data.chip);
		assert(pd->cs_data.gpio_data.chip->ops);
		break;
	case PL022_CS_CTRL_CB:
		assert(pd->cs_data.cs_cb);
		break;
	default:
		break;
	}
	assert(pd->clk_hz);
	assert(pd->speed_hz && pd->speed_hz <= pd->clk_hz/2);
	assert(pd->mode <= SPI_MODE3);
	assert(pd->data_size_bits == 8 || pd->data_size_bits == 16);

	#ifdef PLATFORM_hikey
	DMSG("SSPB2BTRANS: Expected: 0x2. Read: 0x%x",
		io_read8(pd->base + SSPB2BTRANS));
	#endif
	pl022_print_peri_id(pd);
	pl022_print_cell_id(pd);
}

static inline uint32_t pl022_calc_freq(struct pl022_data *pd,
	uint8_t cpsdvr, uint8_t scr)
{
	return pd->clk_hz / (cpsdvr * (1 + scr));
}

static void pl022_control_cs(struct spi_chip *chip, enum gpio_level value)
{
	struct pl022_data *pd = container_of(chip, struct pl022_data, chip);

	switch (pd->cs_control) {
	case PL022_CS_CTRL_AUTO_GPIO:
		if (io_read8(pd->base + SSPSR) & SSPSR_BSY)
			DMSG("pl022 busy - do NOT set CS!");
		while (io_read8(pd->base + SSPSR) & SSPSR_BSY)
			;
		DMSG("pl022 done - set CS!");

		pd->cs_data.gpio_data.chip->ops->set_value(NULL,
			pd->cs_data.gpio_data.pin_num, value);
		break;
	case PL022_CS_CTRL_CB:
		pd->cs_data.cs_cb(value);
		break;
	default:
		break;
	}
}

static void pl022_calc_clk_divisors(struct pl022_data *pd,
	uint8_t *cpsdvr, uint8_t *scr)
{
	unsigned int freq1 = 0;
	unsigned int freq2 = 0;
	uint8_t tmp_cpsdvr1;
	uint8_t tmp_scr1;
	uint8_t tmp_cpsdvr2 = 0;
	uint8_t tmp_scr2 = 0;

	for (tmp_scr1 = SSP_SCR_MIN; tmp_scr1 < SSP_SCR_MAX; tmp_scr1++) {
		for (tmp_cpsdvr1 = SSP_CPSDVR_MIN; tmp_cpsdvr1 < SSP_CPSDVR_MAX;
			tmp_cpsdvr1++) {
			freq1 = pl022_calc_freq(pd, tmp_cpsdvr1, tmp_scr1);
			if (freq1 == pd->speed_hz)
				goto done;
			else if (freq1 < pd->speed_hz)
				goto stage2;
		}
	}

stage2:
	for (tmp_cpsdvr2 = SSP_CPSDVR_MIN; tmp_cpsdvr2 < SSP_CPSDVR_MAX;
		tmp_cpsdvr2++) {
		for (tmp_scr2 = SSP_SCR_MIN; tmp_scr2 < SSP_SCR_MAX;
			tmp_scr2++) {
			freq2 = pl022_calc_freq(pd, tmp_cpsdvr2, tmp_scr2);
			if (freq2 <= pd->speed_hz)
				goto done;
		}
	}

done:
	if (freq1 >= freq2) {
		*cpsdvr = tmp_cpsdvr1;
		*scr = tmp_scr1;
		DMSG("speed: requested: %u, closest1: %u",
			pd->speed_hz, freq1);
	} else {
		*cpsdvr = tmp_cpsdvr2;
		*scr = tmp_scr2;
		DMSG("speed: requested: %u, closest2: %u",
			pd->speed_hz, freq2);
	}
	DMSG("CPSDVR: %u (0x%x), SCR: %u (0x%x)",
		*cpsdvr, *cpsdvr, *scr, *scr);
}

static void pl022_flush_fifo(struct spi_chip *chip)
{
	uint32_t __maybe_unused rdat;
	struct pl022_data *pd = container_of(chip, struct pl022_data, chip);
	do {
		while (io_read32(pd->base + SSPSR) & SSPSR_RNE) {
			rdat = io_read32(pd->base + SSPDR);
			DMSG("rdat: 0x%x", rdat);
		}
	} while (io_read32(pd->base + SSPSR) & SSPSR_BSY);
}

static void pl022_configure(struct spi_chip *chip)
{
	uint16_t mode;
	uint16_t data_size;
	uint8_t cpsdvr;
	uint8_t scr;
	uint8_t lbm;
	struct pl022_data *pd = container_of(chip, struct pl022_data, chip);

	pl022_sanity_check(pd);

	switch (pd->cs_control) {
	case PL022_CS_CTRL_AUTO_GPIO:
		DMSG("Use auto GPIO CS control");
		DMSG("Mask/disable interrupt for CS GPIO");
		pd->cs_data.gpio_data.chip->ops->set_interrupt(NULL,
			pd->cs_data.gpio_data.pin_num,
			GPIO_INTERRUPT_DISABLE);
		DMSG("Set CS GPIO dir to out");
		pd->cs_data.gpio_data.chip->ops->set_direction(NULL,
			pd->cs_data.gpio_data.pin_num,
			GPIO_DIR_OUT);
		break;
	case PL022_CS_CTRL_CB:
		DMSG("Use registered CS callback");
		break;
	case PL022_CS_CTRL_MANUAL:
		DMSG("Use manual CS control");
		break;
	default:
		EMSG("Invalid CS control type: %d", pd->cs_control);
		panic();
	}

	DMSG("Pull CS high");
	pl022_control_cs(chip, GPIO_LEVEL_HIGH);

	pl022_calc_clk_divisors(pd, &cpsdvr, &scr);

	/* configure ssp based on platform settings */
	switch (pd->mode) {
	case SPI_MODE0:
		DMSG("SPI mode 0");
		mode = SSPCR0_SPO0 | SSPCR0_SPH0;
		break;
	case SPI_MODE1:
		DMSG("SPI mode 1");
		mode = SSPCR0_SPO0 | SSPCR0_SPH1;
		break;
	case SPI_MODE2:
		DMSG("SPI mode 2");
		mode = SSPCR0_SPO1 | SSPCR0_SPH0;
		break;
	case SPI_MODE3:
		DMSG("SPI mode 3");
		mode = SSPCR0_SPO1 | SSPCR0_SPH1;
		break;
	default:
		EMSG("Invalid SPI mode: %u", pd->mode);
		panic();
	}

	switch (pd->data_size_bits) {
	case 8:
		DMSG("Data size: 8");
		data_size = SSPCR0_DSS_8BIT;
		break;
	case 16:
		DMSG("Data size: 16");
		data_size = SSPCR0_DSS_16BIT;
		break;
	default:
		EMSG("Unsupported data size: %u bits", pd->data_size_bits);
		panic();
	}

	if (pd->loopback) {
		DMSG("Starting in loopback mode!");
		lbm = SSPCR1_LBM_YES;
	} else {
		DMSG("Starting in regular (non-loopback) mode!");
		lbm = SSPCR1_LBM_NO;
	}

	DMSG("Set Serial Clock Rate (SCR), SPI mode (phase and clock)");
	DMSG("Set frame format (SPI) and data size (8- or 16-bit)");
	io_mask16(pd->base + SSPCR0, SHIFT_U32(scr, 8) | mode | SSPCR0_FRF_SPI |
		data_size, MASK_16);

	DMSG("Set master mode, disable SSP, set loopback mode");
	io_mask8(pd->base + SSPCR1, SSPCR1_SOD_DISABLE | SSPCR1_MS_MASTER |
		SSPCR1_SSE_DISABLE | lbm, MASK_4);

	DMSG("Set clock prescale");
	io_mask8(pd->base + SSPCPSR, cpsdvr, SSPCPSR_CPSDVR);

	DMSG("Disable interrupts");
	io_mask8(pd->base + SSPIMSC, 0, MASK_4);

	DMSG("Clear interrupts");
	io_mask8(pd->base + SSPICR, SSPICR_RORIC | SSPICR_RTIC,
		SSPICR_RORIC | SSPICR_RTIC);

	DMSG("Empty FIFO before starting");
	pl022_flush_fifo(chip);
}

static void pl022_start(struct spi_chip *chip)
{
	struct pl022_data *pd = container_of(chip, struct pl022_data, chip);

	DMSG("Enable SSP");
	io_mask8(pd->base + SSPCR1, SSPCR1_SSE_ENABLE, SSPCR1_SSE);

	pl022_control_cs(chip, GPIO_LEVEL_LOW);
}

static void pl022_end(struct spi_chip *chip)
{
	struct pl022_data *pd = container_of(chip, struct pl022_data, chip);

	pl022_control_cs(chip, GPIO_LEVEL_HIGH);

	DMSG("Disable SSP");
	io_mask8(pd->base + SSPCR1, SSPCR1_SSE_DISABLE, SSPCR1_SSE);
}

static const struct spi_ops pl022_ops = {
	.configure = pl022_configure,
	.start = pl022_start,
	.txrx8 = pl022_txrx8,
	.txrx16 = pl022_txrx16,
	.end = pl022_end,
	.flushfifo = pl022_flush_fifo,
};
DECLARE_KEEP_PAGER(pl022_ops);

void pl022_init(struct pl022_data *pd)
{
	assert(pd);
	pd->chip.ops = &pl022_ops;
}
