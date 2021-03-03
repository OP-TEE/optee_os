// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2021 NXP
 *
 * Driver for DSPI Controller
 *
 */

#include <assert.h>
#include <drivers/ls_dspi.h>
#include <io.h>
#include <kernel/boot.h>
#include <kernel/delay.h>
#include <kernel/dt.h>
#include <libfdt.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <util.h>

/* SPI register offset */
#define DSPI_MCR	0x0 /* Module Configuration Register */
#define DSPI_TCR	0x8 /* Transfer Count Register */
#define DSPI_CTAR0 \
	0xC /* Clock and Transfer Attributes Register (in Master mode) */
#define DSPI_CTAR1 \
	0x10 /* Clock and Transfer Attributes Register (in Master mode) */
#define DSPI_SR     0x2C  /* Status Register */
#define DSPI_RSER   0x30  /* DMA/Interrupt Request Select and Enable Register */
#define DSPI_PUSHR  0x34  /* PUSH TX FIFO Register In Master Mode */
#define DSPI_POPR   0x38  /* POP RX FIFO Register */
#define DSPI_TXFR0  0x3C  /* Transmit FIFO Registers */
#define DSPI_TXFR1  0x40  /* Transmit FIFO Registers */
#define DSPI_TXFR2  0x44  /* Transmit FIFO Registers */
#define DSPI_TXFR3  0x48  /* Transmit FIFO Registers */
#define DSPI_RXFR0  0x7C  /* Receive FIFO Registers */
#define DSPI_RXFR1  0x80  /* Receive FIFO Registers */
#define DSPI_RXFR2  0x84  /* Receive FIFO Registers */
#define DSPI_RXFR3  0x88  /* Receive FIFO Registers */
#define DSPI_CTARE0 0x11C /* Clock and Transfer Attributes Register Extended */
#define DSPI_CTARE1 0x120 /* Clock and Transfer Attributes Register Extended */
#define DSPI_SREX   0x13C /* Status Register Extended */

/* Module configuration */
#define DSPI_MCR_MSTR	0x80000000         /* Master/Slave Mode Select [0] */
#define DSPI_MCR_CSCK	0x40000000         /* Continuous SCK Enable [1] */
#define DSPI_MCR_DCONF(x) (((x) & 0x03) << 28) /* SPI Configuration [2-3] */
#define DSPI_MCR_ROOE	\
	0x01000000 /* Receive FIFO Overflow Overwrite Enable[7] */
#define DSPI_MCR_PCSIS(x) \
	(1 << (16 + (x))) /* Peripheral Chip Select x Inactive State [12-15] */
#define DSPI_MCR_PCSIS_MASK (0xff << 16)
#define DSPI_MCR_MDIS       0x00004000 /* Module Disable [17] */
#define DSPI_MCR_DTXF       0x00002000 /* Disable Transmit FIFO [18] */
#define DSPI_MCR_DRXF       0x00001000 /* Disable Receive FIFO [19] */
#define DSPI_MCR_CTXF       0x00000800 /* Clear TX FIFO [20] */
#define DSPI_MCR_CRXF       0x00000400 /* Clear RX FIFO [21] */
#define DPSI_XSPI           0x00000008 /* Extended SPI Mode [28] */
#define DSPI_MCR_PES        0x00000002 /* Parity Error Stop [30] */
#define DSPI_MCR_HALT       0x00000001 /* Halt [31] */
#define DPSI_ENABLE         0x0
#define DSPI_DISABLE        0x1

/* Transfer count */
#define DSPI_TCR_SPI_TCNT(x) (((x) & 0x0000FFFF) << 16)

/* Status */
#define DSPI_SR_TXRXS    0x40000000               /* TX and RX Status [1] */
#define DSPI_SR_TXCTR(x) \
	(((x) & 0x0000F000) >> 12) /* TX FIFO Counter [16-19] */
#define DSPI_SR_RXCTR(x) \
	(((x) & 0x000000F0) >> 4)  /* RX FIFO Counter [24-27] */

#define DSPI_DATA_8BIT  SHIFT_U32(8, 0)
#define DSPI_DATA_16BIT SHIFT_U32(0xF, 0)

#define DSPI_TFR_CONT    (0x80000000)
#define DSPI_TFR_CTAS(x) (((x) & 0x07) << 12)
#define DSPI_TFR_PCS(x)  (((1 << (x)) & 0x0000003f) << 16)
#define DSPI_IDLE_DATA   0x0

/* tx/rx data wait timeout value, unit: us */
#define DSPI_TXRX_WAIT_TIMEOUT 1000000

/* Transfer Fifo */
#define DSPI_TFR_TXDATA(x) (((x) & 0x0000FFFF))

/* Bit definitions and macros for DRFR */
#define DSPI_RFR_RXDATA(x) (((x) & 0x0000FFFF))

/* CTAR register pre-configure mask */
#define DSPI_CTAR_SET_MODE_MASK \
	(DSPI_CTAR_FMSZ(15) | DSPI_CTAR_PCS_SCK(3) | DSPI_CTAR_PA_SCK(3) | \
	 DSPI_CTAR_P_DT(3) | DSPI_CTAR_CS_SCK(15) | DSPI_CTAR_A_SCK(15) | \
	 DSPI_CTAR_A_DT(15))

/* SPI mode flags */
#define SPI_CPHA      BIT(0) /* clock phase */
#define SPI_CPOL      BIT(1) /* clock polarity */
#define SPI_CS_HIGH   BIT(2) /* CS active high */
#define SPI_LSB_FIRST BIT(3) /* per-word bits-on-wire */
#define SPI_CONT      BIT(4) /* Continuous CS mode */

/* default SCK frequency, unit: HZ */
#define PLATFORM_CLK          650000000
#define DSPI_DEFAULT_SCK_FREQ 10000000
#define DSPI_CLK_DIV          4 /* prescaler divisor */
#define DSPI_CLK              (PLATFORM_CLK / DSPI_CLK_DIV) /* DSPI clock */
#define CS_SPEED_MAX_HZ       1000000   /* Slave max speed */

/*
 * Calculate the divide scaler value between expected SCK frequency
 * and input clk frequency
 * req_pbr:	pre-scaler value of baud rate for slave
 * req_br:	scaler value of baud rate for slave
 * speed_hz:	speed value of slave
 * clkrate:	clock value of slave
 */
static TEE_Result dspi_convert_hz_to_baud(unsigned int *req_pbr,
					  unsigned int *req_br,
					  unsigned int speed_hz,
					  unsigned int clkrate)
{
	/* Valid pre-scaler values for baud rate*/
	static const unsigned int pbr_val[4] = { 2, 3, 5, 7 };
	/* Valid baud rate scaler values*/
	static const unsigned int brs_val[16] = { 2, 4, 6, 8,
						16, 32, 64, 128,
						256, 512, 1024, 2048,
						4096, 8192, 16384, 32768 };
	unsigned int tmp_val = 0;
	unsigned int curr_val = 0;
	unsigned int i = 0;
	unsigned int j = 0;

	tmp_val = clkrate / speed_hz;

	for (i = 0; i < ARRAY_SIZE(pbr_val); i++) {
		for (j = 0; j < ARRAY_SIZE(brs_val); j++) {
			curr_val = pbr_val[i] * brs_val[j];
			if (curr_val >= tmp_val) {
				*req_pbr = i;
				*req_br = j;
				return TEE_SUCCESS;
			}
		}
	}

	EMSG("Can not find valid baud rate, speed_hz is %d, ", speed_hz);
	EMSG("clkrate is %d, using max prescaler value", clkrate);

	return TEE_ERROR_ITEM_NOT_FOUND;
}

/*
 * Configure speed of slave
 * dspi_data:	DSPI controller chip instance
 * speed:	speed of slave
 */
static void dspi_setup_speed(struct ls_dspi_data *dspi_data,
			     unsigned int speed)
{
	TEE_Result status = TEE_ERROR_GENERIC;
	unsigned int bus_setup = 0;
	unsigned int bus_clock = 0;
	unsigned int req_i = 0;
	unsigned int req_j = 0;

	bus_clock = dspi_data->bus_clk_hz;

	DMSG("DSPI set_speed: expected SCK speed %u, bus_clk %u", speed,
	     bus_clock);

	bus_setup = io_read32(dspi_data->base + DSPI_CTAR0);
	bus_setup &= ~(DSPI_CTAR_BRD | DSPI_CTAR_BRP(0x3) | DSPI_CTAR_BR(0xf));

	status = dspi_convert_hz_to_baud(&req_i, &req_j, speed, bus_clock);

	/* In case of failure scenario with max speed, setting default speed */
	if (status == TEE_ERROR_ITEM_NOT_FOUND) {
		speed = dspi_data->speed_hz;
		status = dspi_convert_hz_to_baud(&req_i, &req_j,
						 speed, bus_clock);
	}

	if (status == TEE_SUCCESS) {
		bus_setup |= (DSPI_CTAR_BRP(req_i) | DSPI_CTAR_BR(req_j));
		io_write32(dspi_data->base + DSPI_CTAR0, bus_setup);
		dspi_data->speed_hz = speed;
	} else {
		EMSG("Unable to set speed");
	}
}

/*
 * Transferred data to TX FIFO
 * dspi_data:	DSPI controller chip instance
 */
static void dspi_tx(struct ls_dspi_data *dspi_data, uint32_t ctrl,
		    uint16_t data)
{
	int timeout = DSPI_TXRX_WAIT_TIMEOUT;
	uint32_t dspi_val_addr = dspi_data->base + DSPI_PUSHR;
	uint32_t dspi_val = ctrl | data;

	/* wait for empty entries in TXFIFO or timeout */
	while (DSPI_SR_TXCTR(io_read32(dspi_data->base + DSPI_SR)) >= 4 &&
	       timeout--)
		udelay(1);

	if (timeout >= 0)
		io_write32(dspi_val_addr, dspi_val);
	else
		EMSG("waiting timeout!");
}

/*
 * Read data from RX FIFO
 * dspi_data:	DSPI controller chip instance
 */
static uint16_t dspi_rx(struct ls_dspi_data *dspi_data)
{
	int timeout = DSPI_TXRX_WAIT_TIMEOUT;
	uint32_t dspi_val_addr = dspi_data->base + DSPI_POPR;

	/* wait for valid entries in RXFIFO or timeout */
	while (DSPI_SR_RXCTR(io_read32(dspi_data->base + DSPI_SR)) == 0 &&
	       timeout--)
		udelay(1);

	if (timeout >= 0)
		return (uint16_t)DSPI_RFR_RXDATA(io_read32(dspi_val_addr));

	EMSG("waiting timeout!");

	return 0xFFFF;
}

/*
 * Transfer and Receive 8-bit data
 * chip:	spi_chip instance
 * wdata:	TX data queue
 * rdata:	RX data queue
 * num_pkts:	number of data packets
 */
static enum spi_result ls_dspi_txrx8(struct spi_chip *chip, uint8_t *wdata,
				     uint8_t *rdata, size_t num_pkts)
{
	uint8_t *spi_rd = NULL;
	uint8_t *spi_wr = NULL;
	uint32_t ctrl = 0;
	struct ls_dspi_data *data = container_of(chip, struct ls_dspi_data,
						  chip);
	unsigned int cs = data->slave_cs;

	spi_wr = wdata;
	spi_rd = rdata;

	/*
	 * Assert PCSn signals between transfers
	 * select which CTAR register and slave to be used for TX
	 * CTAS selects which CTAR to be used, here we are using CTAR0
	 * PCS (peripheral chip select) is selecting the slave.
	 */
	ctrl = DSPI_TFR_CTAS(data->ctar_sel) | DSPI_TFR_PCS(cs);
	if (data->slave_mode & SPI_CONT)
		ctrl |= DSPI_TFR_CONT;

	if (data->slave_data_size_bits != 8) {
		EMSG("data_size_bits should be 8, not %u",
		     data->slave_data_size_bits);
		return SPI_ERR_CFG;
	}

	while (num_pkts) {
		if (wdata && rdata) {
			dspi_tx(data, ctrl, *spi_wr++);
			*spi_rd++ = dspi_rx(data);
		} else if (wdata) {
			dspi_tx(data, ctrl, *spi_wr++);
			dspi_rx(data);
		} else if (rdata) {
			dspi_tx(data, ctrl, DSPI_IDLE_DATA);
			*spi_rd++ = dspi_rx(data);
		}
		num_pkts = num_pkts - 1;
	}

	return SPI_OK;
}

/*
 * Transfer and Receive 16-bit data
 * chip:        spi_chip instance
 * wdata:	TX data queue
 * rdata:	RX data queue
 * num_pkts:	number of data packets
 */
static enum spi_result ls_dspi_txrx16(struct spi_chip *chip, uint16_t *wdata,
				      uint16_t *rdata, size_t num_pkts)
{
	uint32_t ctrl = 0;
	uint16_t *spi_rd = NULL;
	uint16_t *spi_wr = NULL;
	struct ls_dspi_data *data = container_of(chip, struct ls_dspi_data,
						  chip);
	unsigned int cs = data->slave_cs;

	spi_wr = wdata;
	spi_rd = rdata;

	/*
	 * Assert PCSn signals between transfers
	 * select which CTAR register and slave to be used for TX
	 * CTAS selects which CTAR to be used, here we are using CTAR0
	 * PCS (peripheral chip select) is selecting the slave.
	 */
	ctrl = DSPI_TFR_CTAS(data->ctar_sel) | DSPI_TFR_PCS(cs);
	if (data->slave_mode & SPI_CONT)
		ctrl |= DSPI_TFR_CONT;

	if (data->slave_data_size_bits != 16) {
		EMSG("data_size_bits should be 16, not %u",
		     data->slave_data_size_bits);
		return SPI_ERR_CFG;
	}

	while (num_pkts) {
		if (wdata && rdata) {
			dspi_tx(data, ctrl, *spi_wr++);
			*spi_rd++ = dspi_rx(data);
		} else if (wdata) {
			dspi_tx(data, ctrl, *spi_wr++);
			dspi_rx(data);
		} else if (rdata) {
			dspi_tx(data, ctrl, DSPI_IDLE_DATA);
			*spi_rd++ = dspi_rx(data);
		}
		num_pkts = num_pkts - 1;
	}

	return SPI_OK;
}

/*
 * Statrt DSPI module
 * chip:	spi_chip instance
 */
static void ls_dspi_start(struct spi_chip *chip)
{
	struct ls_dspi_data *data = container_of(chip, struct ls_dspi_data,
						  chip);

	DMSG("Start DSPI Module");
	io_clrbits32(data->base + DSPI_MCR, DSPI_MCR_HALT);
}

/*
 * Stop DSPI module
 * chip:	spi_chip instance
 */
static void ls_dspi_end(struct spi_chip *chip)
{
	struct ls_dspi_data *data = container_of(chip, struct ls_dspi_data,
						  chip);

	/* De-assert PCSn if in CONT mode */
	if (data->slave_mode & SPI_CONT) {
		unsigned int cs = data->slave_cs;
		unsigned int ctrl = DSPI_TFR_CTAS(data->ctar_sel) |
				    DSPI_TFR_PCS(cs);

		/* Dummy read to deassert */
		dspi_tx(data, ctrl, DSPI_IDLE_DATA);
		dspi_rx(data);
	}

	DMSG("Stop DSPI Module");
	io_setbits32(data->base + DSPI_MCR, DSPI_MCR_HALT);
}

/*
 * Clear RX and TX FIFO
 * dspi_data:   DSPI controller chip instance
 */
void dspi_flush_fifo(struct ls_dspi_data *dspi_data)
{
	unsigned int mcr_val = 0;

	mcr_val = io_read32(dspi_data->base + DSPI_MCR);
	/* flush RX and TX FIFO */
	mcr_val |= (DSPI_MCR_CTXF | DSPI_MCR_CRXF);

	io_write32(dspi_data->base + DSPI_MCR, mcr_val);
}

/*
 * Configure active state of slave
 * dspi_data:   DSPI controller chip instance
 * cs:		chip select value of slave
 * state:	slave mode
 */
static void dspi_set_cs_active_state(struct ls_dspi_data *dspi_data,
				     unsigned int cs, unsigned int state)
{
	DMSG("Set CS active state cs=%d state=%d", cs, state);

	if (state & SPI_CS_HIGH)
		/* CSx inactive state is low */
		io_clrbits32(dspi_data->base + DSPI_MCR, DSPI_MCR_PCSIS(cs));
	else
		/* CSx inactive state is high */
		io_setbits32(dspi_data->base + DSPI_MCR, DSPI_MCR_PCSIS(cs));
}

/*
 * Configure transfer state of slave
 * dspi_data:   DSPI controller chip instance
 * state:	slave mode
 */
static void dspi_set_transfer_state(struct ls_dspi_data *dspi_data,
				    unsigned int state)
{
	unsigned int bus_setup = 0;

	DMSG("Set transfer state=%d bits=%d", state,
	     dspi_data->slave_data_size_bits);

	bus_setup = io_read32(dspi_data->base + DSPI_CTAR0);
	bus_setup &= ~DSPI_CTAR_SET_MODE_MASK;
	bus_setup |= dspi_data->ctar_val;
	bus_setup &= ~(DSPI_CTAR_CPOL | DSPI_CTAR_CPHA | DSPI_CTAR_LSBFE);

	if (state & SPI_CPOL)
		bus_setup |= DSPI_CTAR_CPOL;
	if (state & SPI_CPHA)
		bus_setup |= DSPI_CTAR_CPHA;
	if (state & SPI_LSB_FIRST)
		bus_setup |= DSPI_CTAR_LSBFE;

	if (dspi_data->slave_data_size_bits == 8)
		bus_setup |= DSPI_CTAR_FMSZ(7);
	else if (dspi_data->slave_data_size_bits == 16)
		bus_setup |= DSPI_CTAR_FMSZ(15);

	if (dspi_data->ctar_sel == 0)
		io_write32(dspi_data->base + DSPI_CTAR0, bus_setup);
	else
		io_write32(dspi_data->base + DSPI_CTAR1, bus_setup);
}

/*
 * Configure speed of slave
 * dspi_data:   DSPI controller chip instance
 * speed_max_hz:        maximum speed for slave
 */
static void dspi_set_speed(struct ls_dspi_data *dspi_data,
			   unsigned int speed_max_hz)
{
	dspi_setup_speed(dspi_data, speed_max_hz);
}

/*
 * Configure slave for DSPI controller
 * dspi_data:		DSPI controller chip instance
 * cs:			chip select value of slave
 * speed_max_hz:	maximum speed of slave
 * state:		slave mode
 */
static void dspi_config_slave_state(struct ls_dspi_data *dspi_data,
				    unsigned int cs, unsigned int speed_max_hz,
				    unsigned int state)
{
	unsigned int sr_val = 0;

	/* configure speed */
	dspi_set_speed(dspi_data, speed_max_hz);

	/* configure transfer state */
	dspi_set_transfer_state(dspi_data, state);

	/* configure active state of CSX */
	dspi_set_cs_active_state(dspi_data, cs, state);

	/* clear FIFO */
	dspi_flush_fifo(dspi_data);

	/* check module TX and RX status */
	sr_val = io_read32(dspi_data->base + DSPI_SR);
	if ((sr_val & DSPI_SR_TXRXS) != DSPI_SR_TXRXS)
		EMSG("DSPI RX/TX not ready");
}

/*
 * Configure master for DSPI controller
 * dspi_data: DSPI controller chip instance
 * mcr_val: value of master configuration register
 */
static void dspi_set_master_state(struct ls_dspi_data *dspi_data,
				  unsigned int mcr_val)
{
	DMSG("Set master state val=0x%x", mcr_val);
	io_write32(dspi_data->base + DSPI_MCR, mcr_val);
}

/*
 * Configure DSPI controller
 * chip: spi_chip instance
 */
static void ls_dspi_configure(struct spi_chip *chip)
{
	struct ls_dspi_data *data = container_of(chip, struct ls_dspi_data,
						  chip);
	unsigned int mcr_cfg_val = 0;

	mcr_cfg_val = DSPI_MCR_MSTR | DSPI_MCR_PCSIS_MASK | DSPI_MCR_CRXF |
		      DSPI_MCR_CTXF;

	/* Configure Master */
	dspi_set_master_state(data, mcr_cfg_val);

	/* Configure DSPI slave */
	dspi_config_slave_state(data, data->slave_cs, data->slave_speed_max_hz,
				data->slave_mode);
}

/*
 * Extract information for DSPI Controller from the DTB
 * dspi_data: DSPI controller chip instance
 */
static TEE_Result get_info_from_device_tree(struct ls_dspi_data *dspi_data)
{
	const fdt32_t *bus_num = NULL;
	const fdt32_t *chip_select_num = NULL;
	size_t size = 0;
	int node = 0;
	vaddr_t ctrl_base = 0;
	void *fdt = NULL;

	/*
	 * First get the DSPI Controller base address from the DTB
	 * if DTB present and if the DSPI Controller defined in it.
	 */
	fdt = get_dt();
	if (!fdt) {
		EMSG("Unable to get DTB, DSPI init failed\n");
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	node = 0;
	while (node != -FDT_ERR_NOTFOUND) {
		node = fdt_node_offset_by_compatible(fdt, node,
						     "fsl,lx2160a-dspi");
		if (!(_fdt_get_status(fdt, node) & DT_STATUS_OK_SEC))
			continue;

		bus_num = fdt_getprop(fdt, node, "bus-num", NULL);
		if (bus_num && dspi_data->slave_bus ==
			(unsigned int)fdt32_to_cpu(*bus_num)) {
			if (dt_map_dev(fdt, node, &ctrl_base, &size) < 0) {
				EMSG("Unable to get virtual address");
				return TEE_ERROR_GENERIC;
			}
			break;
		}
	}

	dspi_data->base = ctrl_base;
	dspi_data->bus_clk_hz = DSPI_CLK;

	chip_select_num = fdt_getprop(fdt, node, "spi-num-chipselects", NULL);
	if (chip_select_num)
		dspi_data->num_chipselect = (int)fdt32_to_cpu(*chip_select_num);
	else
		return TEE_ERROR_ITEM_NOT_FOUND;

	dspi_data->speed_hz = DSPI_DEFAULT_SCK_FREQ;

	return TEE_SUCCESS;
}

static const struct spi_ops ls_dspi_ops = {
	.configure = ls_dspi_configure,
	.start = ls_dspi_start,
	.txrx8 = ls_dspi_txrx8,
	.txrx16 = ls_dspi_txrx16,
	.end = ls_dspi_end,
};
DECLARE_KEEP_PAGER(ls_dspi_ops);

TEE_Result ls_dspi_init(struct ls_dspi_data *dspi_data)
{
	TEE_Result status = TEE_ERROR_GENERIC;

	/*
	 * First get the DSPI Controller base address from the DTB,
	 * if DTB present and if the DSPI Controller defined in it.
	 */
	if (dspi_data)
		status = get_info_from_device_tree(dspi_data);
	if (status == TEE_SUCCESS)
		/* generic DSPI chip handle */
		dspi_data->chip.ops = &ls_dspi_ops;
	else
		EMSG("Unable to get info from device tree");

	return status;
}
