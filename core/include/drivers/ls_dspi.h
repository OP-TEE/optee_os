/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2021 NXP
 *
 * Helper Code for DSPI Controller driver
 */

#ifndef __DRIVERS_LS_DSPI_H
#define __DRIVERS_LS_DSPI_H

#include <mm/core_memprot.h>
#include <spi.h>

/* Clock and transfer attributes */
#define DSPI_CTAR_BRD	     0x80000000		/* Double Baud Rate [0] */
#define DSPI_CTAR_FMSZ(x)    (((x) & 0x0F) << 27) /* Frame Size [1-4] */
#define DSPI_CTAR_CPOL	     0x04000000		/* Clock Polarity [5] */
#define DSPI_CTAR_CPHA	     0x02000000		/* Clock Phase [6] */
#define DSPI_CTAR_LSBFE	     0x01000000		/* LSB First [7] */
#define DSPI_CTAR_PCS_SCK(x) (((x) & 0x03) << 22) /* PCSSCK [8-9] */
#define DSPI_CTAR_PA_SCK(x)  (((x) & 0x03) << 20) /* PASC [10-11] */
#define DSPI_CTAR_P_DT(x)    (((x) & 0x03) << 18) /* PDT [12-13] */
#define DSPI_CTAR_BRP(x)     \
	(((x) & 0x03) << 16) /* Baud Rate Prescaler [14-15] */
#define DSPI_CTAR_CS_SCK(x)  (((x) & 0x0F) << 12) /* CSSCK [16-19] */
#define DSPI_CTAR_A_SCK(x)   (((x) & 0x0F) << 8)	/* ASC [20-23] */
#define DSPI_CTAR_A_DT(x)    (((x) & 0x0F) << 4)	/* DT [24-27] */
#define DSPI_CTAR_BR(x)	     ((x) & 0x0F)	/* Baud Rate Scaler [28-31] */

/* SPI mode flags */
#define SPI_CPHA      BIT(0) /* clock phase */
#define SPI_CPOL      BIT(1) /* clock polarity */
#define SPI_CS_HIGH   BIT(2) /* CS active high */
#define SPI_LSB_FIRST BIT(3) /* per-word bits-on-wire */
#define SPI_CONT      BIT(4) /* Continuous CS mode */

/*
 * struct ls_dspi_data describes DSPI controller chip instance
 * The structure contains below members:
 * chip:		generic spi_chip instance
 * base:		DSPI controller base address
 * bus_clk_hz:		DSPI input clk frequency
 * speed_hz:		Default SCK frequency=1mhz
 * num_chipselect:	chip/slave selection
 * slave_bus:		bus value of slave
 * slave_cs:		chip slect value of slave
 * slave_speed_max_hz:	max spped of slave
 * slave_mode:		mode of slave
 * slave_data_size_bits:Data size to be transferred (8 or 16 bits)
 * ctar_val:		value of Clock and Transfer Attributes Register (CTAR)
 * ctar_sel:		CTAR0 or CTAR1
 */
struct ls_dspi_data {
	struct spi_chip chip;
	vaddr_t base;
	unsigned int bus_clk_hz;
	unsigned int speed_hz;
	unsigned int num_chipselect;
	unsigned int slave_bus;
	unsigned int slave_cs;
	unsigned int slave_speed_max_hz;
	unsigned int slave_mode;
	unsigned int slave_data_size_bits;
	unsigned int ctar_val;
	unsigned int ctar_sel;
};

/*
 * Initialize DSPI Controller
 * dspi_data:	DSPI controller chip instance
 */
TEE_Result ls_dspi_init(struct ls_dspi_data *dspi_data);

#endif /* __DRIVERS_LS_DSPI_H */
