/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016, Linaro Limited
 */

#ifndef __SPI_H__
#define __SPI_H__

#include <types_ext.h>

enum spi_mode {
	SPI_MODE0,
	SPI_MODE1,
	SPI_MODE2,
	SPI_MODE3
};

enum spi_result {
	SPI_OK,
	SPI_ERR_CFG,
	SPI_ERR_PKTCNT,
	SPI_ERR_GENERIC
};

struct spi_chip {
	const struct spi_ops *ops;
};

struct spi_ops {
	void (*configure)(struct spi_chip *chip);
	void (*start)(struct spi_chip *chip);
	enum spi_result (*txrx8)(struct spi_chip *chip, uint8_t *wdat,
		uint8_t *rdat, size_t num_pkts);
	enum spi_result (*txrx16)(struct spi_chip *chip, uint16_t *wdat,
		uint16_t *rdat, size_t num_pkts);
	void (*end)(struct spi_chip *chip);
	void (*flushfifo)(struct spi_chip *chip);
};

#endif	/* __SPI_H__ */

