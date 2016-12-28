/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
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
};

#endif	/* __SPI_H__ */

