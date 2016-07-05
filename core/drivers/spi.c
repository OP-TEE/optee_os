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
 *
 * SPI -- Serial Peripheral Interface
 *
 * Defines a simple and generic interface to access SPI devices.
 *
 */

#include <assert.h>
#include <spi.h>
#include <trace.h>

/*
 * The spi implementation
 */
static const struct spi_ops *ops;

void spi_txrx8(uint8_t *wdat, uint8_t *rdat, uint32_t num_txpkts, uint32_t *num_rxpkts)
{
	assert(ops);
	assert(ops->txrx8 != 0);
	assert(wdat != 0 && rdat != 0 && num_rxpkts != 0);

	ops->txrx8(wdat, rdat, num_txpkts, num_rxpkts);
}

void spi_txrx16(uint16_t *wdat, uint16_t *rdat, uint32_t num_txpkts, uint32_t *num_rxpkts)
{
	assert(ops);
	assert(ops->txrx16 != 0);
	assert(wdat != 0 && rdat != 0 && num_rxpkts != 0);

	ops->txrx16(wdat, rdat, num_txpkts, num_rxpkts);
}

void spi_tx8(uint8_t *wdat, uint32_t num_txpkts)
{
	assert(ops);
	assert(ops->tx8 != 0);
	assert(wdat != 0);

	ops->tx8(wdat, num_txpkts);
}

void spi_tx16(uint16_t *wdat, uint32_t num_txpkts)
{
	assert(ops);
	assert(ops->tx16 != 0);
	assert(wdat != 0);

	ops->tx16(wdat, num_txpkts);
}

void spi_rx8(uint8_t *rdat, uint32_t *num_rxpkts)
{
	assert(ops);
	assert(ops->rx8 != 0);
	assert(rdat != 0 && num_rxpkts != 0);

	ops->rx8(rdat, num_rxpkts);
}

void spi_rx16(uint16_t *rdat, uint32_t *num_rxpkts)
{
	assert(ops);
	assert(ops->rx16 != 0);
	assert(rdat != 0 && num_rxpkts != 0);

	ops->rx16(rdat, num_rxpkts);
}

/*
 * Initialize the spi. The fields in the provided spi
 * ops pointer must be valid.
 */
void spi_init(const struct spi_ops *ops_ptr)
{
	assert(ops_ptr);

	ops = ops_ptr;
}
