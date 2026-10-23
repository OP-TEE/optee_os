// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <drivers/qcom_geni_spi.h>
#include <initcall.h>
#include <inttypes.h>
#include <spi.h>
#include <stdint.h>
#include <string.h>
#include <trace.h>
#include <util.h>

/*
 * Boot-time self-test for the QUP GENI SPI driver, run once via
 * driver_init() on the first configured SE. Loops MOSI back to MISO
 * inside the SE and confirms a known TX pattern reads back unchanged,
 * exercising FIFO fill/drain, byte-packing, and CS assert/deassert
 * without needing external wiring. Enable with CFG_QUP_SPI_TEST=y.
 */

#define QUP_SPI_TEST_SPEED_HZ		50000000
#define QUP_SPI_TEST_BITS_PER_WORD	8
#define QUP_SPI_TEST_NUM_PKTS		16

static bool qup_spi_test_buffers_match(const uint8_t *tx, const uint8_t *rx,
					size_t len)
{
	size_t i = 0;

	for (i = 0; i < len; i++) {
		if (tx[i] != rx[i]) {
			EMSG("QUP SPI test: mismatch at byte %zu: tx=%#x rx=%#x",
			     i, tx[i], rx[i]);
			return false;
		}
	}

	return true;
}

static enum spi_result qup_spi_test_run_txrx(struct qup_spi_data *qs,
					      const uint8_t *tx, uint8_t *rx,
					      size_t num_pkts)
{
	enum spi_result res = SPI_OK;

	qs->chip.ops->start(&qs->chip);
	res = qs->chip.ops->txrx8(&qs->chip, (uint8_t *)tx, rx, num_pkts);
	qs->chip.ops->end(&qs->chip);

	return res;
}

/*
 * Loop MOSI back to MISO inside the SE and confirm a known TX pattern is
 * read back unchanged. Proves FIFO fill/drain, byte-packing, and the
 * CS assert/txrx/deassert sequence all work end to end.
 */
static bool qup_spi_test_loopback(struct qup_spi_data *qs)
{
	uint8_t tx[QUP_SPI_TEST_NUM_PKTS] = { 0 };
	uint8_t rx[QUP_SPI_TEST_NUM_PKTS] = { 0 };
	size_t i = 0;
	enum spi_result res = SPI_OK;

	for (i = 0; i < sizeof(tx); i++)
		tx[i] = (uint8_t)(0xa5 ^ i);
	memset(rx, 0, sizeof(rx));

	qs->speed_hz = QUP_SPI_TEST_SPEED_HZ;
	qs->bits_per_word = QUP_SPI_TEST_BITS_PER_WORD;
	qs->mode = SPI_MODE0;
	qs->cs = 0;
	qs->cs_high = false;
	qup_spi_set_loopback(qs, true);
	qs->chip.ops->configure(&qs->chip);

	res = qup_spi_test_run_txrx(qs, tx, rx, sizeof(tx));

	qup_spi_set_loopback(qs, false);
	qs->chip.ops->configure(&qs->chip);

	DMSG("QUP SPI %u: loopback tx/rx buffers:", qs->id);
	DHEXDUMP(tx, sizeof(tx));
	DHEXDUMP(rx, sizeof(rx));

	if (res != SPI_OK) {
		EMSG("QUP SPI %u: loopback test: txrx failed, res=%d",
		     qs->id, res);
		return false;
	}

	if (!qup_spi_test_buffers_match(tx, rx, sizeof(tx))) {
		EMSG("QUP SPI %u: loopback test: readback mismatch", qs->id);
		return false;
	}

	IMSG("QUP SPI %u: loopback test: PASS (%zu bytes)", qs->id,
	     sizeof(tx));

	return true;
}

static TEE_Result qup_spi_test_init(void)
{
	struct qup_spi_data qs = { };
	TEE_Result res = TEE_SUCCESS;

	if (!qup_spi_config_count) {
		IMSG("QUP SPI test: no SE configured for this platform, skipping");
		return TEE_SUCCESS;
	}

	res = qup_spi_init(&qs, qup_spi_config[0].id);
	if (res) {
		EMSG("QUP SPI test: qup_spi_init(%u) failed: %#"PRIx32,
		     qup_spi_config[0].id, res);
		return TEE_SUCCESS;
	}

	if (!qup_spi_test_loopback(&qs))
		EMSG("QUP SPI %u: loopback test: FAIL", qs.id);

	return TEE_SUCCESS;
}

driver_init_late(qup_spi_test_init);
