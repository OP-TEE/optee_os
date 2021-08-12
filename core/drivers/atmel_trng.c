// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2021 Microchip
 */

#include <assert.h>
#include <drivers/clk.h>
#include <drivers/clk_dt.h>
#include <io.h>
#include <kernel/boot.h>
#include <libfdt.h>
#include <matrix.h>
#include <rng_support.h>
#include <platform_config.h>
#include <string.h>
#include <tee/tee_cryp_utl.h>

/* Registers */
#define TRNG_CTRL		0x0
#define TRNG_CTRL_WAKEY_OFFSET	8
#define TRNG_CTRL_WAKEY_VALUE	0x524E47

#define TRNG_IER		0x10
#define TRNG_ISR		0x1C
#define TRNG_ODATA		0x50

#define TRNG_BYTE_READ		sizeof(uint32_t)

static vaddr_t trng_base;
static uint32_t trng_last_val;
static uint8_t trng_valid_bytes;

static uint32_t atmel_trng_read32(void)
{
	u32 isr;

	do {
		isr = io_read32(trng_base + TRNG_ISR);
	} while (!isr);

	return io_read32(trng_base + TRNG_ODATA);
}

TEE_Result crypto_rng_read(void *buf, size_t len)
{
	uint8_t *rngbuf = buf;
	uint32_t val = 0;
	uint8_t len_to_copy = 0;

	assert(buf);

	if (!trng_base)
		panic("TRNG not initialized");

	while (len) {
		val = atmel_trng_read32();
		len_to_copy = len > TRNG_BYTE_READ ? TRNG_BYTE_READ : len;
		memcpy(rngbuf, &val, len_to_copy);
		rngbuf += len_to_copy;
		len -= len_to_copy;
	}

	return TEE_SUCCESS;
}

uint8_t hw_get_random_byte(void)
{
	uint8_t data = 0;

	if (!trng_base)
		panic("TRNG not initialized");

	/*
	 * The TRNG generates a whole 32 bits word every 84 cycles. To avoid
	 * discarding 3 bytes at each request, request 32 bytes of random data
	 * and return only 1
	 */
	if (trng_valid_bytes == 0) {
		trng_last_val = atmel_trng_read32();
		trng_valid_bytes = TRNG_BYTE_READ;
	}

	data = trng_last_val & 0xFF;
	trng_last_val >>= 8;
	trng_valid_bytes--;

	return data;
}

/* This is a true RNG, no need for seeding */
void plat_rng_init(void)
{
}

static void atmel_trng_reset(void)
{
	uint32_t ctrl_val = TRNG_CTRL_WAKEY_VALUE << TRNG_CTRL_WAKEY_OFFSET;

	/* Disable TRNG */
	io_setbits32(trng_base + TRNG_CTRL, ctrl_val);
	/* Enable interrupt */
	io_setbits32(trng_base + TRNG_IER, 1);
	/* Enable TRNG */
	io_setbits32(trng_base + TRNG_CTRL, ctrl_val | 1);
}

static TEE_Result trng_node_setup(const void *fdt, int nodeoffset, int status)
{
	size_t size = 0;
	struct clk *clk = NULL;

	if (status != DT_STATUS_OK_SEC)
		return TEE_ERROR_GENERIC;

	matrix_configure_periph_secure(AT91C_ID_TRNG);

	if (dt_map_dev(fdt, nodeoffset, &trng_base, &size) < 0)
		return TEE_ERROR_GENERIC;

	clk = clk_dt_get_by_idx(fdt, nodeoffset, 0);
	if (!clk)
		return TEE_ERROR_GENERIC;

	clk_enable(clk);

	atmel_trng_reset();

	return TEE_SUCCESS;
}

static TEE_Result trng_probe(void)
{
	int node = -1;
	int status = 0;
	TEE_Result res = TEE_ERROR_GENERIC;
	void *fdt = get_embedded_dt();

	if (!fdt)
		return TEE_ERROR_GENERIC;

	while (true) {
		node = fdt_node_offset_by_compatible(fdt, node,
						     "atmel,at91sam9g45-trng");
		if (node < 0)
			break;

		status = _fdt_get_status(fdt, node);
		res = trng_node_setup(fdt, node, status);
		if (res == TEE_SUCCESS)
			return TEE_SUCCESS;
	}

	return TEE_ERROR_GENERIC;
}
driver_init(trng_probe);
