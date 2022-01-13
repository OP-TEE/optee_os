// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2021 Microchip
 */

#include <assert.h>
#include <drivers/clk.h>
#include <drivers/clk_dt.h>
#include <io.h>
#include <kernel/boot.h>
#include <kernel/spinlock.h>
#include <libfdt.h>
#include <matrix.h>
#include <platform_config.h>
#include <rng_support.h>
#include <string.h>
#include <tee/tee_cryp_utl.h>

/* Registers */
#define TRNG_CTRL		0x0
#define TRNG_CTRL_WAKEY_OFFSET	8
#define TRNG_CTRL_WAKEY_VALUE	0x524E47

#define TRNG_IER		0x10
#define TRNG_ISR		0x1C
#define TRNG_ODATA		0x50

static unsigned int trng_lock = SPINLOCK_UNLOCK;
static unsigned int trng_random_val_lock = SPINLOCK_UNLOCK;
static vaddr_t trng_base;
static uint8_t random_byte_pos;
static union {
	uint32_t val;
	uint8_t byte[sizeof(uint32_t)];
} random_data;

static uint32_t atmel_trng_read32(void)
{
	uint32_t exceptions = 0;
	uint32_t value = 0;

	exceptions = cpu_spin_lock_xsave(&trng_lock);

	while (!io_read32(trng_base + TRNG_ISR))
		;

	value = io_read32(trng_base + TRNG_ODATA);

	cpu_spin_unlock_xrestore(&trng_lock, exceptions);

	return value;
}

TEE_Result crypto_rng_read(void *buf, size_t len)
{
	uint8_t *rngbuf = buf;
	uint32_t val = 0;
	size_t len_to_copy = 0;

	assert(buf);
	assert(trng_base);

	while (len) {
		val = atmel_trng_read32();
		len_to_copy = MIN(len, sizeof(uint32_t));
		memcpy(rngbuf, &val, len_to_copy);
		rngbuf += len_to_copy;
		len -= len_to_copy;
	}

	return TEE_SUCCESS;
}

uint8_t hw_get_random_byte(void)
{
	uint32_t exceptions = 0;
	uint8_t data = 0;

	assert(trng_base);

	exceptions = cpu_spin_lock_xsave(&trng_random_val_lock);

	/*
	 * The TRNG generates a whole 32 bits word every 84 cycles. To avoid
	 * discarding 3 bytes at each request, request 4 bytes of random data
	 * and return only 1 at each request until there is no more bytes in the
	 * random_data "cache".
	 */
	if (!random_byte_pos)
		random_data.val = atmel_trng_read32();

	data = random_data.byte[random_byte_pos++];
	if (random_byte_pos == sizeof(uint32_t))
		random_byte_pos = 0;

	cpu_spin_unlock_xrestore(&trng_random_val_lock, exceptions);

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

static TEE_Result trng_node_probe(const void *fdt, int node,
				  const void *compat_data __unused)
{
	int status = _fdt_get_status(fdt, node);
	size_t size = 0;
	struct clk *clk = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (status != DT_STATUS_OK_SEC)
		return TEE_ERROR_GENERIC;

	matrix_configure_periph_secure(AT91C_ID_TRNG);

	res = clk_dt_get_by_index(fdt, node, 0, &clk);
	if (res)
		return res;

	if (dt_map_dev(fdt, node, &trng_base, &size) < 0)
		return TEE_ERROR_GENERIC;

	clk_enable(clk);

	atmel_trng_reset();

	return TEE_SUCCESS;
}

static const struct dt_device_match atmel_trng_match_table[] = {
	{ .compatible = "atmel,at91sam9g45-trng" },
	{ }
};

DEFINE_DT_DRIVER(atmel_trng_dt_driver) = {
	.name = "atmel_trng",
	.type = DT_DRIVER_NOTYPE,
	.match_table = atmel_trng_match_table,
	.probe = trng_node_probe,
};
