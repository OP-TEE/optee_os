// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2022, Vaisala Oyj
 */

#include <assert.h>
#include <io.h>
#include <kernel/boot.h>
#include <kernel/delay.h>
#include <kernel/dt.h>
#include <kernel/dt_driver.h>
#include <kernel/spinlock.h>
#include <libfdt.h>
#include <platform_config.h>
#include <rng_support.h>
#include <string.h>
#include <tee/tee_cryp_utl.h>

#define CONTROL_REG                     0x00000000
#define STATUS_REG                      0x00000004
#define RAND_REG                        0x00000000

#define HOST_TO_TRNG_RESET              0x00000001
#define HOST_TO_TRNG_RELEASE_RESET      0x00000002
#define HOST_TO_TRNG_ENABLE             0x80000000
#define HOST_TO_TRNG_ZEROIZE            0x80000004
#define HOST_TO_TRNG_ACK_ZEROIZE        0x80000008
#define HOST_TO_TRNG_READ               0x8000000F

/* trng statuses */
#define TRNG_ACK_RESET                  0x000000AC
#define TRNG_SUCCESSFUL_STARTUP         0x00000057
#define TRNG_FAILED_STARTUP             0x000000FA
#define TRNG_NEW_RAND_AVAILABLE         0x000000ED

static unsigned int trng_lock = SPINLOCK_UNLOCK;

static vaddr_t xiphera_trng_base;

static uint32_t xiphera_trng_read32(void)
{
	uint32_t value = 0;
	uint32_t exceptions = 0;
	uint32_t status = 0;

	while (true) {
		/* Wait until we have value available */
		status = io_read32(xiphera_trng_base + STATUS_REG);
		if (status != TRNG_NEW_RAND_AVAILABLE)
			continue;

		value = io_read32(xiphera_trng_base + RAND_REG);

		/*
		 * Ack that RNG value has been consumed and trigger new one to
		 * be generated
		 */
		io_write32(xiphera_trng_base + CONTROL_REG, HOST_TO_TRNG_READ);
		io_write32(xiphera_trng_base + CONTROL_REG,
			   HOST_TO_TRNG_ENABLE);

		break;
	}

	return value;
}

/* This is a true RNG, no need for seeding */
void plat_rng_init(void)
{
}

TEE_Result hw_get_random_bytes(void *buf, size_t len)
{
	static union {
		uint32_t val;
		uint8_t byte[4];
	} fifo;
	static size_t fifo_pos;
	uint8_t *buffer = buf;
	size_t buffer_pos = 0;

	assert(xiphera_trng_base);

	while (buffer_pos < len) {
		uint32_t exceptions = cpu_spin_lock_xsave(&trng_lock);

		/* Refill our FIFO */
		if (fifo_pos == 0)
			fifo.val = xiphera_trng_read32();

		buffer[buffer_pos++] = fifo.byte[fifo_pos++];
		fifo_pos %= 4;

		cpu_spin_unlock_xrestore(&trng_lock, exceptions);
	}

	return TEE_SUCCESS;
}

static TEE_Result xiphera_trng_probe(const void *fdt, int node,
				     const void *compat_data __unused)
{
	int dt_status = _fdt_get_status(fdt, node);
	uint32_t status = 0;
	size_t size = 0;

	/* Skip non-secure instances */
	if (dt_status != DT_STATUS_OK_SEC)
		return TEE_ERROR_NODE_DISABLED;

	if (xiphera_trng_base) {
		EMSG("Only one secure instance is supported");
		return TEE_ERROR_GENERIC;
	}

	if (dt_map_dev(fdt, node, &xiphera_trng_base, &size) < 0)
		return TEE_ERROR_GENERIC;

	/*
	 * The TRNG needs to be first reset in order to provide stable
	 * operation.
	 *
	 * Reset of the chip should complete within 200 us but in some cases it
	 * could take up to 400 us. If it is not ready within 400 us assume
	 * there is problem.
	 */
	io_write32(xiphera_trng_base + CONTROL_REG, HOST_TO_TRNG_RESET);
	udelay(200);

	status = io_read32(xiphera_trng_base + STATUS_REG);
	if (status != TRNG_ACK_RESET) {
		/*
		 * Give it additional 200 us to allow it to reset.
		 *
		 * If still not done -> error out.
		 */
		udelay(200);
		status = io_read32(xiphera_trng_base + STATUS_REG);
		if (status != TRNG_ACK_RESET) {
			EMSG("Failed to reset TRNG\n");
			return TEE_ERROR_GENERIC;
		}
	}

	/*
	 * Now TRNG should be internally stable.
	 *
	 * Clear internal random number generation engine to start in stable
	 * state and give it 20 ms to enable good random number entropy and
	 * then check that random number engine is ready.
	 */
	io_write32(xiphera_trng_base + CONTROL_REG,
		   HOST_TO_TRNG_RELEASE_RESET);
	io_write32(xiphera_trng_base + CONTROL_REG, HOST_TO_TRNG_ENABLE);
	io_write32(xiphera_trng_base + CONTROL_REG, HOST_TO_TRNG_ZEROIZE);
	mdelay(20);

	status = io_read32(xiphera_trng_base + STATUS_REG);
	if (status != TRNG_SUCCESSFUL_STARTUP) {
		/*
		 * Check specifically if there were startup test errors to aid
		 * in debugging TRNG implementation in FPGA
		 */
		if (status == TRNG_FAILED_STARTUP) {
			EMSG("Startup tests have failed\n");
			return TEE_ERROR_GENERIC;
		}

		EMSG("Startup tests yielded no response -> TRNG stuck\n");
		return TEE_ERROR_GENERIC;
	}

	io_write32(xiphera_trng_base + CONTROL_REG, HOST_TO_TRNG_ACK_ZEROIZE);

	DMSG("TRNG initialized\n");

	return TEE_SUCCESS;
}

static const struct dt_device_match xiphera_trng_match_table[] = {
	{ .compatible = "xiphera,xip8001b-trng" },
	{ }
};

DEFINE_DT_DRIVER(xiphera_trng_dt_driver) = {
	.name = "xiphera_trng",
	.type = DT_DRIVER_NOTYPE,
	.match_table = xiphera_trng_match_table,
	.probe = xiphera_trng_probe,
};
