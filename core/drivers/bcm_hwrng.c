// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2019 Broadcom.
 */

#include <crypto/crypto.h>
#include <drivers/bcm_hwrng.h>
#include <initcall.h>
#include <io.h>
#include <kernel/delay.h>
#include <kernel/panic.h>
#include <kernel/spinlock.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <rng_support.h>
#include <string.h>
#include <trace.h>

/* Registers */
#define RNG_CTRL_OFFSET         0x00
#define RNG_CTRL_MASK           0x00001fff
#define RNG_CTRL_DISABLE        0x00000000
#define RNG_CTRL_ENABLE         0x00000001

#define RNG_SOFT_RESET_OFFSET   0x04
#define RNG_SOFT_RESET_MASK     0x00000001

#define RNG_FIFO_DATA_OFFSET    0x20

#define RNG_FIFO_COUNT_OFFSET   0x24

#define RNG_FIFO_COUNT_MASK     0x000000ff
#define RNG_TIMEOUT_US		10000

static vaddr_t bcm_hwrng_base;
static unsigned int bcm_hwrng_lock;

static void bcm_hwrng_reset(void)
{
	/* Disable RBG */
	io_clrsetbits32(bcm_hwrng_base + RNG_CTRL_OFFSET,
			RNG_CTRL_MASK, RNG_CTRL_DISABLE);
	/* Reset RNG and RBG */
	io_setbits32(bcm_hwrng_base +
		     RNG_SOFT_RESET_OFFSET, RNG_SOFT_RESET_MASK);
	io_clrbits32(bcm_hwrng_base +
		     RNG_SOFT_RESET_OFFSET, RNG_SOFT_RESET_MASK);
	/* Enable RBG */
	io_clrsetbits32(bcm_hwrng_base + RNG_CTRL_OFFSET,
			RNG_CTRL_MASK, RNG_CTRL_ENABLE);
}

static size_t do_rng_read(void *buf, size_t blen)
{
	uint32_t available = 0;
	size_t copied = 0;
	size_t copy_len = 0;
	union {
		uint32_t word;
		uint8_t  bytes[4];
	} data;
	uint64_t timeout;

	assert(bcm_hwrng_base);

	cpu_spin_lock(&bcm_hwrng_lock);

	while (copied < blen) {
		if (!available) {
			timeout = timeout_init_us(RNG_TIMEOUT_US);
			do {
				available = io_read32(bcm_hwrng_base +
						RNG_FIFO_COUNT_OFFSET);
				available = available & RNG_FIFO_COUNT_MASK;
				if (timeout_elapsed(timeout)) {
					DMSG("timeout waiting for rng FIFO\n");
					goto out;
				}
			} while (!available);
		}
		available--;

		data.word = io_read32(bcm_hwrng_base +
				     RNG_FIFO_DATA_OFFSET);

		copy_len = MIN((blen - copied), sizeof(uint32_t));
		memcpy((uint8_t *)buf + copied, data.bytes, copy_len);
		copied += copy_len;
	}

out:
	cpu_spin_unlock(&bcm_hwrng_lock);
	return copied;
}

uint32_t bcm_hwrng_read_rng(uint32_t *p_out, uint32_t words_to_read)
{
	size_t copy_len = words_to_read * sizeof(uint32_t);

	copy_len = do_rng_read((void *)p_out, copy_len);

	return copy_len / sizeof(uint32_t);
}

TEE_Result crypto_rng_read(void *buf, size_t blen)
{
	if (do_rng_read(buf, blen) == blen)
		return TEE_SUCCESS;

	return TEE_ERROR_NO_DATA;
}

uint8_t hw_get_random_byte(void)
{
	uint8_t data = 0;

	if (do_rng_read(&data, 1) != 1)
		panic();

	return data;
}

static TEE_Result bcm_hwrng_init(void)
{
	bcm_hwrng_base = (vaddr_t)phys_to_virt(HWRNG_BASE, MEM_AREA_IO_SEC);
	bcm_hwrng_lock = SPINLOCK_UNLOCK;

	bcm_hwrng_reset();

	DMSG("bcm_hwrng init done\n");
	return TEE_SUCCESS;
}

driver_init(bcm_hwrng_init);
