// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2019 Broadcom.
 */

#include <drivers/bcm_hwrng.h>
#include <initcall.h>
#include <io.h>
#include <kernel/delay.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
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

uint32_t bcm_hwrng_read_rng(uint32_t *p_out, uint32_t words_to_read)
{
	uint32_t available_words = 0;
	uint32_t num_words = 0;
	uint32_t i = 0;
	uint64_t timeout = timeout_init_us(RNG_TIMEOUT_US);

	assert(bcm_hwrng_base);

	do {
		available_words = io_read32(bcm_hwrng_base +
					    RNG_FIFO_COUNT_OFFSET);
		available_words = available_words & RNG_FIFO_COUNT_MASK;
	} while (!available_words && !timeout_elapsed(timeout));

	if ((available_words > 0) && (words_to_read > 0)) {
		num_words =  MIN(available_words, words_to_read);
		for (i = 0; i < num_words; i++)
			p_out[i] = io_read32(bcm_hwrng_base +
					     RNG_FIFO_DATA_OFFSET);
	}

	return num_words;
}

static TEE_Result bcm_hwrng_init(void)
{
	bcm_hwrng_base = (vaddr_t)phys_to_virt(HWRNG_BASE, MEM_AREA_IO_SEC,
					       HWRNG_END - HWRNG_BASE);

	bcm_hwrng_reset();

	DMSG("bcm_hwrng init done\n");
	return TEE_SUCCESS;
}

driver_init(bcm_hwrng_init);
