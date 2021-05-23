// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016, Linaro Limited
 */

/* Driver for the internal Random Number Generator of HiSilicon P660/Hi16xx */

#include <initcall.h>
#include <io.h>
#include <kernel/spinlock.h>
#include <kernel/tee_time.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <rng_support.h>
#include <trace.h>
#include <types_ext.h>
#include <util.h>

/* ALG sub-controller registers */

#define ALG_SC_RNG_RESET_DREQ	0xAB4	/* RNG reset cancel */
#  define ALG_SC_SRST_DREQ_RNG	BIT(0)

/* RNG registers */

#define	RNG_SEED	0x0	/* Initial seed */
#define RNG_CTRL	0x4	/* Control register */
#  define RNG_SEED_SEL	BIT(2)	/* Re-seed source: 1: ring osc., 0: LFSR */
#  define RNG_RING_EN	BIT(1)	/* Enable ring oscillator */
#  define RNG_EN	BIT(0)	/* Enable RNG */
#define RNG_NUM		0x10	/* Random number output */
#define RNG_PHY_SEED	0x14	/* Ring oscillator output */

register_phys_mem_pgdir(MEM_AREA_IO_SEC, ALG_SC_BASE, ALG_SC_REG_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, RNG_BASE, RNG_REG_SIZE);

static unsigned int rng_lock = SPINLOCK_UNLOCK;

static TEE_Result hi16xx_rng_init(void)
{
	vaddr_t alg = (vaddr_t)phys_to_virt(ALG_SC_BASE, MEM_AREA_IO_SEC,
					    ALG_SC_REG_SIZE);
	vaddr_t rng = (vaddr_t)phys_to_virt(RNG_BASE, MEM_AREA_IO_SEC,
					    RNG_REG_SIZE);
	TEE_Time time;

	/* ALG sub-controller must allow RNG out of reset */
	io_write32(alg + ALG_SC_RNG_RESET_DREQ, ALG_SC_SRST_DREQ_RNG);

	/* Set initial seed */
	tee_time_get_sys_time(&time);
	io_write32(rng + RNG_SEED, time.seconds * 1000 + time.millis);

	/*
	 * Enable RNG and configure it to re-seed automatically from the
	 * internal ring oscillator
	 */
	io_write32(rng + RNG_CTRL, RNG_EN | RNG_RING_EN | RNG_SEED_SEL);

	IMSG("Hi16xx RNG initialized");
	return TEE_SUCCESS;
}

uint8_t hw_get_random_byte(void)
{
	static vaddr_t r;
	static int pos;
	static union {
		uint32_t val;
		uint8_t byte[4];
	} random;
	uint8_t ret;
	uint32_t exceptions;

	exceptions = cpu_spin_lock_xsave(&rng_lock);

	if (!r)
		r = (vaddr_t)phys_to_virt(RNG_BASE, MEM_AREA_IO_SEC, 1) +
			RNG_NUM;

	if (!pos)
		random.val = io_read32(r);

	ret = random.byte[pos++];

	if (pos == 4)
		pos = 0;

	cpu_spin_unlock_xrestore(&rng_lock, exceptions);

	return ret;
}

driver_init(hi16xx_rng_init);
