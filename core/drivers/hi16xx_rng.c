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

/* Driver for the internal Random Number Generator of HiSilicon P660/Hi16xx */

#include <initcall.h>
#include <io.h>
#include <kernel/mutex.h>
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

register_phys_mem(MEM_AREA_IO_SEC, ALG_SC_BASE, ALG_SC_REG_SIZE);
register_phys_mem(MEM_AREA_IO_SEC, RNG_BASE, RNG_REG_SIZE);

static struct mutex rng_mutex = MUTEX_INITIALIZER;

static TEE_Result hi16xx_rng_init(void)
{
	vaddr_t alg = (vaddr_t)phys_to_virt(ALG_SC_BASE, MEM_AREA_IO_SEC);
	vaddr_t rng = (vaddr_t)phys_to_virt(RNG_BASE, MEM_AREA_IO_SEC);
	TEE_Time time;

	/* ALG sub-controller must allow RNG out of reset */
	write32(ALG_SC_SRST_DREQ_RNG, alg + ALG_SC_RNG_RESET_DREQ);

	/* Set initial seed */
	tee_time_get_sys_time(&time);
	write32(time.seconds * 1000 + time.millis, rng + RNG_SEED);

	/*
	 * Enable RNG and configure it to re-seed automatically from the
	 * internal ring oscillator
	 */
	write32(RNG_EN | RNG_RING_EN | RNG_SEED_SEL, rng + RNG_CTRL);

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

	mutex_lock(&rng_mutex);

	if (!r)
		r = (vaddr_t)phys_to_virt(RNG_BASE, MEM_AREA_IO_SEC) + RNG_NUM;

	if (!pos)
		random.val = read32(r);

	ret = random.byte[pos++];

	if (pos == 4)
		pos = 0;

	mutex_unlock(&rng_mutex);

	return ret;
}

driver_init(hi16xx_rng_init);
