// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020, Linaro Limited
 */

#include <assert.h>
#include <drivers/stm32_rng.h>
#include <drivers/stm32mp1_rcc.h>
#include <io.h>
#include <kernel/delay.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <stm32_util.h>
#include <tee/tee_cryp_utl.h>
#include <trace.h>

#define RNG1_RESET_TIMEOUT_US		1000
#define PRNG_SEED_SIZE			16

/* Override weak plat_rng_init with platform handler to seed PRNG */
void plat_rng_init(void)
{
	vaddr_t rng = (vaddr_t)phys_to_virt(RNG1_BASE, MEM_AREA_IO_SEC, 1);
	vaddr_t rcc = stm32_rcc_base();
	uint64_t timeout_ref = timeout_init_us(RNG1_RESET_TIMEOUT_US);
	uint8_t seed[PRNG_SEED_SIZE] = { };
	size_t size = 0;

	assert(cpu_mmu_enabled());

	/* Setup RNG1 without clock/reset driver support, not yet initialized */
	io_setbits32(rcc + RCC_MP_AHB5ENSETR, RCC_MP_AHB5ENSETR_RNG1EN);
	io_setbits32(rcc + RCC_MP_AHB5LPENCLRR, RCC_MP_AHB5LPENSETR_RNG1LPEN);
	io_setbits32(rcc + RCC_AHB5RSTSETR, RCC_AHB5RSTSETR_RNG1RST);
	while (!(io_read32(rcc + RCC_AHB5RSTSETR) & RCC_AHB5RSTSETR_RNG1RST))
		if (timeout_elapsed(timeout_ref))
			panic();
	io_setbits32(rcc + RCC_AHB5RSTCLRR, RCC_AHB5RSTSETR_RNG1RST);
	while (io_read32(rcc + RCC_AHB5RSTSETR) & RCC_AHB5RSTSETR_RNG1RST)
		if (timeout_elapsed(timeout_ref))
			panic();

	size = sizeof(seed);
	if (stm32_rng_read_raw(rng, seed, &size))
		panic();
	if (size != sizeof(seed))
		panic();

	if (crypto_rng_init(seed, sizeof(seed)))
		panic();

	DMSG("PRNG seeded with RNG1");
}
