// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2018-2019, STMicroelectronics
 */

#include <drivers/stm32mp1_rcc.h>
#include <io.h>
#include <kernel/delay.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <stm32_util.h>

#define RESET_ID_MASK		GENMASK_32(31, 5)
#define RESET_ID_SHIFT		5
#define RESET_BIT_POS_MASK	GENMASK_32(4, 0)

#define RESET_TIMEOUT_US	1000

/*
 * Loop until condition is reached or timeout elapsed. We test the condition
 * again after timeout is detected and panic only if it is still false since
 * TEE thread might have been suspended hence timing out when resumed.
 */
#define WAIT_COND_OR_PANIC(_condition, _timeout_ref) \
	do { \
		if (timeout_elapsed(_timeout_ref) && !(_condition)) \
			panic(); \
	} while (!(_condition))

vaddr_t stm32_rcc_base(void)
{
	static struct io_pa_va base = { .pa = RCC_BASE };

	return io_pa_or_va(&base);
}

static size_t reset_id2reg_offset(unsigned int id)
{
	return ((id & RESET_ID_MASK) >> RESET_ID_SHIFT) * sizeof(uint32_t);
}

static uint8_t reset_id2reg_bit_pos(unsigned int reset_id)
{
	return reset_id & RESET_BIT_POS_MASK;
}

void stm32_reset_assert(unsigned int id)
{
	size_t offset = reset_id2reg_offset(id);
	uint32_t bitmsk = BIT(reset_id2reg_bit_pos(id));
	uint64_t timeout_ref = timeout_init_us(RESET_TIMEOUT_US);
	vaddr_t rcc_base = stm32_rcc_base();

	io_write32(rcc_base + offset, bitmsk);

	WAIT_COND_OR_PANIC(io_read32(rcc_base + offset) & bitmsk,
			   timeout_ref);
}

void stm32_reset_deassert(unsigned int id)
{
	size_t offset = reset_id2reg_offset(id) + RCC_MP_RSTCLRR_OFFSET;
	uint32_t bitmsk = BIT(reset_id2reg_bit_pos(id));
	uint64_t timeout_ref = timeout_init_us(RESET_TIMEOUT_US);
	vaddr_t rcc_base = stm32_rcc_base();

	io_write32(rcc_base + offset, bitmsk);

	WAIT_COND_OR_PANIC(!(io_read32(rcc_base + offset) & bitmsk),
			   timeout_ref);
}

void stm32mp_rcc_raw_setup_rng1(void)
{
	vaddr_t rng = (vaddr_t)phys_to_virt(RNG1_BASE, MEM_AREA_IO_SEC);
	vaddr_t rcc = stm32_rcc_base();
	uint64_t timeout_ref = timeout_init_us(RESET_TIMEOUT_US);

	assert(rng && rcc);

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
}
