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
#include <tee_api_defines.h>

#define RESET_ID_MASK		GENMASK_32(31, 5)
#define RESET_ID_SHIFT		5
#define RESET_BIT_POS_MASK	GENMASK_32(4, 0)

vaddr_t stm32_rcc_base(void)
{
	static struct io_pa_va base = { .pa = RCC_BASE };

	return io_pa_or_va_secure(&base, 1);
}

static size_t reset_id2reg_offset(unsigned int id)
{
	return ((id & RESET_ID_MASK) >> RESET_ID_SHIFT) * sizeof(uint32_t);
}

static uint8_t reset_id2reg_bit_pos(unsigned int reset_id)
{
	return reset_id & RESET_BIT_POS_MASK;
}

TEE_Result stm32_reset_assert(unsigned int id, unsigned int to_us)
{
	size_t offset = reset_id2reg_offset(id);
	uint32_t bitmsk = BIT(reset_id2reg_bit_pos(id));
	vaddr_t rcc_base = stm32_rcc_base();

	io_write32(rcc_base + offset, bitmsk);

	if (to_us) {
		uint64_t timeout_ref = timeout_init_us(to_us);

		while (!(io_read32(rcc_base + offset) & bitmsk))
			if (timeout_elapsed(timeout_ref))
				break;

		if (!(io_read32(rcc_base + offset) & bitmsk))
			return TEE_ERROR_SECURITY;
	}

	return TEE_SUCCESS;
}

TEE_Result stm32_reset_deassert(unsigned int id, unsigned int to_us)
{
	size_t offset = reset_id2reg_offset(id) + RCC_MP_RSTCLRR_OFFSET;
	uint32_t bitmsk = BIT(reset_id2reg_bit_pos(id));
	vaddr_t rcc_base = stm32_rcc_base();

	io_write32(rcc_base + offset, bitmsk);

	if (to_us) {
		uint64_t timeout_ref = timeout_init_us(to_us);

		while ((io_read32(rcc_base + offset) & bitmsk))
			if (timeout_elapsed(timeout_ref))
				break;

		if (io_read32(rcc_base + offset) & bitmsk)
			return TEE_ERROR_SECURITY;
	}

	return TEE_SUCCESS;
}

void stm32_reset_assert_deassert_mcu(bool assert_not_deassert)
{
	vaddr_t rcc_base = stm32_rcc_base();

	/*
	 * The RCC_MP_GCR is a read/write register.
	 * Assert the MCU HOLD_BOOT means clear the BOOT_MCU bit
	 * Deassert the MCU HOLD_BOOT means set the BOOT_MCU the bit
	 */
	if (assert_not_deassert)
		io_clrbits32(rcc_base + RCC_MP_GCR, RCC_MP_GCR_BOOT_MCU);
	else
		io_setbits32(rcc_base + RCC_MP_GCR, RCC_MP_GCR_BOOT_MCU);
}
