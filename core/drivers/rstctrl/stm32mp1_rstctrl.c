// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021-2022, Linaro Limited
 * Copyright (c) 2018-2024, STMicroelectronics
 */

#include <arm.h>
#include <drivers/rstctrl.h>
#include <drivers/stm32mp1_rcc.h>
#include <drivers/stm32mp_dt_bindings.h>
#include <io.h>
#include <keep.h>
#include <kernel/dt.h>
#include <kernel/dt_driver.h>
#include <stm32_util.h>

#include "stm32_rstctrl.h"

#define RESET_ID_MASK		GENMASK_32(31, 5)
#define RESET_ID_SHIFT		U(5)
#define RESET_BIT_POS_MASK	GENMASK_32(4, 0)
#define RESET_OFFSET_MAX	U(1024)

static size_t reset_id2reg_offset(unsigned int id)
{
	size_t offset = (id & RESET_ID_MASK) >> RESET_ID_SHIFT;

	assert(offset < RESET_OFFSET_MAX);
	return offset * sizeof(uint32_t);
}

static uint32_t reset_id2reg_bit_pos(unsigned int reset_id)
{
	uint32_t pos = reset_id & RESET_BIT_POS_MASK;

	assert(pos < 32);
	return pos;
}

static TEE_Result reset_assert(struct rstctrl *rstctrl, unsigned int to_us)
{
	unsigned int id = to_stm32_rstline(rstctrl)->id;
	vaddr_t rcc_base = stm32_rcc_base();
	uint32_t bit_mask = 0;
	size_t offset = 0;

#ifdef CFG_STM32MP15
	switch (id) {
	case MCU_HOLD_BOOT_R:
		/*
		 * The RCC_MP_GCR is a read/write register.
		 * Assert the MCU HOLD_BOOT means clear the BOOT_MCU bit
		 */
		io_clrbits32(rcc_base + RCC_MP_GCR, RCC_MP_GCR_BOOT_MCU);

		return TEE_SUCCESS;
	case MCU_R:
		/* MCU reset can only be written */
		to_us = 0;
		break;
	default:
		break;
	}
#endif

	offset = reset_id2reg_offset(id);
	bit_mask = BIT(reset_id2reg_bit_pos(id));

	io_write32(rcc_base + offset, bit_mask);

	if (to_us) {
		uint32_t value = 0;

		if (IO_READ32_POLL_TIMEOUT(rcc_base + offset, value,
					   value & bit_mask, 0, to_us))
			return TEE_ERROR_GENERIC;
	} else {
		/* Make sure the above write is performed */
		dsb();
	}

	return TEE_SUCCESS;
}

static TEE_Result reset_deassert(struct rstctrl *rstctrl, unsigned int to_us)
{
	unsigned int id = to_stm32_rstline(rstctrl)->id;
	vaddr_t rcc_base = stm32_rcc_base();
	uint32_t bit_mask = 0;
	size_t offset = 0;

#ifdef CFG_STM32MP15
	switch (id) {
	case MCU_HOLD_BOOT_R:
		/*
		 * The RCC_MP_GCR is a read/write register.
		 * Deassert the MCU HOLD_BOOT means set the BOOT_MCU the bit
		 */
		io_setbits32(rcc_base + RCC_MP_GCR, RCC_MP_GCR_BOOT_MCU);

		return TEE_SUCCESS;
	case MCU_R:
		/* MCU reset deasserts by its own */
		return TEE_SUCCESS;
	default:
		break;
	}
#endif

	offset = reset_id2reg_offset(id) + RCC_MP_RSTCLRR_OFFSET;
	bit_mask = BIT(reset_id2reg_bit_pos(id));

	io_write32(rcc_base + offset, bit_mask);

	if (to_us) {
		uint32_t value = 0;

		if (IO_READ32_POLL_TIMEOUT(rcc_base + offset, value,
					   !(value & bit_mask), 0, to_us))
			return TEE_ERROR_GENERIC;
	} else {
		/* Make sure the above write is performed */
		dsb();
	}

	return TEE_SUCCESS;
}

static const struct rstctrl_ops stm32_rstctrl_ops = {
	.assert_level = reset_assert,
	.deassert_level = reset_deassert,
};
DECLARE_KEEP_PAGER(stm32_rstctrl_ops);

static const struct rstctrl_ops *stm32_reset_get_ops(unsigned int id __unused)
{
	return &stm32_rstctrl_ops;
}

static const struct stm32_reset_data stm32mp1_reset_data = {
	.get_rstctrl_ops = stm32_reset_get_ops
};
DECLARE_KEEP_PAGER(stm32mp1_reset_data);

static const struct dt_device_match stm32_rstctrl_match_table[] = {
	{
		.compatible = "st,stm32mp1-rcc",
		.compat_data = &stm32mp1_reset_data,
	},
	{
		.compatible = "st,stm32mp1-rcc-secure",
		.compat_data = &stm32mp1_reset_data,
	},
	{
		.compatible = "st,stm32mp13-rcc",
		.compat_data = &stm32mp1_reset_data,
	},
	{ }
};

DEFINE_DT_DRIVER(stm32_rstctrl_dt_driver) = {
	.name = "stm32_rstctrl",
	.type = DT_DRIVER_RSTCTRL,
	.match_table = stm32_rstctrl_match_table,
	.probe = stm32_rstctrl_provider_probe,
};
