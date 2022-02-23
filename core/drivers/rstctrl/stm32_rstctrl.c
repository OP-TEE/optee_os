// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021-2022, Linaro Limited
 * Copyright (c) 2018-2022, STMicroelectronics
 */

#include <drivers/rstctrl.h>
#include <drivers/stm32mp1_rcc.h>
#include <dt-bindings/reset/stm32mp1-resets.h>
#include <io.h>
#include <kernel/delay.h>
#include <kernel/dt.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <stm32_util.h>

#define RESET_ID_MASK		GENMASK_32(31, 5)
#define RESET_ID_SHIFT		5
#define RESET_BIT_POS_MASK	GENMASK_32(4, 0)
#define RESET_OFFSET_MAX	1024

/* Exposed rstctrl instance */
struct stm32_rstline {
	unsigned int id;
	struct rstctrl rstctrl;
	SLIST_ENTRY(stm32_rstline) link;
};

static SLIST_HEAD(, stm32_rstline) stm32_rst_list =
	SLIST_HEAD_INITIALIZER(stm32_rst_list);

static size_t reset_id2reg_offset(unsigned int id)
{
	size_t offset = (id & RESET_ID_MASK) >> RESET_ID_SHIFT;

	assert(offset < RESET_OFFSET_MAX);
	return offset * sizeof(uint32_t);
}

static uint8_t reset_id2reg_bit_pos(unsigned int reset_id)
{
	uint8_t pos = reset_id & RESET_BIT_POS_MASK;

	assert(pos < 32);
	return pos;
}

static struct stm32_rstline *to_rstline(struct rstctrl *rstctrl)
{
	assert(rstctrl);

	return container_of(rstctrl, struct stm32_rstline, rstctrl);
}

static TEE_Result reset_assert(struct rstctrl *rstctrl, unsigned int to_us)
{
	unsigned int id = to_rstline(rstctrl)->id;
	vaddr_t rcc_base = stm32_rcc_base();
	uint32_t bit_mask = 0;
	size_t offset = 0;

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

	offset = reset_id2reg_offset(id);
	bit_mask = BIT(reset_id2reg_bit_pos(id));

	io_write32(rcc_base + offset, bit_mask);

	if (to_us) {
		uint64_t timeout_ref = timeout_init_us(to_us);

		while (!(io_read32(rcc_base + offset) & bit_mask))
			if (timeout_elapsed(timeout_ref))
				break;

		if (!(io_read32(rcc_base + offset) & bit_mask))
			return TEE_ERROR_SECURITY;
	}

	return TEE_SUCCESS;
}

static TEE_Result reset_deassert(struct rstctrl *rstctrl, unsigned int to_us)
{
	unsigned int id = to_rstline(rstctrl)->id;
	vaddr_t rcc_base = stm32_rcc_base();
	uint32_t bit_mask = 0;
	size_t offset = 0;

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

	offset = reset_id2reg_offset(id) + RCC_MP_RSTCLRR_OFFSET;
	bit_mask = BIT(reset_id2reg_bit_pos(id));

	io_write32(rcc_base + offset, bit_mask);

	if (to_us) {
		uint64_t timeout_ref = timeout_init_us(to_us);

		while ((io_read32(rcc_base + offset) & bit_mask))
			if (timeout_elapsed(timeout_ref))
				break;

		if (io_read32(rcc_base + offset) & bit_mask)
			return TEE_ERROR_SECURITY;
	}

	return TEE_SUCCESS;
}

static struct rstctrl_ops stm32_rstctrl_ops = {
	.assert_level = reset_assert,
	.deassert_level = reset_deassert,
};

static struct stm32_rstline *find_rstctrl_device(unsigned int control_id)
{
	struct stm32_rstline *stm32_rstline = NULL;

	SLIST_FOREACH(stm32_rstline, &stm32_rst_list, link)
		if (stm32_rstline->id == control_id)
			break;

	return stm32_rstline;
}

static struct stm32_rstline *find_or_allocate_rstline(unsigned int binding_id)
{
	struct stm32_rstline *stm32_rstline = find_rstctrl_device(binding_id);

	if (stm32_rstline)
		return stm32_rstline;

	stm32_rstline = calloc(1, sizeof(*stm32_rstline));
	if (stm32_rstline) {
		stm32_rstline->rstctrl.ops = &stm32_rstctrl_ops;
		stm32_rstline->id = binding_id;
		SLIST_INSERT_HEAD(&stm32_rst_list, stm32_rstline, link);
	}

	return stm32_rstline;
}

struct rstctrl *stm32mp_rcc_reset_id_to_rstctrl(unsigned int binding_id)
{
	struct stm32_rstline *rstline = find_or_allocate_rstline(binding_id);

	assert(rstline);
	return &rstline->rstctrl;
}

#ifdef CFG_EMBED_DTB
static struct rstctrl *stm32_rstctrl_get_dev(struct dt_driver_phandle_args *arg,
					     void *priv_data __unused,
					     TEE_Result *res)
{
	struct stm32_rstline *stm32_rstline = NULL;
	uintptr_t control_id = 0;

	if (arg->args_count != 1) {
		*res = TEE_ERROR_BAD_PARAMETERS;
		return NULL;
	}
	control_id = arg->args[0];

	stm32_rstline = find_or_allocate_rstline(control_id);
	if (!stm32_rstline) {
		*res = TEE_ERROR_OUT_OF_MEMORY;
		return NULL;
	}

	*res = TEE_SUCCESS;
	return &stm32_rstline->rstctrl;
}

static TEE_Result stm32_rstctrl_provider_probe(const void *fdt, int offs,
					       const void *compat_data __unused)
{
	struct dt_node_info info = { };

	assert(rstctrl_ops_is_valid(&stm32_rstctrl_ops));

	_fdt_fill_device_info(fdt, &info, offs);

	assert(info.reg == RCC_BASE &&
	       info.reg_size != DT_INFO_INVALID_REG_SIZE);

	return rstctrl_register_provider(fdt, offs, stm32_rstctrl_get_dev,
					 NULL);
}

static const struct dt_device_match stm32_rstctrl_match_table[] = {
	{ .compatible = "st,stm32mp1-rcc" },
	{ .compatible = "st,stm32mp1-rcc-secure" },
	{ }
};

DEFINE_DT_DRIVER(stm32_rstctrl_dt_driver) = {
	.name = "stm32_rstctrl",
	.type = DT_DRIVER_RSTCTRL,
	.match_table = stm32_rstctrl_match_table,
	.probe = stm32_rstctrl_provider_probe,
};
#endif /*CFG_EMBED_DTB*/
