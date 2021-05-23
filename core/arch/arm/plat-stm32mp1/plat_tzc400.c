// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019-2020, STMicroelectronics
 */

#include <assert.h>
#include <config.h>
#include <drivers/tzc400.h>
#include <initcall.h>
#include <kernel/interrupt.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <trace.h>
#include <util.h>

static enum itr_return tzc_it_handler(struct itr_handler *handler __unused)
{
	EMSG("TZC permission failure");
	tzc_fail_dump();

	if (IS_ENABLED(CFG_STM32MP_PANIC_ON_TZC_PERM_VIOLATION))
		panic();
	else
		tzc_int_clear();

	return ITRR_HANDLED;
}

static struct itr_handler tzc_itr_handler = {
	.it = STM32MP1_IRQ_TZC,
	.handler = tzc_it_handler,
};
DECLARE_KEEP_PAGER(tzc_itr_handler);

static bool tzc_region_is_non_secure(unsigned int i, vaddr_t base, size_t size)
{
	struct tzc_region_config region_cfg = { };
	uint32_t ns_cpu_mask = TZC_REGION_ACCESS_RDWR(STM32MP1_TZC_A7_ID);
	uint32_t filters_mask = GENMASK_32(1, 0);

	if (tzc_get_region_config(i, &region_cfg))
		panic();

	return region_cfg.base == base && region_cfg.top == (base + size - 1) &&
	       region_cfg.sec_attr == TZC_REGION_S_NONE &&
	       (region_cfg.ns_device_access & ns_cpu_mask) == ns_cpu_mask &&
	       region_cfg.filters == filters_mask;
}

static bool tzc_region_is_secure(unsigned int i, vaddr_t base, size_t size)
{
	struct tzc_region_config region_cfg = { };
	uint32_t filters_mask = GENMASK_32(1, 0);

	if (tzc_get_region_config(i, &region_cfg))
		panic();

	return region_cfg.base == base && region_cfg.top == (base + size - 1) &&
	       region_cfg.sec_attr == TZC_REGION_S_RDWR &&
	       region_cfg.ns_device_access == 0 &&
	       region_cfg.filters == filters_mask;
}

static TEE_Result init_stm32mp1_tzc(void)
{
	void *base = phys_to_virt(TZC_BASE, MEM_AREA_IO_SEC, 1);
	unsigned int region_index = 1;
	const uint64_t dram_start = DDR_BASE;
	const uint64_t dram_end = dram_start + CFG_DRAM_SIZE;
	const uint64_t tzdram_start = CFG_TZDRAM_START;
	const uint64_t tzdram_size = CFG_TZDRAM_SIZE;
	const uint64_t tzdram_end = tzdram_start + tzdram_size;

	assert(base);

	tzc_init((vaddr_t)base);
	tzc_dump_state();

	/*
	 * Early boot stage is in charge of configuring memory regions
	 * OP-TEE hence here only check this complies with static Core
	 * expectations.
	 */
	if (dram_start < tzdram_start) {
		if (!tzc_region_is_non_secure(region_index, dram_start,
					      tzdram_start - dram_start))
			panic("Unexpected TZC area on non-secure region");

		region_index++;
	}

	if (!tzc_region_is_secure(region_index, tzdram_start, tzdram_size))
		panic("Unexpected TZC configuration on secure region");

	if (tzdram_end < dram_end) {
		region_index++;

		if (!tzc_region_is_non_secure(region_index, tzdram_end,
					      dram_end - tzdram_end))
			panic("Unexpected TZC area on non-secure region");
	}

	itr_add(&tzc_itr_handler);
	itr_enable(tzc_itr_handler.it);
	tzc_set_action(TZC_ACTION_INT);

	return TEE_SUCCESS;
}
driver_init(init_stm32mp1_tzc);
