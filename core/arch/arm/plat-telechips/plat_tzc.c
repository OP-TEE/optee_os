// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2024, Telechips Inc.
 */

#include <drivers/openedges_omc.h>
#include <initcall.h>
#include <kernel/interrupt.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <trace.h>

#define NSEC_ALL_ACCESS   UINT32_MAX

static void tzc_protect_teeos(void)
{
	struct omc_region_config cfg = {
		.filters = GENMASK_32(TZC_OMC_FILTERS - 1, 0),
		.base = CFG_TZDRAM_START - DRAM0_BASE,
		.top = (CFG_TZDRAM_START + CFG_TZDRAM_SIZE - 1) - DRAM0_BASE,
		.ns_device_access = 0,
		.flags = OMC_FLAG_RELATIVE_ADDR,
	};

	omc_configure_region(TZC_TEEOS_REGION_NUM, &cfg);
}

static enum itr_return tzc_it_handler(struct itr_handler *h)
{
	uint8_t filter = UINT8_MAX;
	enum itr_return ret = ITRR_NONE;

	switch (h->it) {
	case TZC_OMC_INT_0:
		filter = 0;
		break;
#if defined(TZC_OMC_INT_1)
	case TZC_OMC_INT_1:
		filter = 1;
		break;
#endif
#if defined(TZC_OMC_INT_2)
	case TZC_OMC_INT_2:
		filter = 2;
		break;
#endif
#if defined(TZC_OMC_INT_3)
	case TZC_OMC_INT_3:
		filter = 3;
		break;
#endif
	default:
		break;
	}

	if (filter != UINT8_MAX) {
		EMSG("OMC(%"PRIu8") TZC permission failure", filter);
		omc_fail_dump(filter);
		omc_int_clear(filter);

		ret = ITRR_HANDLED;
	}

	return ret;
}

static struct itr_handler tzc_itr_handler[] = {
	{
		.it = TZC_OMC_INT_0,
		.handler = tzc_it_handler,
	},
#if defined(TZC_OMC_INT_1)
	{
		.it = TZC_OMC_INT_1,
		.handler = tzc_it_handler,
	},
#endif
#if defined(TZC_OMC_INT_2)
	{
		.it = TZC_OMC_INT_2,
		.handler = tzc_it_handler,
	},
#endif
#if defined(TZC_OMC_INT_3)
	{
		.it = TZC_OMC_INT_3,
		.handler = tzc_it_handler,
	},
#endif
};

static TEE_Result tzc_configure(void)
{
	vaddr_t va = 0;
	uint8_t filter = 0;
	struct omc_region_config cfg = {
		.filters = GENMASK_32(TZC_OMC_FILTERS - 1, 0),
		.base = 0,
		.top = UINT64_MAX,
		.ns_device_access = NSEC_ALL_ACCESS,
		.flags = 0,
	};

	DMSG("Initializing TZC");

	va = (vaddr_t)phys_to_virt_io(TZC_OMC_BASE,
				      TZC_OMC_FILTERS * TZC_OMC_FILTER_OFFS);
	if (!va)
		panic();

	omc_init(va, TZC_OMC_FILTER_OFFS, TZC_OMC_FILTERS);
	omc_configure_region(0, &cfg);
	tzc_protect_teeos();

	for (filter = 0; filter < ARRAY_SIZE(tzc_itr_handler); filter++) {
		interrupt_add_handler_with_chip(interrupt_get_main_chip(),
						&tzc_itr_handler[filter]);
		interrupt_enable(interrupt_get_main_chip(),
				 tzc_itr_handler[filter].it);
	}
	omc_set_action(OMC_ACTION_INT);

	return TEE_SUCCESS;
}
service_init(tzc_configure);
