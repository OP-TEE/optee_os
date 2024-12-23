// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2024, Telechips Inc.
 */

#include <io.h>
#include <initcall.h>
#include <tee/tee_svc.h>
#include <kernel/interrupt.h>
#include <kernel/panic.h>
#include <drivers/tcc_omc.h>
#include <mm/core_mmu.h>
#include <mm/core_memprot.h>
#include <trace.h>

static void tzc_protect_teeos(void)
{
	struct tzc_region_config cfg = {
		.filters = (U(1) << TZC_OMC_FILTERS) - U(1),
		.base = CFG_TZDRAM_START - DRAM0_BASE,
		.top = (CFG_TZDRAM_START + CFG_TZDRAM_SIZE - U(1)) - DRAM0_BASE,
		.sec_attr = TZC_REGION_S_RDWR,
		.ns_device_access = U(0),
	};

	omc_configure_region(TZC_TEEOS_REGION_NUM, &cfg);
}

static enum itr_return tzc_it_handler(struct itr_handler *h)
{
	uint8_t filter;
	enum itr_return ret = ITRR_NONE;

	switch (h->it) {
	case TZC_OMC_INT_0:
		filter = U(0);
		break;
#if defined(TZC_OMC_INT_1)
	case TZC_OMC_INT_1:
		filter = U(1);
		break;
#endif
#if defined(TZC_OMC_INT_2)
	case TZC_OMC_INT_2:
		filter = U(2);
		break;
#endif
#if defined(TZC_OMC_INT_3)
	case TZC_OMC_INT_3:
		filter = U(3);
		break;
#endif
	default:
		filter = U(0xFF);
		break;
	}

	if (filter != U(0xFF)) {
		EMSG("OMC(%d) TZC permission failure", filter);
		omc_fail_dump(filter);
		omc_int_clear(filter);

		ret = ITRR_HANDLED;
	}

	return ret;
}

static struct itr_handler tzc_itr_handler[TZC_OMC_FILTERS] = {
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
	vaddr_t va;
	uint8_t filter;
	struct tzc_region_config cfg = {
		.filters = (U(1) << TZC_OMC_FILTERS) - U(1),
		.base = (vaddr_t)0,
		.top = U(0xFFFFFFFFFFFFFFFF),
		.sec_attr = TZC_REGION_S_RDWR,
		.ns_device_access = U(0xFFFFFFFF),
	};

	DMSG("Initializing TZC");

	va = (vaddr_t)phys_to_virt_io(TZC_OMC_BASE,
				       TZC_OMC_FILTERS * TZC_OMC_FILTER_OFFS);
	if (va == U(0))
		panic();

	omc_init(va, TZC_OMC_FILTER_OFFS, TZC_OMC_FILTERS);
	omc_configure_region(0, &cfg);
	tzc_protect_teeos();

	for (filter = 0; filter < TZC_OMC_FILTERS; filter++) {
		interrupt_add_handler_with_chip(interrupt_get_main_chip(),
						&tzc_itr_handler[filter]);
		interrupt_enable(interrupt_get_main_chip(),
				 tzc_itr_handler[filter].it);
	}
	omc_set_action(TZC_ACTION_INT);

	return TEE_SUCCESS;
}
service_init(tzc_configure);
