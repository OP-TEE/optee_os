// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017-2018, STMicroelectronics
 * Copyright (c) 2016-2018, Linaro Limited
 */

#include <boot_api.h>
#include <console.h>
#include <drivers/gic.h>
#include <drivers/stm32_uart.h>
#include <kernel/generic_boot.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <kernel/pm_stubs.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <sm/psci.h>
#include <tee/entry_std.h>
#include <tee/entry_fast.h>
#include <trace.h>

register_phys_mem(MEM_AREA_IO_NSEC, CONSOLE_UART_BASE, CONSOLE_UART_SIZE);

register_phys_mem(MEM_AREA_IO_SEC, GIC_BASE, GIC_SIZE);
register_phys_mem(MEM_AREA_IO_SEC, BKP_REGS_BASE, SMALL_PAGE_SIZE);

static struct gic_data gic_data;
static struct console_pdata console_data;

static void main_fiq(void)
{
	gic_it_handle(&gic_data);
}

static const struct thread_handlers handlers = {
	.std_smc = tee_entry_std,
	.fast_smc = tee_entry_fast,
	.nintr = main_fiq,
	.cpu_on = pm_panic,
	.cpu_off = pm_panic,
	.cpu_suspend = pm_panic,
	.cpu_resume = pm_panic,
	.system_off = pm_panic,
	.system_reset = pm_panic,
};

const struct thread_handlers *generic_boot_get_handlers(void)
{
	return &handlers;
}

#define _ID2STR(id)		(#id)
#define ID2STR(id)		_ID2STR(id)

static TEE_Result platform_banner(void)
{
#ifdef CFG_EMBED_DTB
	IMSG("Platform stm32mp1: flavor %s - DT %s",
		ID2STR(PLATFORM_FLAVOR),
		ID2STR(CFG_EMBED_DTB_SOURCE_FILE));
#else
	IMSG("Platform stm32mp1: flavor %s - no device tree",
		ID2STR(PLATFORM_FLAVOR));
#endif

	return TEE_SUCCESS;
}
service_init(platform_banner);

void console_init(void)
{
	stm32_uart_init(&console_data, CONSOLE_UART_BASE);
	register_serial_console(&console_data.chip);
}

void main_init_gic(void)
{
	void *gicc_base;
	void *gicd_base;

	gicc_base = phys_to_virt(GIC_BASE + GICC_OFFSET, MEM_AREA_IO_SEC);
	gicd_base = phys_to_virt(GIC_BASE + GICD_OFFSET, MEM_AREA_IO_SEC);
	if (!gicc_base || !gicd_base)
		panic();

	gic_init(&gic_data, (vaddr_t)gicc_base, (vaddr_t)gicd_base);
	itr_init(&gic_data.chip);
}

void main_secondary_init_gic(void)
{
	gic_cpu_init(&gic_data);
}
