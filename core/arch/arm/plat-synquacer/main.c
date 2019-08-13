// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018, Linaro Limited
 */

#include <arm.h>
#include <console.h>
#include <drivers/gic.h>
#include <drivers/pl011.h>
#include <io.h>
#include <kernel/generic_boot.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <kernel/pm_stubs.h>
#include <kernel/thread.h>
#include <kernel/timer.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <sm/optee_smc.h>
#include <tee/entry_fast.h>
#include <tee/entry_std.h>
#include <rng_pta.h>

static void main_fiq(void);

static const struct thread_handlers handlers = {
	.fast_smc = tee_entry_fast,
	.nintr = main_fiq,
	.cpu_on = cpu_on_handler,
	.cpu_off = pm_do_nothing,
	.cpu_suspend = pm_do_nothing,
	.cpu_resume = pm_do_nothing,
	.system_off = pm_do_nothing,
	.system_reset = pm_do_nothing,
};

static struct gic_data gic_data;
static struct pl011_data console_data;

register_phys_mem_pgdir(MEM_AREA_IO_NSEC, CONSOLE_UART_BASE,
			CORE_MMU_PGDIR_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, GIC_BASE, CORE_MMU_PGDIR_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, THERMAL_SENSOR_BASE,
			CORE_MMU_PGDIR_SIZE);

const struct thread_handlers *generic_boot_get_handlers(void)
{
	return &handlers;
}

static void main_fiq(void)
{
	gic_it_handle(&gic_data);
}

void console_init(void)
{
	pl011_init(&console_data, CONSOLE_UART_BASE, CONSOLE_UART_CLK_IN_HZ,
		   CONSOLE_BAUDRATE);
	register_serial_console(&console_data.chip);
}

void main_init_gic(void)
{
	vaddr_t gicd_base;

	gicd_base = (vaddr_t)phys_to_virt(GIC_BASE + GICD_OFFSET,
					  MEM_AREA_IO_SEC);

	if (!gicd_base)
		panic();

	/* On ARMv8-A, GIC configuration is initialized in TF-A */
	gic_init_base_addr(&gic_data, 0, gicd_base);

	itr_init(&gic_data.chip);
}

static enum itr_return timer_itr_cb(struct itr_handler *h __unused)
{
	/* Reset timer for next FIQ */
	generic_timer_handler(TIMER_PERIOD_MS);

	/* Collect entropy on each timer FIQ */
	rng_collect_entropy();

	return ITRR_HANDLED;
}

static struct itr_handler timer_itr = {
	.it = IT_SEC_TIMER,
	.flags = ITRF_TRIGGER_LEVEL,
	.handler = timer_itr_cb,
};

static TEE_Result init_timer_itr(void)
{
	itr_add(&timer_itr);
	itr_enable(IT_SEC_TIMER);

	/* Enable timer FIQ to fetch entropy required during boot */
	generic_timer_start(TIMER_PERIOD_MS);

	return TEE_SUCCESS;
}
driver_init(init_timer_itr);
