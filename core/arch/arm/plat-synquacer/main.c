// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018, Linaro Limited
 */

#include <arm.h>
#include <console.h>
#include <drivers/gic.h>
#include <drivers/pl011.h>
#include <io.h>
#include <kernel/boot.h>
#include <kernel/interrupt.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <kernel/thread.h>
#include <kernel/timer.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <rng_pta.h>
#include <sm/optee_smc.h>

static struct gic_data gic_data;
static struct pl011_data console_data;

register_phys_mem_pgdir(MEM_AREA_IO_NSEC, CONSOLE_UART_BASE,
			CORE_MMU_PGDIR_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, GIC_BASE, CORE_MMU_PGDIR_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, THERMAL_SENSOR_BASE,
			CORE_MMU_PGDIR_SIZE);

void itr_core_handler(void)
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
					  MEM_AREA_IO_SEC, 1);

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
