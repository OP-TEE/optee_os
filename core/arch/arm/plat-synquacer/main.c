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
#include <sm/optee_smc.h>

#include "synquacer_rng_pta.h"

static struct pl011_data console_data;

register_phys_mem_pgdir(MEM_AREA_IO_NSEC, CONSOLE_UART_BASE,
			CORE_MMU_PGDIR_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, GIC_BASE, CORE_MMU_PGDIR_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, THERMAL_SENSOR_BASE,
			CORE_MMU_PGDIR_SIZE);

void plat_console_init(void)
{
	pl011_init(&console_data, CONSOLE_UART_BASE, CONSOLE_UART_CLK_IN_HZ,
		   CONSOLE_BAUDRATE);
	register_serial_console(&console_data.chip);
}

void boot_primary_init_intc(void)
{
	gic_init(0, GIC_BASE + GICD_OFFSET);
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
	if (interrupt_add_handler_with_chip(interrupt_get_main_chip(),
					    &timer_itr))
		panic();

	interrupt_enable(timer_itr.chip, timer_itr.it);

	/* Enable timer FIQ to fetch entropy required during boot */
	generic_timer_start(TIMER_PERIOD_MS);

	return TEE_SUCCESS;
}
driver_init(init_timer_itr);
