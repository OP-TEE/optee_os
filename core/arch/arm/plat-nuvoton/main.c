/*
 * Copyright (c) 2016-2023, Linaro Limited
 *
 * Copyright (c) 2014-2023, STMicroelectronics International N.V.
 *
 * Copyright (C) 2022-2023 Nuvoton Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <arm.h>
#include <console.h>
#include <drivers/gic.h>
#include <drivers/ns16550.h>
#include <drivers/tzc400.h>
#include <initcall.h>
#include <keep.h>
#include <kernel/boot.h>
#include <kernel/interrupt.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <kernel/tee_time.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <npcm845x_utils.h>
#include <platform_config.h>
#include <sm/psci.h>
#include <stdint.h>
#include <string.h>
#include <trace.h>

static struct gic_data gic_data __nex_bss;
static struct ns16550_data console_data __nex_bss;

register_phys_mem_pgdir(MEM_AREA_IO_SEC, CONSOLE_UART_BASE, UART_REG_SIZE);

#ifdef DRAM0_BASE
register_ddr(DRAM0_BASE, DRAM0_SIZE);
#endif /* DRAM0_BASE */

#ifdef DRAM1_BASE
register_ddr(DRAM1_BASE, DRAM1_SIZE);
#endif /* DRAM1_BASE */

#ifdef GIC_BASE
register_phys_mem_pgdir(MEM_AREA_IO_SEC, GICD_BASE, GIC_DIST_REG_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, GICC_BASE, GIC_DIST_REG_SIZE);

void main_init_gic(void)
{
print_version();
#if defined(CFG_WITH_ARM_TRUSTED_FW)
	/* On ARMv8, GIC configuration is initialized in ARM-TF */
	gic_init_base_addr(&gic_data, GIC_BASE + GICC_OFFSET,
			GIC_BASE + GICD_OFFSET);
#else
	/* Initialize GIC */
	gic_init(&gic_data, GIC_BASE + GICC_OFFSET, GIC_BASE + GICD_OFFSET);
#endif
	itr_init(&gic_data.chip);
}

#if !defined(CFG_WITH_ARM_TRUSTED_FW)
void main_secondary_init_gic(void)
{
	gic_cpu_init(&gic_data);
}
#endif

#endif

void itr_core_handler(void)
{
	gic_it_handle(&gic_data);
}

void console_init(void)
{
	ns16550_init(&console_data, CONSOLE_UART_BASE, IO_WIDTH_U32, 2);
	register_serial_console(&console_data.chip);
}
