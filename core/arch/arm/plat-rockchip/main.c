// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2017, Fuzhou Rockchip Electronics Co., Ltd.
 * Copyright (C) 2019, Theobroma Systems Design und Consulting GmbH
 */

#include <console.h>
#include <drivers/gic.h>
#include <drivers/serial8250_uart.h>
#include <io.h>
#include <kernel/boot.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <stdint.h>

#if defined(CFG_EARLY_CONSOLE)
static struct serial8250_uart_data early_console_data;
#if defined(PLATFORM_FLAVOR_rk3506) || defined(PLATFORM_FLAVOR_rv1106)
/*
 * rk3506 / rv1106: map the early console UART secure (NS=0), not IO_NSEC.
 * The system firewall rejects a secure master issuing a non-secure access
 * to the UART once the MMU is enabled (sync external abort), so the
 * post-MMU mapping must keep the same secure attribute as the working
 * pre-MMU access. OP-TEE owns the debug UART during bring-up, so a
 * secure mapping is appropriate.
 */
register_phys_mem_pgdir(MEM_AREA_IO_SEC,
			CFG_EARLY_CONSOLE_BASE, CFG_EARLY_CONSOLE_SIZE);
#else
register_phys_mem_pgdir(MEM_AREA_IO_NSEC,
			CFG_EARLY_CONSOLE_BASE, CFG_EARLY_CONSOLE_SIZE);
#endif
#endif

#ifdef CFG_DRAM_BASE
register_ddr(CFG_DRAM_BASE, CFG_DRAM_SIZE);
#endif
#ifdef CFG_NSEC_DDR_1_BASE
register_ddr(CFG_NSEC_DDR_1_BASE, CFG_NSEC_DDR_1_SIZE);
#endif

register_phys_mem_pgdir(MEM_AREA_IO_SEC, GIC_BASE, GIC_SIZE);

void boot_primary_init_intc(void)
{
	gic_init(GICC_BASE, GICD_BASE);
}

void boot_secondary_init_intc(void)
{
	gic_init_per_cpu();
}

void plat_console_init(void)
{
#if defined(CFG_EARLY_CONSOLE)
	/*
	 * Console devices can vary a lot between devices and
	 * OP-TEE will switch to the DT-based real console later,
	 * based on DT-devices and the systems chosen node.
	 * So early console is only needed for early debugging.
	 */
	serial8250_uart_init(&early_console_data,
			     CFG_EARLY_CONSOLE_BASE,
			     CFG_EARLY_CONSOLE_CLK_IN_HZ,
			     CFG_EARLY_CONSOLE_BAUDRATE);
	register_serial_console(&early_console_data.chip);
#endif
}
