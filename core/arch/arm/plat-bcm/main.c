// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2019 Broadcom.
 */

#include <bcm_elog.h>
#include <console.h>
#include <drivers/gic.h>
#include <drivers/serial8250_uart.h>
#include <kernel/boot.h>
#include <kernel/interrupt.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <mm/tee_pager.h>
#include <platform_config.h>
#include <stdint.h>

static struct gic_data gic_data;
struct serial8250_uart_data console_data;

#ifdef BCM_DEVICE0_BASE
register_phys_mem_pgdir(MEM_AREA_IO_SEC, BCM_DEVICE0_BASE, BCM_DEVICE0_SIZE);
#endif
#ifdef BCM_DEVICE1_BASE
register_phys_mem_pgdir(MEM_AREA_IO_SEC, BCM_DEVICE1_BASE, BCM_DEVICE1_SIZE);
#endif
#ifdef BCM_DEVICE2_BASE
register_phys_mem_pgdir(MEM_AREA_IO_SEC, BCM_DEVICE2_BASE, BCM_DEVICE2_SIZE);
#endif
#ifdef BCM_DEVICE3_BASE
register_phys_mem_pgdir(MEM_AREA_IO_SEC, BCM_DEVICE3_BASE, BCM_DEVICE3_SIZE);
#endif
#ifdef BCM_DEVICE4_BASE
register_phys_mem_pgdir(MEM_AREA_IO_SEC, BCM_DEVICE4_BASE, BCM_DEVICE4_SIZE);
#endif
#ifdef BCM_DEVICE5_BASE
register_phys_mem_pgdir(MEM_AREA_IO_NSEC, BCM_DEVICE5_BASE, BCM_DEVICE5_SIZE);
#endif
#ifdef BCM_DRAM0_NS_BASE
register_dynamic_shm(BCM_DRAM0_NS_BASE, BCM_DRAM0_NS_SIZE);
#endif
#ifdef BCM_DRAM1_NS_BASE
register_dynamic_shm(BCM_DRAM1_NS_BASE, BCM_DRAM1_NS_SIZE);
#endif
#ifdef BCM_DRAM2_NS_BASE
register_dynamic_shm(BCM_DRAM2_NS_BASE, BCM_DRAM2_NS_SIZE);
#endif
#ifdef BCM_DRAM0_SEC_BASE
register_phys_mem(MEM_AREA_RAM_SEC, BCM_DRAM0_SEC_BASE, BCM_DRAM0_SEC_SIZE);
#endif
#ifdef CFG_BCM_ELOG_AP_UART_LOG_BASE
register_phys_mem(MEM_AREA_IO_NSEC, CFG_BCM_ELOG_AP_UART_LOG_BASE,
		  CFG_BCM_ELOG_AP_UART_LOG_SIZE);
#endif
#ifdef CFG_BCM_ELOG_BASE
register_phys_mem(MEM_AREA_RAM_NSEC, CFG_BCM_ELOG_BASE, CFG_BCM_ELOG_SIZE);
#endif

void plat_trace_ext_puts(const char *str)
{
	const char *p;

	for (p = str; *p; p++)
		bcm_elog_putchar(*p);
}

void console_init(void)
{
	serial8250_uart_init(&console_data, CONSOLE_UART_BASE,
			     CONSOLE_UART_CLK_IN_HZ, CONSOLE_BAUDRATE);
	register_serial_console(&console_data.chip);

	bcm_elog_init(CFG_BCM_ELOG_AP_UART_LOG_BASE,
		      CFG_BCM_ELOG_AP_UART_LOG_SIZE);
}

void itr_core_handler(void)
{
	gic_it_handle(&gic_data);
}

void main_init_gic(void)
{
	vaddr_t gicd_base;

	gicd_base = core_mmu_get_va(GICD_BASE, MEM_AREA_IO_SEC, 1);

	if (!gicd_base)
		panic();

	gic_init_base_addr(&gic_data, 0, gicd_base);
	itr_init(&gic_data.chip);

}
