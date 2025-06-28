// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2025 NXP
 */

#include <console.h>
#include <drivers/ns16550.h>
#include <drivers/plic.h>
#include <kernel/boot.h>
#include <platform_config.h>

#ifdef CFG_16550_UART
static struct ns16550_data console_data __nex_bss;
register_phys_mem_pgdir(MEM_AREA_IO_NSEC, UART0_BASE, NS16550_UART_REG_SIZE);
#endif

register_ddr(DRAM_BASE, DRAM_SIZE);

#ifdef CFG_RISCV_PLIC
void boot_primary_init_intc(void)
{
	plic_init(PLIC_BASE);
}
#endif /* CFG_RISCV_PLIC */

#ifdef CFG_16550_UART
void plat_console_init(void)
{
	ns16550_init(&console_data, UART0_BASE, IO_WIDTH_U32, 2);
	register_serial_console(&console_data.chip);
}
#endif

void interrupt_main_handler(void)
{
	if (IS_ENABLED(CFG_RISCV_PLIC))
		plic_it_handle();
}
