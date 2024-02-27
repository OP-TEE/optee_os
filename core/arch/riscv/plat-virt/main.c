// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022-2023 NXP
 */

#include <console.h>
#include <drivers/ns16550.h>
#include <drivers/plic.h>
#include <kernel/boot.h>
#include <kernel/tee_common_otp.h>
#include <platform_config.h>

static struct ns16550_data console_data __nex_bss;

register_ddr(DRAM_BASE, DRAM_SIZE);

register_phys_mem_pgdir(MEM_AREA_IO_NSEC, UART0_BASE,
			CORE_MMU_PGDIR_SIZE);

#ifdef CFG_RISCV_PLIC
void boot_primary_init_intc(void)
{
	plic_init(PLIC_BASE);
}

void boot_secondary_init_intc(void)
{
	plic_hart_init();
}
#endif /* CFG_RISCV_PLIC */

void plat_console_init(void)
{
	ns16550_init(&console_data, UART0_BASE, IO_WIDTH_U8, 0);
	register_serial_console(&console_data.chip);
}

void interrupt_main_handler(void)
{
	if (IS_ENABLED(CFG_RISCV_PLIC))
		plic_it_handle();
}
