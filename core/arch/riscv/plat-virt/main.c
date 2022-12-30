// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022-2023 NXP
 */

#include <console.h>
#include <drivers/ns16550.h>
#include <kernel/boot.h>
#include <kernel/tee_common_otp.h>
#include <platform_config.h>
#include <plic.h>

static struct plic_data plic_data __nex_bss;
static struct ns16550_data console_data __nex_bss;

register_ddr(DRAM_BASE, DRAM_SIZE);

register_phys_mem_pgdir(MEM_AREA_IO_NSEC, UART0_BASE,
			CORE_MMU_PGDIR_SIZE);

#ifdef	CFG_RISCV_PLIC
void main_init_plic(void)
{
	plic_init(&plic_data, PLIC_BASE);
	itr_init(&plic_data.chip);
}

void main_secondary_init_plic(void)
{
	plic_hart_init(&plic_data);
}
#endif /* CFG_RISCV_PLIC */

void console_init(void)
{
	ns16550_init(&console_data, UART0_BASE, IO_WIDTH_U8, 0);
	register_serial_console(&console_data.chip);
}

void itr_core_handler(void)
{
	if (IS_ENABLED(CFG_RISCV_PLIC))
		plic_it_handle(&plic_data);
}
