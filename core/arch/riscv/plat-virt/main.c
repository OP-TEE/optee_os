// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022-2023 NXP
 */

#include <console.h>
#include <drivers/aplic.h>
#include <drivers/imsic.h>
#include <drivers/ns16550.h>
#include <drivers/plic.h>
#include <kernel/boot.h>
#include <kernel/tee_common_otp.h>
#include <platform_config.h>

#ifdef CFG_16550_UART
static struct ns16550_data console_data __nex_bss;
register_phys_mem_pgdir(MEM_AREA_IO_NSEC, UART0_BASE, CORE_MMU_PGDIR_SIZE);
#endif

register_ddr(DRAM_BASE, DRAM_SIZE);

#if defined(CFG_RISCV_APLIC) || defined(CFG_RISCV_APLIC_MSI)
register_phys_mem_pgdir(MEM_AREA_IO_SEC, APLIC_BASE,
			APLIC_SIZE);
#endif
#if defined(CFG_RISCV_APLIC_MSI) && defined(CFG_RISCV_IMSIC)
register_phys_mem_pgdir(MEM_AREA_IO_SEC, IMSIC_BASE,
			IMSIC_SIZE);
#endif

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

#ifdef CFG_RISCV_APLIC
void boot_primary_init_intc(void)
{
	aplic_init(APLIC_BASE);
}

void boot_secondary_init_intc(void)
{
	aplic_init_per_hart();
}
#endif /* CFG_RISCV_APLIC */

#if defined(CFG_RISCV_APLIC_MSI) && defined(CFG_RISCV_IMSIC)
void boot_primary_init_intc(void)
{
	aplic_init(APLIC_BASE);
	imsic_init(IMSIC_BASE);
}

void boot_secondary_init_intc(void)
{
	aplic_init_per_hart();
	imsic_init_per_hart();
}
#endif

#ifdef CFG_16550_UART
void plat_console_init(void)
{
	ns16550_init(&console_data, UART0_BASE, IO_WIDTH_U8, 0);
	register_serial_console(&console_data.chip);
}
#endif

void interrupt_main_handler(void)
{
	if (IS_ENABLED(CFG_RISCV_PLIC))
		plic_it_handle();
	else if (IS_ENABLED(CFG_RISCV_APLIC))
		aplic_it_handle();
	else if (IS_ENABLED(CFG_RISCV_APLIC_MSI) &&
		 IS_ENABLED(CFG_RISCV_IMSIC))
		imsic_it_handle();
}
