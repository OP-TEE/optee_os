// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016, GlobalLogic
 * Copyright (c) 2019-2020, Renesas Electronics Corporation
 */

#include <console.h>
#include <drivers/gic.h>
#include <drivers/scif.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <platform_config.h>

register_phys_mem_pgdir(MEM_AREA_IO_SEC, CONSOLE_UART_BASE, SCIF_REG_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, GICD_BASE, GIC_DIST_REG_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, GICC_BASE, GIC_DIST_REG_SIZE);

register_dynamic_shm(NSEC_DDR_0_BASE, NSEC_DDR_0_SIZE);
#ifdef NSEC_DDR_1_BASE
register_dynamic_shm(NSEC_DDR_1_BASE, NSEC_DDR_1_SIZE);
#endif
#ifdef NSEC_DDR_2_BASE
register_dynamic_shm(NSEC_DDR_2_BASE, NSEC_DDR_2_SIZE);
#endif
#ifdef NSEC_DDR_3_BASE
register_dynamic_shm(NSEC_DDR_3_BASE, NSEC_DDR_3_SIZE);
#endif

static struct scif_uart_data console_data __nex_bss;

void plat_console_init(void)
{
	scif_uart_init(&console_data, CONSOLE_UART_BASE);
	register_serial_console(&console_data.chip);
}
