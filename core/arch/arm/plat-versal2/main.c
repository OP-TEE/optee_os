// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2023-2024, Advanced Micro Devices, Inc. All rights reserved.
 */

#include <arm.h>
#include <assert.h>
#include <console.h>
#include <drivers/gic.h>
#include <drivers/pl011.h>
#include <drivers/versal_pm.h>
#include <io.h>
#include <kernel/boot.h>
#include <kernel/misc.h>
#include <kernel/tee_time.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <stdint.h>
#include <string.h>
#include <tee/tee_fs.h>
#include <trace.h>

static struct pl011_data console_data;

register_phys_mem_pgdir(MEM_AREA_IO_SEC,
			ROUNDDOWN(CONSOLE_UART_BASE, CORE_MMU_PGDIR_SIZE),
			CORE_MMU_PGDIR_SIZE);

register_phys_mem_pgdir(MEM_AREA_IO_SEC, GICD_BASE, GIC_DIST_REG_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, GICR_BASE, GIC_DIST_REG_SIZE);

register_ddr(DRAM0_BASE, DRAM0_SIZE);

void boot_primary_init_intc(void)
{
	gic_init_v3(0, GICD_BASE, GICR_BASE);
}

void plat_console_init(void)
{
	pl011_init(&console_data, CONSOLE_UART_BASE,
		   CONSOLE_UART_CLK_IN_HZ, CONSOLE_BAUDRATE);
	register_serial_console(&console_data.chip);
}

static TEE_Result platform_banner(void)
{
	IMSG("OP-TEE OS Running on Platform AMD Versal Gen 2");

	return TEE_SUCCESS;
}

service_init(platform_banner);
