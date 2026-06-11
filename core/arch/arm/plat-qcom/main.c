// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025, Linaro Limited
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <console.h>
#include <drivers/gic.h>
#include <drivers/qcom_geni_uart.h>
#include <kernel/boot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>

#include "diag_log.h"

/*
 * Register the physical memory area for peripherals etc. Here we are
 * registering the UART console.
 */
register_phys_mem_pgdir(MEM_AREA_IO_NSEC, GENI_UART_REG_BASE,
			GENI_UART_REG_SIZE);

register_phys_mem_pgdir(MEM_AREA_IO_SEC, GICD_BASE, GIC_DIST_REG_SIZE);
#ifdef CFG_ARM_GICV3
register_phys_mem_pgdir(MEM_AREA_IO_SEC, GICR_BASE, GIC_REDIST_REG_SIZE);
#else
register_phys_mem_pgdir(MEM_AREA_IO_SEC, GICC_BASE, GIC_CPU_REG_SIZE);
#endif

register_ddr(DRAM0_BASE, DRAM0_SIZE);
#ifdef DRAM1_BASE
register_ddr(DRAM1_BASE, DRAM1_SIZE);
#endif

static struct qcom_geni_uart_data console_data;

void plat_trace_ext_puts(const char *str)
{
	qcom_diag_log_puts(str);
}

void plat_trace_init(void)
{
	qcom_diag_log_init();
}

void plat_console_init(void)
{
	qcom_geni_uart_init(&console_data, GENI_UART_REG_BASE);
	register_serial_console(&console_data.chip);
}

static TEE_Result platform_banner(void)
{
	IMSG("Platform Qualcomm: Flavor %s", TO_STR(PLATFORM_FLAVOR));

	return TEE_SUCCESS;
}

boot_final(platform_banner);

void boot_primary_init_intc(void)
{
#ifdef CFG_ARM_GICV3
	gic_init_v3(0, GICD_BASE, GICR_BASE);
#else
	gic_init(GICC_BASE, GICD_BASE);
#endif
}

void boot_secondary_init_intc(void)
{
	gic_init_per_cpu();
}
