// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017, Schneider Electric
 * Copyright (c) 2020, Linaro Limited
 */

#include <arm.h>
#include <console.h>
#include <drivers/gic.h>
#include <drivers/ns16550.h>
#include <kernel/boot.h>
#include <kernel/interrupt.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <rzn1_tz.h>

static struct gic_data gic_data;
static struct ns16550_data console_data;

register_phys_mem(MEM_AREA_IO_SEC, GIC_BASE, CORE_MMU_PGDIR_SIZE);
register_phys_mem(MEM_AREA_IO_SEC, PERIPH_REG_BASE, CORE_MMU_PGDIR_SIZE);
register_ddr(DRAM_BASE, DRAM_SIZE);

void console_init(void)
{
	ns16550_init(&console_data, CONSOLE_UART_BASE, IO_WIDTH_U32, 2);
	register_serial_console(&console_data.chip);
}

void main_init_gic(void)
{
	vaddr_t gicc_base = 0;
	vaddr_t gicd_base = 0;

	gicc_base = (vaddr_t)phys_to_virt(GICC_BASE, MEM_AREA_IO_SEC, 1);
	gicd_base = (vaddr_t)phys_to_virt(GICD_BASE, MEM_AREA_IO_SEC, 1);
	if (!gicc_base || !gicd_base)
		panic();

	gic_init(&gic_data, gicc_base, gicd_base);

	itr_init(&gic_data.chip);
}

void main_secondary_init_gic(void)
{
	gic_cpu_init(&gic_data);
}

static TEE_Result rzn1_tz_init(void)
{
	vaddr_t tza_init_reg = 0;
	vaddr_t tza_targ_reg = 0;

	tza_init_reg = core_mmu_get_va(FW_STATIC_TZA_INIT, MEM_AREA_IO_SEC,
				       sizeof(uint32_t));
	tza_targ_reg = core_mmu_get_va(FW_STATIC_TZA_TARG, MEM_AREA_IO_SEC,
				       sizeof(uint32_t));

	/* TZ initiator ports */
	io_write32(tza_init_reg, TZ_INIT_CSA_SEC | TZ_INIT_YS_SEC |
				 TZ_INIT_YC_SEC | TZ_INIT_YD_SEC);

	/* TZ target ports */
	io_write32(tza_targ_reg, TZ_TARG_PC_SEC | TZ_TARG_QB_SEC |
				 TZ_TARG_QA_SEC | TZ_TARG_UB_SEC |
				 TZ_TARG_UA_SEC);

	return TEE_SUCCESS;
}

service_init(rzn1_tz_init);
