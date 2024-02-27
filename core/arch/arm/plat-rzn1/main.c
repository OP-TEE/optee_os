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
#include <kernel/delay.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <rzn1_tz.h>

#define SYSCTRL_PWRCTRL_CM3	(SYSCTRL_BASE + 0x174)
#define SYSCTRL_PWRSTAT_CM3	(SYSCTRL_BASE + 0x178)

#define SYSCTRL_PWRCTRL_CM3_CLKEN_A	BIT(0)
#define SYSCTRL_PWRCTRL_CM3_RSTN_A	BIT(1)
#define SYSCTRL_PWRCTRL_CM3_MIREQ_A	BIT(2)

#define SYSCTRL_PWRSTAT_CM3_MIRACK_A	BIT(0)

/* Timeout waiting for Master Idle Request Acknowledge */
#define IDLE_ACK_TIMEOUT_US		1000

static struct ns16550_data console_data;

register_phys_mem(MEM_AREA_IO_SEC, GIC_BASE, CORE_MMU_PGDIR_SIZE);
register_phys_mem(MEM_AREA_IO_SEC, PERIPH_REG_BASE, CORE_MMU_PGDIR_SIZE);
register_ddr(DRAM_BASE, DRAM_SIZE);

void plat_console_init(void)
{
	ns16550_init(&console_data, CONSOLE_UART_BASE, IO_WIDTH_U32, 2);
	register_serial_console(&console_data.chip);
}

void boot_primary_init_intc(void)
{
	gic_init(GICC_BASE, GICD_BASE);
}

void boot_secondary_init_intc(void)
{
	gic_init_per_cpu();
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

#ifdef CFG_BOOT_CM3
static TEE_Result rzn1_cm3_start(void)
{
	vaddr_t cm3_pwrctrl_reg = 0;
	vaddr_t cm3_pwrstat_reg = 0;
	uint64_t timeout_ack = timeout_init_us(IDLE_ACK_TIMEOUT_US);

	cm3_pwrctrl_reg = core_mmu_get_va(SYSCTRL_PWRCTRL_CM3, MEM_AREA_IO_SEC,
					  sizeof(uint32_t));
	cm3_pwrstat_reg = core_mmu_get_va(SYSCTRL_PWRSTAT_CM3, MEM_AREA_IO_SEC,
					  sizeof(uint32_t));

	/* Master Idle Request to the interconnect for CM3 */
	io_clrbits32(cm3_pwrctrl_reg, SYSCTRL_PWRCTRL_CM3_MIREQ_A);

	/* Wait for Master Idle Request Acknowledge for CM3 */
	while (!timeout_elapsed(timeout_ack))
		if (!(io_read32(cm3_pwrstat_reg) &
				SYSCTRL_PWRSTAT_CM3_MIRACK_A))
			break;

	if (io_read32(cm3_pwrstat_reg) & SYSCTRL_PWRSTAT_CM3_MIRACK_A)
		panic();

	/* Clock Enable for CM3_HCLK & Active low Reset to CM3 */
	io_setbits32(cm3_pwrctrl_reg, SYSCTRL_PWRCTRL_CM3_CLKEN_A);
	io_setbits32(cm3_pwrctrl_reg, SYSCTRL_PWRCTRL_CM3_RSTN_A);

	return TEE_SUCCESS;
}

service_init(rzn1_cm3_start);
#endif
