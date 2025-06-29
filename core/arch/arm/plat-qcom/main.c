// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025, Linaro Limited
 */

#include <console.h>
#include <drivers/geni_uart.h>
#include <drivers/clk_qcom.h>
#include <kernel/boot.h>
#include <kernel/panic.h>
#include <io.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <stdint.h>
#include <tee/entry_fast.h>
#include <tee/entry_std.h>
#include <drivers/gic.h>
#include <sm/optee_smc.h>
#include <kernel/delay.h>

#include "q6dsp.h"

/*
 * Register the physical memory area for peripherals etc. Here we are
 * registering the UART console.
 */
register_phys_mem_pgdir(MEM_AREA_IO_NSEC, CONSOLE_UART_BASE,
			GENI_UART_REG_SIZE);
register_phys_mem(MEM_AREA_IO_NSEC, GCC_BASE, 0x100000);
register_phys_mem(MEM_AREA_IO_NSEC, WPSS_BASE, 0x1000);
register_phys_mem(MEM_AREA_IO_NSEC, ADSP_BASE, 0x1000);
#ifdef ADSP_LPASS_EFUSE
/* We only need the one 32-bit register... */
register_phys_mem(MEM_AREA_IO_NSEC, ADSP_LPASS_EFUSE, 0x1000);
#endif

register_phys_mem_pgdir(MEM_AREA_IO_SEC, GICD_BASE, GIC_DIST_REG_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, GICR_BASE, 0x100000);

register_ddr(DRAM0_BASE, DRAM0_SIZE);
register_ddr(DRAM1_BASE, DRAM1_SIZE);
register_ddr(DRAM2_BASE, DRAM2_SIZE);
register_ddr(DRAM3_BASE, DRAM3_SIZE);

static struct geni_uart_data console_data;

void plat_console_init(void)
{
	geni_uart_init(&console_data, CONSOLE_UART_BASE);
	register_serial_console(&console_data.chip);
}

void boot_primary_init_intc(void)
{
	gic_init_v3(0, GICD_BASE, GICR_BASE);
}

void boot_secondary_init_intc(void)
{
	gic_init_per_cpu();
}

#define SMC_SVC_PIL 0x02
#define QTI_SIP_SVC_AVAILABLE_ID	U(0xc2000601)
#define QCOM_SCM_PIL_PAS_INIT_IMAGE	U(0xc2000201)
#define QCOM_SCM_PIL_PAS_MEM_SETUP	U(0xc2000202)
#define QCOM_SCM_PIL_PAS_AUTH_AND_RESET	U(0xc2000205)
#define QCOM_SCM_PIL_PAS_SHUTDOWN	U(0xc2000206)
#define QCOM_SCM_PIL_PAS_IS_SUPPORTED	U(0xc2000207)

static bool qti_check_syscall_availability(uint64_t smc_fid)
{
	/*
	 * Ignore the top two bytes when checking if an SMC call
	 * is supported since those aren't set.
	 */
	smc_fid = (smc_fid & 0x3fffffff) | 0xc0000000;
	switch (smc_fid) {
	case QTI_SIP_SVC_AVAILABLE_ID:
	case QCOM_SCM_PIL_PAS_INIT_IMAGE:
	case QCOM_SCM_PIL_PAS_MEM_SETUP:
	case QCOM_SCM_PIL_PAS_AUTH_AND_RESET:
	case QCOM_SCM_PIL_PAS_SHUTDOWN:
	case QCOM_SCM_PIL_PAS_IS_SUPPORTED:
		return true;
	default:
		return false;
	}
}

/* Add handlers for DSP init */
void tee_entry_fast(struct thread_smc_args *args)
{
	/* Mask off the function ID */
	uint32_t smc = args->a0 & 0xFFFFFF00;

	if (args->a0 == QTI_SIP_SVC_AVAILABLE_ID) {
		args->a0 = OPTEE_SMC_RETURN_OK;
		args->a1 = qti_check_syscall_availability(args->a2) ? 1 : 0;
		return;
	}

	/* SIP call for PIL svc */
	if (smc == 0xc2000200)
		qcom_handle_pil_smc(args);
	else
		__tee_entry_fast(args);
}
