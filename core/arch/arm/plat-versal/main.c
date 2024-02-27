// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) Foundries Ltd. 2022 - All Rights Reserved
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

#define VERSAL_AHWROT_SECURED 0xA5A5A5A5
#define VERSAL_SHWROT_SECURED 0x96969696
#define VERSAL_AHWROT_REG 0x14C
#define VERSAL_SHWROT_REG 0x150

static struct pl011_data console_data;

register_phys_mem_pgdir(MEM_AREA_IO_SEC,
			ROUNDDOWN(CONSOLE_UART_BASE, CORE_MMU_PGDIR_SIZE),
			CORE_MMU_PGDIR_SIZE);

register_phys_mem_pgdir(MEM_AREA_IO_SEC,
			GIC_BASE, CORE_MMU_PGDIR_SIZE);

register_phys_mem_pgdir(MEM_AREA_IO_SEC,
			GIC_BASE + GICD_OFFSET, CORE_MMU_PGDIR_SIZE);

register_phys_mem(MEM_AREA_IO_SEC, PLM_RTCA, PLM_RTCA_LEN);

register_ddr(DRAM0_BASE, DRAM0_SIZE);

#if defined(DRAM1_BASE)
register_ddr(DRAM1_BASE, DRAM1_SIZE);
register_ddr(DRAM2_BASE, DRAM2_SIZE);
#endif

void boot_primary_init_intc(void)
{
	gic_init(GIC_BASE + GICC_OFFSET, GIC_BASE + GICD_OFFSET);
}

void plat_console_init(void)
{
	pl011_init(&console_data, CONSOLE_UART_BASE,
		   CONSOLE_UART_CLK_IN_HZ, CONSOLE_BAUDRATE);
	register_serial_console(&console_data.chip);
}

static TEE_Result platform_banner(void)
{
	vaddr_t plm_rtca = (vaddr_t)phys_to_virt(PLM_RTCA, MEM_AREA_IO_SEC,
						 PLM_RTCA_LEN);
	const char __maybe_unused *ahwrot_str = "OFF";
	const char __maybe_unused *shwrot_str = "OFF";
	uint8_t version = 0;

	assert(plm_rtca);

	if (versal_soc_version(&version)) {
		EMSG("Failure to retrieve SoC version");
		return TEE_ERROR_GENERIC;
	}

	IMSG("Platform Versal:\tSilicon Revision v%"PRIu8, version);

	if (io_read32(plm_rtca + VERSAL_AHWROT_REG) == VERSAL_AHWROT_SECURED)
		ahwrot_str = "ON";

	if (io_read32(plm_rtca + VERSAL_SHWROT_REG) == VERSAL_SHWROT_SECURED)
		shwrot_str = "ON";

	IMSG("Hardware Root of Trust: Asymmetric[%s], Symmetric[%s]",
	     ahwrot_str, shwrot_str);

	return TEE_SUCCESS;
}

#if defined(CFG_RPMB_FS)
bool plat_rpmb_key_is_ready(void)
{
	vaddr_t plm_rtca = (vaddr_t)phys_to_virt(PLM_RTCA, MEM_AREA_IO_SEC,
						 PLM_RTCA_LEN);

	assert(plm_rtca);

	if (io_read32(plm_rtca + VERSAL_AHWROT_REG) == VERSAL_AHWROT_SECURED)
		return true;

	if (io_read32(plm_rtca + VERSAL_SHWROT_REG) == VERSAL_SHWROT_SECURED)
		return true;

	return false;
}
#endif

service_init(platform_banner);

#if defined(CFG_VERSAL_FPGA_DDR_ADDR)
static TEE_Result program_fpga(void)
{
	return versal_write_fpga(CFG_VERSAL_FPGA_DDR_ADDR);
}

service_init(program_fpga);
#endif
