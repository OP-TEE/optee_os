// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) Foundries Ltd. 2022 - All Rights Reserved
 */

#include <arm.h>
#include <console.h>
#include <drivers/gic.h>
#include <drivers/pl011.h>
#include <drivers/versal_nvm.h>
#include <drivers/versal_pm.h>
#include<io.h>
#include <kernel/boot.h>
#include <kernel/interrupt.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <kernel/tee_time.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <stdint.h>
#include <string.h>
#include <tee/tee_fs.h>
#include <trace.h>

#define SECURE_BOOT_STATE_AHWROT_REG 0x14C
#define SECURED_AHWROT 0xA5A5A5A5

#define SECURE_BOOT_STATE_SHWROT_REG 0x150
#define SECURED_SHWROT 0x96969696

static bool secure_boot;
static struct gic_data gic_data;
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

void main_init_gic(void)
{
	/* On ARMv8, GIC configuration is initialized in ARM-TF */
	gic_init_base_addr(&gic_data,
			   GIC_BASE + GICC_OFFSET,
			   GIC_BASE + GICD_OFFSET);
}

void itr_core_handler(void)
{
	gic_it_handle(&gic_data);
}

void console_init(void)
{
	pl011_init(&console_data, CONSOLE_UART_BASE,
		   CONSOLE_UART_CLK_IN_HZ, CONSOLE_BAUDRATE);
	register_serial_console(&console_data.chip);
}

static void check_secure_boot(void)
{
	vaddr_t plm_rtca = (vaddr_t)phys_to_virt(PLM_RTCA, MEM_AREA_IO_SEC,
						 PLM_RTCA_LEN);
	bool ahwrot = false;
	bool shwrot = false;
	uint32_t val = 0;

	assert(plm_rtca);

	val = io_read32(plm_rtca + SECURE_BOOT_STATE_AHWROT_REG);
	if (val == SECURED_AHWROT)
		ahwrot = true;

	val = io_read32(plm_rtca + SECURE_BOOT_STATE_SHWROT_REG);
	if (val == SECURED_SHWROT)
		shwrot = true;

	IMSG("Hardware Root of Trust:\t"
	     "Asymmetric %s Enabled, Symmetric %s Enabled",
	     ahwrot ? "" : "NOT", shwrot ? "" : "NOT");

	secure_boot = ahwrot || shwrot;
}

static TEE_Result platform_banner(void)
{
	TEE_Result ret = TEE_SUCCESS;
	uint8_t version = 0;

	ret = versal_soc_version(&version);
	if (ret) {
		EMSG("Failure to retrieve SoC version");
		return ret;
	}

	IMSG("Platform Versal:\tSilicon Revision v%d", version);

	check_secure_boot();

	if (IS_ENABLED(CFG_VERSAL_FPGA_INIT)) {
		ret = versal_write_fpga(CFG_VERSAL_FPGA_DDR_ADDR);
		if (ret) {
			EMSG("Failure to load the FPGA bitstream");
			return TEE_ERROR_GENERIC;
		}
	}

	return TEE_SUCCESS;
}

#if defined(CFG_RPMB_FS)
bool plat_rpmb_key_is_ready(void)
{
	return secure_boot;
}
#endif

service_init(platform_banner);
