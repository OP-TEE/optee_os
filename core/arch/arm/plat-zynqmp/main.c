// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016, Xilinx Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <platform_config.h>

#include <stdint.h>
#include <string.h>

#include <drivers/gic.h>
#include <drivers/cdns_uart.h>
#include <drivers/zynqmp_csu.h>

#include <arm.h>
#include <console.h>
#include <io.h>
#include <kernel/boot.h>
#include <kernel/interrupt.h>
#include <kernel/misc.h>
#include <kernel/tee_common_otp.h>
#include <kernel/tee_time.h>
#include <mm/core_memprot.h>
#include <tee/tee_fs.h>
#include <trace.h>

static struct gic_data gic_data;
static struct cdns_uart_data console_data;

register_phys_mem_pgdir(MEM_AREA_IO_SEC,
			ROUNDDOWN(CONSOLE_UART_BASE, CORE_MMU_PGDIR_SIZE),
			CORE_MMU_PGDIR_SIZE);

register_phys_mem_pgdir(MEM_AREA_IO_SEC,
			ROUNDDOWN(GIC_BASE, CORE_MMU_PGDIR_SIZE),
			CORE_MMU_PGDIR_SIZE);

register_phys_mem_pgdir(MEM_AREA_IO_SEC,
			ROUNDDOWN(GIC_BASE + GICD_OFFSET, CORE_MMU_PGDIR_SIZE),
			CORE_MMU_PGDIR_SIZE);
#if defined(CFG_ZYNQMP_CSU)
register_phys_mem_pgdir(MEM_AREA_IO_SEC, CSU_BASE, CSU_SIZE);
#endif

#if CFG_DDR_SIZE > 0x80000000

#ifdef CFG_ARM32_core
#error DDR size over 2 GiB is not supported in 32 bit ARM mode
#endif

register_ddr(DRAM0_BASE, 0x80000000);
register_ddr(DRAM1_BASE, CFG_DDR_SIZE - 0x80000000);
#else
register_ddr(DRAM0_BASE, CFG_DDR_SIZE);
#endif

void main_init_gic(void)
{
	vaddr_t gicc_base, gicd_base;

	gicc_base = (vaddr_t)phys_to_virt(GIC_BASE + GICC_OFFSET,
					  MEM_AREA_IO_SEC, 1);
	gicd_base = (vaddr_t)phys_to_virt(GIC_BASE + GICD_OFFSET,
					  MEM_AREA_IO_SEC, 1);
	/* On ARMv8, GIC configuration is initialized in ARM-TF */
	gic_init_base_addr(&gic_data, gicc_base, gicd_base);
}

void itr_core_handler(void)
{
	gic_it_handle(&gic_data);
}

void console_init(void)
{
	cdns_uart_init(&console_data, CONSOLE_UART_BASE,
		       CONSOLE_UART_CLK_IN_HZ, CONSOLE_BAUDRATE);
	register_serial_console(&console_data.chip);
}

#if defined(CFG_RPMB_FS)
bool plat_rpmb_key_is_ready(void)
{
	vaddr_t csu = core_mmu_get_va(CSU_BASE, MEM_AREA_IO_SEC, CSU_SIZE);
	struct tee_hw_unique_key hwkey = { };
	uint32_t status = 0;

	if (tee_otp_get_hw_unique_key(&hwkey))
		return false;

	/*
	 * For security reasons, we don't allow writing the RPMB key using the
	 * development HUK even though it is unique.
	 */
	status = io_read32(csu + ZYNQMP_CSU_STATUS_OFFSET);
	if (status & ZYNQMP_CSU_STATUS_AUTH)
		return true;

	return false;
}
#endif
