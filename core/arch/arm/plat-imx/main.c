// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2015 Freescale Semiconductor, Inc.
 * Copyright (c) 2016, Wind River Systems.
 * All rights reserved.
 * Copyright 2019, 2023 NXP
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

#include <arm.h>
#include <console.h>
#include <drivers/gic.h>
#include <drivers/imx_uart.h>
#include <drivers/imx_ocotp.h>
#include <imx.h>
#include <kernel/boot.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <stdint.h>
#include <pta_manufacturing.h>

static struct imx_uart_data console_data __nex_bss;

#ifdef CONSOLE_UART_BASE
register_phys_mem_pgdir(MEM_AREA_IO_NSEC, CONSOLE_UART_BASE,
			CORE_MMU_PGDIR_SIZE);
#endif
#ifdef GIC_BASE
register_phys_mem_pgdir(MEM_AREA_IO_SEC, GIC_BASE, CORE_MMU_PGDIR_SIZE);
#endif
#ifdef ANATOP_BASE
register_phys_mem_pgdir(MEM_AREA_IO_SEC, ANATOP_BASE, CORE_MMU_PGDIR_SIZE);
#endif
#ifdef GICD_BASE
register_phys_mem_pgdir(MEM_AREA_IO_SEC, GICD_BASE, 0x10000);
#endif
#ifdef AIPS0_BASE
register_phys_mem_pgdir(MEM_AREA_IO_SEC, AIPS0_BASE,
			ROUNDUP(AIPS0_SIZE, CORE_MMU_PGDIR_SIZE));
#endif
#ifdef AIPS1_BASE
register_phys_mem_pgdir(MEM_AREA_IO_SEC, AIPS1_BASE,
			ROUNDUP(AIPS1_SIZE, CORE_MMU_PGDIR_SIZE));
#endif
#ifdef AIPS2_BASE
register_phys_mem_pgdir(MEM_AREA_IO_SEC, AIPS2_BASE,
			ROUNDUP(AIPS2_SIZE, CORE_MMU_PGDIR_SIZE));
#endif
#ifdef AIPS3_BASE
register_phys_mem_pgdir(MEM_AREA_IO_SEC, AIPS3_BASE,
			ROUNDUP(AIPS3_SIZE, CORE_MMU_PGDIR_SIZE));
#endif
#ifdef IRAM_BASE
register_phys_mem(MEM_AREA_TEE_COHERENT,
		  ROUNDDOWN(IRAM_BASE, CORE_MMU_PGDIR_SIZE),
		  CORE_MMU_PGDIR_SIZE);
#endif
#ifdef M4_AIPS_BASE
register_phys_mem(MEM_AREA_IO_SEC, M4_AIPS_BASE, M4_AIPS_SIZE);
#endif
#ifdef IRAM_S_BASE
register_phys_mem(MEM_AREA_TEE_COHERENT,
		  ROUNDDOWN(IRAM_S_BASE, CORE_MMU_PGDIR_SIZE),
		  CORE_MMU_PGDIR_SIZE);
#endif

#if defined(CFG_PL310)
register_phys_mem_pgdir(MEM_AREA_IO_SEC,
			ROUNDDOWN(PL310_BASE, CORE_MMU_PGDIR_SIZE),
			CORE_MMU_PGDIR_SIZE);
#endif

#if defined(CFG_DRAM_BASE) && defined(CFG_DDR_SIZE)
register_ddr(CFG_DRAM_BASE, CFG_DDR_SIZE);
#endif
#if defined(CFG_NSEC_DDR_1_BASE) && defined(CFG_NSEC_DDR_1_SIZE)
register_ddr(CFG_NSEC_DDR_1_BASE, CFG_NSEC_DDR_1_SIZE);
#endif

void plat_console_init(void)
{
#ifdef CONSOLE_UART_BASE
	imx_uart_init(&console_data, CONSOLE_UART_BASE);
	register_serial_console(&console_data.chip);
#endif
}

void boot_primary_init_intc(void)
{
#ifdef GICD_BASE
	gic_init(0, GICD_BASE);
#else
	gic_init(GIC_BASE + GICC_OFFSET, GIC_BASE + GICD_OFFSET);
#endif
}

#if !defined(CFG_CORE_HAS_GENERIC_TIMER)
unsigned long plat_get_freq(void)
{
	/* Standard i.MX6 boot frequency set by ROM code */
	return 792000000;
}
#endif

#if CFG_TEE_CORE_NB_CORE > 1
void boot_secondary_init_intc(void)
{
	gic_init_per_cpu();
}
#endif

#if defined(CFG_MANUFACTURING_PTA) &&                 \
	defined(CFG_IMX_OCOTP_MANUFACTURING_BANK) &&  \
	defined(CFG_IMX_OCOTP_MANUFACTURING_WORD) &&  \
	defined(CFG_IMX_OCOTP_MANUFACTURING_BIT) &&   \
	defined(CFG_IMX_OCOTP_MANUFACTURING_WIDTH) && \
	CFG_IMX_OCOTP_MANUFACTURING_WIDTH > 0
#if CFG_IMX_OCOTP_MANUFACTURING_WIDTH > 4
#error CFG_IMX_OCOTP_MANUFACTURING_WIDTH must not be bigger then 4
#endif
TEE_Result pta_manufacturing_query_state(enum pta_manufacturing_state *state)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t val = 0;
	int i = (4 - CFG_IMX_OCOTP_MANUFACTURING_WIDTH);

	res = imx_ocotp_read(CFG_IMX_OCOTP_MANUFACTURING_BANK,
			     CFG_IMX_OCOTP_MANUFACTURING_WORD, &val);
	if (res) {
		EMSG("Failed to read manufacturing fuse.");
		*state = PTA_MANUFACTURING_STATE_UNKNOWN;
		return res;
	}

	val = (val >> CFG_IMX_OCOTP_MANUFACTURING_BIT);
	val = val & ((1U << CFG_IMX_OCOTP_MANUFACTURING_WIDTH) - 1);
	while (i-- > 0) {
		/* shift to right place, but fill with last bit. */
		val = val << 1 | (val & 1);
	}
	*state = (enum pta_manufacturing_state)val;
	return TEE_SUCCESS;
}

TEE_Result pta_manufacturing_set_state(enum pta_manufacturing_state state)
{
	uint32_t val = state;

	val = val >> (4 - CFG_IMX_OCOTP_MANUFACTURING_WIDTH);
	val = val & ((1U << CFG_IMX_OCOTP_MANUFACTURING_WIDTH) - 1);
	val = val << CFG_IMX_OCOTP_MANUFACTURING_BIT;

	return imx_ocotp_write(CFG_IMX_OCOTP_MANUFACTURING_BANK,
			       CFG_IMX_OCOTP_MANUFACTURING_WORD, val);
}
#endif
