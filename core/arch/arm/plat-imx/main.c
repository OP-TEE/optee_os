// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2015 Freescale Semiconductor, Inc.
 * Copyright (c) 2016, Wind River Systems.
 * All rights reserved.
 * Copyright 2019 NXP
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
#include <imx.h>
#include <io.h>
#include <kernel/boot.h>
#include <kernel/interrupt.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <sm/optee_smc.h>
#include <stdint.h>

static struct gic_data gic_data __nex_bss;

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

register_dynamic_shm(CFG_NSEC_DDR_0_BASE, CFG_NSEC_DDR_0_SIZE);
#if defined(CFG_NSEC_DDR_1_BASE) && defined(CFG_NSEC_DDR_1_SIZE)
register_dynamic_shm(CFG_NSEC_DDR_1_BASE, CFG_NSEC_DDR_1_SIZE);
#endif

void itr_core_handler(void)
{
	gic_it_handle(&gic_data);
}

void console_init(void)
{
#ifdef CONSOLE_UART_BASE
	imx_uart_init(&console_data, CONSOLE_UART_BASE);
	register_serial_console(&console_data.chip);
#endif
}

void main_init_gic(void)
{
#ifdef GICD_BASE
	gic_init(&gic_data, 0, GICD_BASE);
#else
	gic_init(&gic_data, GIC_BASE + GICC_OFFSET, GIC_BASE + GICD_OFFSET);
#endif
	itr_init(&gic_data.chip);
}

#if CFG_TEE_CORE_NB_CORE > 1
void main_secondary_init_gic(void)
{
	gic_cpu_init(&gic_data);
}
#endif
