// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, Allwinner Technology Co., Ltd.
 * Copyright (c) 2018, Linaro Limited
 * Copyright (c) 2018, Amit Singh Tomar <amittomer25@gmail.com>
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

#include <console.h>
#include <io.h>
#include <stdint.h>
#include <drivers/gic.h>
#include <drivers/serial8250_uart.h>
#include <drivers/tzc380.h>
#include <kernel/boot.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <kernel/tz_ssvce_def.h>
#include <mm/core_mmu.h>
#include <mm/core_memprot.h>
#include <mm/tee_pager.h>
#include <platform_config.h>
#include <sm/optee_smc.h>

#ifdef GIC_BASE
register_phys_mem_pgdir(MEM_AREA_IO_SEC, GIC_BASE, CORE_MMU_PGDIR_SIZE);
#endif

#ifdef CONSOLE_UART_BASE
register_phys_mem_pgdir(MEM_AREA_IO_NSEC,
			CONSOLE_UART_BASE, SUNXI_UART_REG_SIZE);
#endif

#ifdef SUNXI_TZPC_BASE
register_phys_mem_pgdir(MEM_AREA_IO_SEC, SUNXI_TZPC_BASE, SUNXI_TZPC_REG_SIZE);
#define REG_TZPC_SMTA_DECPORT0_STA_REG      (0x0004)
#define REG_TZPC_SMTA_DECPORT0_SET_REG      (0x0008)
#define REG_TZPC_SMTA_DECPORT0_CLR_REG      (0x000C)
#define REG_TZPC_SMTA_DECPORT1_STA_REG      (0x0010)
#define REG_TZPC_SMTA_DECPORT1_SET_REG      (0x0014)
#define REG_TZPC_SMTA_DECPORT1_CLR_REG      (0x0018)
#define REG_TZPC_SMTA_DECPORT2_STA_REG      (0x001c)
#define REG_TZPC_SMTA_DECPORT2_SET_REG      (0x0020)
#define REG_TZPC_SMTA_DECPORT2_CLR_REG      (0x0024)
#endif

#ifdef SUNXI_CPUCFG_BASE
register_phys_mem_pgdir(MEM_AREA_IO_SEC, SUNXI_CPUCFG_BASE,
			SUNXI_CPUCFG_REG_SIZE);
#endif

#ifdef SUNXI_PRCM_BASE
register_phys_mem_pgdir(MEM_AREA_IO_SEC, SUNXI_PRCM_BASE, SUNXI_PRCM_REG_SIZE);
#endif

#ifdef CFG_TZC380
vaddr_t smc_base(void);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, SUNXI_SMC_BASE, TZC400_REG_SIZE);
#define SMC_MASTER_BYPASS 0x18
#define SMC_MASTER_BYPASS_EN_MASK 0x1
#endif

#ifdef GIC_BASE
static struct gic_data gic_data;
#endif
#ifdef SUNXI_TZPC_BASE
static void tzpc_init(void);
#endif

static struct serial8250_uart_data console_data;

void console_init(void)
{
	serial8250_uart_init(&console_data,
			     CONSOLE_UART_BASE,
			     CONSOLE_UART_CLK_IN_HZ,
			     CONSOLE_BAUDRATE);
	register_serial_console(&console_data.chip);
}

#ifdef SUNXI_TZPC_BASE
static void tzpc_init(void)
{
	vaddr_t v = (vaddr_t)phys_to_virt(SUNXI_TZPC_BASE, MEM_AREA_IO_SEC,
					  SUNXI_TZPC_REG_SIZE);

	DMSG("SMTA_DECPORT0=%x", io_read32(v + REG_TZPC_SMTA_DECPORT0_STA_REG));
	DMSG("SMTA_DECPORT1=%x", io_read32(v + REG_TZPC_SMTA_DECPORT1_STA_REG));
	DMSG("SMTA_DECPORT2=%x", io_read32(v + REG_TZPC_SMTA_DECPORT2_STA_REG));

	/* Allow all peripherals for normal world */
	io_write32(v + REG_TZPC_SMTA_DECPORT0_SET_REG, 0xbe);
	io_write32(v + REG_TZPC_SMTA_DECPORT1_SET_REG, 0xff);
	io_write32(v + REG_TZPC_SMTA_DECPORT2_SET_REG, 0x7f);

	DMSG("SMTA_DECPORT0=%x", io_read32(v + REG_TZPC_SMTA_DECPORT0_STA_REG));
	DMSG("SMTA_DECPORT1=%x", io_read32(v + REG_TZPC_SMTA_DECPORT1_STA_REG));
	DMSG("SMTA_DECPORT2=%x", io_read32(v + REG_TZPC_SMTA_DECPORT2_STA_REG));
}
#else
static inline void tzpc_init(void)
{
}
#endif /* SUNXI_TZPC_BASE */

#ifndef CFG_WITH_ARM_TRUSTED_FW
void main_init_gic(void)
{
	gic_init(&gic_data, GIC_BASE + GICC_OFFSET, GIC_BASE + GICD_OFFSET);
	itr_init(&gic_data.chip);
}

void main_secondary_init_gic(void)
{
	gic_cpu_init(&gic_data);
}
#endif

#ifdef ARM32
void plat_primary_init_early(void)
{
	assert(!cpu_mmu_enabled());

	tzpc_init();
}
#endif

/*
 * Allwinner's A64 has TZC380 like controller called SMC that can
 * be programmed to protect parts of DRAM from non-secure world.
 */
#ifdef CFG_TZC380
vaddr_t smc_base(void)
{
	return (vaddr_t)phys_to_virt(SUNXI_SMC_BASE, MEM_AREA_IO_SEC,
				     TZC400_REG_SIZE);
}

static TEE_Result smc_init(void)
{
	vaddr_t base = smc_base();

	if (!base) {
		EMSG("smc not mapped");
		panic();
	}

	tzc_init(base);
	tzc_configure_region(0, 0x0, TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_1G) |
			     TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_ALL);
	tzc_configure_region(1, 0x0, TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_32M) |
			     TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_S_RW);

	/* SoC specific bits */
	io_clrbits32(base + SMC_MASTER_BYPASS, SMC_MASTER_BYPASS_EN_MASK);

	return TEE_SUCCESS;
}

driver_init(smc_init);
#endif /* CFG_TZC380 */
