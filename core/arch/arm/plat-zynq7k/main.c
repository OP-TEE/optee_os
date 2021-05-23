// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2015 Freescale Semiconductor, Inc.
 * All rights reserved.
 * Copyright (c) 2016, Wind River Systems.
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

#include <arm32.h>
#include <console.h>
#include <drivers/cdns_uart.h>
#include <drivers/gic.h>
#include <io.h>
#include <kernel/boot.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <kernel/tz_ssvce_pl310.h>
#include <mm/core_mmu.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <platform_smc.h>
#include <stdint.h>
#include <tee/entry_fast.h>

static struct gic_data gic_data;
static struct cdns_uart_data console_data;

register_phys_mem_pgdir(MEM_AREA_IO_NSEC, CONSOLE_UART_BASE,
			CORE_MMU_PGDIR_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, GIC_BASE, CORE_MMU_PGDIR_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, PL310_BASE, CORE_MMU_PGDIR_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, SLCR_BASE, CORE_MMU_PGDIR_SIZE);

void plat_primary_init_early(void)
{
	/* primary core */
#if defined(CFG_BOOT_SECONDARY_REQUEST)
	/* set secondary entry address and release core */
	io_write32(SECONDARY_ENTRY_DROP, TEE_LOAD_ADDR);
	dsb();
	sev();
#endif

	/* SCU config */
	io_write32(SCU_BASE + SCU_INV_SEC, SCU_INV_CTRL_INIT);
	io_write32(SCU_BASE + SCU_SAC, SCU_SAC_CTRL_INIT);
	io_write32(SCU_BASE + SCU_NSAC, SCU_NSAC_CTRL_INIT);

	/* SCU enable */
	io_setbits32(SCU_BASE + SCU_CTRL, 0x1);

	/* NS Access control */
	io_write32(SECURITY2_SDIO0, ACCESS_BITS_ALL);
	io_write32(SECURITY3_SDIO1, ACCESS_BITS_ALL);
	io_write32(SECURITY4_QSPI, ACCESS_BITS_ALL);
	io_write32(SECURITY6_APB_SLAVES, ACCESS_BITS_ALL);

	io_write32(SLCR_UNLOCK, SLCR_UNLOCK_MAGIC);

	io_write32(SLCR_TZ_DDR_RAM, ACCESS_BITS_ALL);
	io_write32(SLCR_TZ_DMA_NS, ACCESS_BITS_ALL);
	io_write32(SLCR_TZ_DMA_IRQ_NS, ACCESS_BITS_ALL);
	io_write32(SLCR_TZ_DMA_PERIPH_NS, ACCESS_BITS_ALL);
	io_write32(SLCR_TZ_GEM, ACCESS_BITS_ALL);
	io_write32(SLCR_TZ_SDIO, ACCESS_BITS_ALL);
	io_write32(SLCR_TZ_USB, ACCESS_BITS_ALL);

	io_write32(SLCR_LOCK, SLCR_LOCK_MAGIC);
}

void console_init(void)
{
	cdns_uart_init(&console_data, CONSOLE_UART_BASE, 0, 0);
	register_serial_console(&console_data.chip);
}

vaddr_t pl310_base(void)
{
	static void *va;

	if (cpu_mmu_enabled()) {
		if (!va)
			va = phys_to_virt(PL310_BASE, MEM_AREA_IO_SEC, 1);
		return (vaddr_t)va;
	}
	return PL310_BASE;
}

void arm_cl2_config(vaddr_t pl310_base)
{
	/* Disable PL310 */
	io_write32(pl310_base + PL310_CTRL, 0);

	/*
	 * Xilinx AR#54190 recommends setting L2C RAM in SLCR
	 * to 0x00020202 for proper cache operations.
	 */
	io_write32(SLCR_L2C_RAM, SLCR_L2C_RAM_VALUE);

	io_write32(pl310_base + PL310_TAG_RAM_CTRL, PL310_TAG_RAM_CTRL_INIT);
	io_write32(pl310_base + PL310_DATA_RAM_CTRL, PL310_DATA_RAM_CTRL_INIT);
	io_write32(pl310_base + PL310_AUX_CTRL, PL310_AUX_CTRL_INIT);
	io_write32(pl310_base + PL310_PREFETCH_CTRL, PL310_PREFETCH_CTRL_INIT);
	io_write32(pl310_base + PL310_POWER_CTRL, PL310_POWER_CTRL_INIT);

	/* invalidate all cache ways */
	arm_cl2_invbyway(pl310_base);
}

void arm_cl2_enable(vaddr_t pl310_base)
{
	uint32_t val;

	/* Enable PL310 ctrl -> only set lsb bit */
	io_write32(pl310_base + PL310_CTRL, 1);

	/* if L2 FLZW enable, enable in L1 */
	val = io_read32(pl310_base + PL310_AUX_CTRL);
	if (val & 1)
		write_actlr(read_actlr() | (1 << 3));
}

void main_init_gic(void)
{
	vaddr_t gicc_base;
	vaddr_t gicd_base;

	gicc_base = (vaddr_t)phys_to_virt(GIC_BASE + GICC_OFFSET,
					  MEM_AREA_IO_SEC, 1);
	gicd_base = (vaddr_t)phys_to_virt(GIC_BASE + GICD_OFFSET,
					  MEM_AREA_IO_SEC, 1);

	if (!gicc_base || !gicd_base)
		panic();

	/* Initialize GIC */
	gic_init(&gic_data, gicc_base, gicd_base);
	itr_init(&gic_data.chip);
}

void main_secondary_init_gic(void)
{
	gic_cpu_init(&gic_data);
}

static vaddr_t slcr_access_range[] = {
	0x004, 0x008,	/* lock, unlock */
	0x100, 0x1FF,	/* PLL */
	0x200, 0x2FF,	/* Reset */
	0xA00, 0xAFF	/* L2C */
};

static uint32_t write_slcr(uint32_t addr, uint32_t val)
{
	uint32_t i;

	for (i = 0; i < ARRAY_SIZE(slcr_access_range); i += 2) {
		if (addr >= slcr_access_range[i] &&
		    addr <= slcr_access_range[i+1]) {
			static vaddr_t va;

			if (!va)
				va = (vaddr_t)phys_to_virt(SLCR_BASE,
							   MEM_AREA_IO_SEC,
							   addr +
							   sizeof(uint32_t));
			io_write32(va + addr, val);
			return OPTEE_SMC_RETURN_OK;
		}
	}
	return OPTEE_SMC_RETURN_EBADADDR;
}

static uint32_t read_slcr(uint32_t addr, uint32_t *val)
{
	uint32_t i;

	for (i = 0; i < ARRAY_SIZE(slcr_access_range); i += 2) {
		if (addr >= slcr_access_range[i] &&
		    addr <= slcr_access_range[i+1]) {
			static vaddr_t va;

			if (!va)
				va = (vaddr_t)phys_to_virt(SLCR_BASE,
							   MEM_AREA_IO_SEC,
							   addr +
							   sizeof(uint32_t));
			*val = io_read32(va + addr);
			return OPTEE_SMC_RETURN_OK;
		}
	}
	return OPTEE_SMC_RETURN_EBADADDR;
}

/* Overriding the default __weak tee_entry_fast() */
void tee_entry_fast(struct thread_smc_args *args)
{
	switch (args->a0) {
	case ZYNQ7K_SMC_SLCR_WRITE:
		args->a0 = write_slcr(args->a1, args->a2);
		break;
	case ZYNQ7K_SMC_SLCR_READ:
		args->a0 = read_slcr(args->a1, &args->a2);
		break;
	default:
		__tee_entry_fast(args);
		break;
	}
}
