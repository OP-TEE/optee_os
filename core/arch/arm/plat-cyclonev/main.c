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

/*
 * This code has been adapted from zynq7k platform port
 */

#include <arm32.h>
#include <console.h>
#include <drivers/serial8250_uart.h>
#include <drivers/gic.h>
#include <io.h>
#include <kernel/boot.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <kernel/tz_ssvce_pl310.h>
#include <mm/core_mmu.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <sm/sm.h>
#include <limits.h>
#include <stdint.h>
#include <tee/entry_fast.h>

#define PADDR_INVALID ULONG_MAX

struct cyclonev_l3_security {
	uint32_t __pad_32_0;
	uint32_t __pad_32_1;
	uint32_t l4main;
	uint32_t l4sp;
	uint32_t l4mp;
	uint32_t l4osc1;
	uint32_t l4spim;
	uint32_t stm;
	uint32_t lwhps2fpgaregs;
	uint32_t usb1;
	uint32_t nanddata;
	uint32_t usb0;
	uint32_t nandregs;
	uint32_t qspidata;
	uint32_t fpgamgrdata;
	uint32_t hps2fpgaregs;
	uint32_t acp;
	uint32_t rom;
	uint32_t ocram;
	uint32_t sdrdata;
};

static struct serial8250_uart_data console_data;
static struct cyclonev_l3_security *l3_regs;

register_phys_mem_pgdir(MEM_AREA_IO_NSEC, CONSOLE_UART_BASE,
			CORE_MMU_PGDIR_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, GIC_BASE, SMALL_PAGE_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, PL310_BASE, SMALL_PAGE_SIZE);

void init_sec_mon(unsigned long nsec_entry)
{
	struct sm_nsec_ctx *nsec_ctx;

	assert(nsec_entry != PADDR_INVALID);

	/* Initialize secure monitor */
	nsec_ctx = sm_get_nsec_ctx();
	nsec_ctx->mon_lr = 0x01000000U;  /* Linux */
	nsec_ctx->r0 = 0;
	nsec_ctx->r1 = 0xFFFFFFFF;  /* Machine type (-1) */
	nsec_ctx->r2 = 0x02000000U;  /* DT address */
	nsec_ctx->mon_spsr = CPSR_MODE_SVC | CPSR_I;
}

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

	// Enable NS access on all peripherals.

	l3_regs = (struct cyclonev_l3_security *)L3REGS_BASE;
	io_write32((uint32_t)&l3_regs->l4main, ALL_ACCESS_N_BITS(4));
	io_write32((uint32_t)&l3_regs->l4sp, ALL_ACCESS_N_BITS(11));
	io_write32((uint32_t)&l3_regs->l4mp, ALL_ACCESS_N_BITS(10));
	io_write32((uint32_t)&l3_regs->l4osc1, ALL_ACCESS_N_BITS(7));
	io_write32((uint32_t)&l3_regs->l4spim, ALL_ACCESS_N_BITS(3));
	io_write32((uint32_t)&l3_regs->stm, ALL_ACCESS_N_BITS(1));
	io_write32((uint32_t)&l3_regs->lwhps2fpgaregs, ALL_ACCESS_N_BITS(1));
	io_write32((uint32_t)&l3_regs->lwhps2fpgaregs, ALL_ACCESS_N_BITS(1));
	io_write32((uint32_t)&l3_regs->usb1, ALL_ACCESS_N_BITS(1));
	io_write32((uint32_t)&l3_regs->nanddata, ALL_ACCESS_N_BITS(1));
	io_write32((uint32_t)&l3_regs->usb0, ALL_ACCESS_N_BITS(1));
	io_write32((uint32_t)&l3_regs->usb0, ALL_ACCESS_N_BITS(1));
	io_write32((uint32_t)&l3_regs->nandregs, ALL_ACCESS_N_BITS(1));
	io_write32((uint32_t)&l3_regs->qspidata, ALL_ACCESS_N_BITS(1));
	io_write32((uint32_t)&l3_regs->fpgamgrdata, ALL_ACCESS_N_BITS(1));
	io_write32((uint32_t)&l3_regs->hps2fpgaregs, ALL_ACCESS_N_BITS(1));
	io_write32((uint32_t)&l3_regs->acp, ALL_ACCESS_N_BITS(1));
	io_write32((uint32_t)&l3_regs->rom, ALL_ACCESS_N_BITS(1));
	io_write32((uint32_t)&l3_regs->ocram, ALL_ACCESS_N_BITS(1));
	io_write32((uint32_t)&l3_regs->sdrdata, ALL_ACCESS_N_BITS(1));
}

void plat_console_init(void)
{
	serial8250_uart_init(&console_data, CONSOLE_UART_BASE, 0, 0);
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

void boot_primary_init_intc(void)
{
	gic_init(GIC_BASE + GICC_OFFSET, GIC_BASE + GICD_OFFSET);
}

void boot_secondary_init_intc(void)
{
	gic_init_per_cpu();
}

