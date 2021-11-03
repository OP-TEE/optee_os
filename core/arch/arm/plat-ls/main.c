// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2018 NXP
 * Copyright (C) 2015 Freescale Semiconductor, Inc.
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

#include <arm.h>
#include <console.h>
#include <drivers/gic.h>
#ifdef CFG_PL011
#include <drivers/pl011.h>
#else
#include <drivers/ns16550.h>
#endif
#include <io.h>
#include <kernel/boot.h>
#include <kernel/dt.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <kernel/thread.h>
#include <kernel/tz_ssvce_def.h>
#include <libfdt.h>
#include <mm/core_memprot.h>
#include <sm/optee_smc.h>
#include <kernel/tee_common_otp.h>
#include <mm/core_mmu.h>

static struct gic_data gic_data;
#ifdef CFG_PL011
static struct pl011_data console_data;
#else
static struct ns16550_data console_data;
#endif

register_phys_mem_pgdir(MEM_AREA_IO_NSEC, CONSOLE_UART_BASE,
			CORE_MMU_PGDIR_SIZE);
#if !defined(PLATFORM_FLAVOR_lx2160aqds) && !defined(PLATFORM_FLAVOR_lx2160ardb)
register_phys_mem_pgdir(MEM_AREA_IO_SEC, GIC_BASE, CORE_MMU_PGDIR_SIZE);
#endif

#if defined(PLATFORM_FLAVOR_lx2160ardb) || defined(PLATFORM_FLAVOR_lx2160aqds)
register_ddr(CFG_DRAM0_BASE, (CFG_TZDRAM_START - CFG_DRAM0_BASE));
#ifdef CFG_DRAM1_BASE
register_ddr(CFG_DRAM1_BASE, CFG_DRAM1_SIZE);
#endif
#endif

#ifdef CFG_ARM32_core
void plat_primary_init_early(void)
{
	vaddr_t addr;

#if defined(CFG_BOOT_SECONDARY_REQUEST)
	/* set secondary entry address */
	io_write32(DCFG_BASE + DCFG_SCRATCHRW1,
		   __compiler_bswap32(TEE_LOAD_ADDR));

	/* release secondary cores */
	io_write32(DCFG_BASE + DCFG_CCSR_BRR /* cpu1 */,
		   __compiler_bswap32(0x1 << 1));
	dsb();
	sev();
#endif

	/* configure CSU */

	/* first grant all peripherals */
	for (addr = CSU_BASE + CSU_CSL_START;
		 addr != CSU_BASE + CSU_CSL_END;
		 addr += 4)
		io_write32(addr, __compiler_bswap32(CSU_ACCESS_ALL));

	/* restrict key preipherals from NS */
	io_write32(CSU_BASE + CSU_CSL30,
		   __compiler_bswap32(CSU_ACCESS_SEC_ONLY));
	io_write32(CSU_BASE + CSU_CSL37,
		   __compiler_bswap32(CSU_ACCESS_SEC_ONLY));

	/* lock the settings */
	for (addr = CSU_BASE + CSU_CSL_START;
	     addr != CSU_BASE + CSU_CSL_END;
	     addr += 4)
		io_setbits32(addr,
			     __compiler_bswap32(CSU_SETTING_LOCK));
}
#endif

void console_init(void)
{
#ifdef CFG_PL011
	/*
	 * Everything for uart driver initialization is done in bootloader.
	 * So not reinitializing console.
	 */
	pl011_init(&console_data, CONSOLE_UART_BASE, 0, 0);
#else
	ns16550_init(&console_data, CONSOLE_UART_BASE, IO_WIDTH_U8, 0);
#endif
	register_serial_console(&console_data.chip);
}

#if defined(PLATFORM_FLAVOR_lx2160aqds) || defined(PLATFORM_FLAVOR_lx2160ardb)
static TEE_Result get_gic_base_addr_from_dt(paddr_t *gic_addr)
{
	paddr_t paddr = 0;
	size_t size = 0;

	void *fdt = get_embedded_dt();
	int gic_offset = 0;

	gic_offset = fdt_path_offset(fdt, "/soc/interrupt-controller@6000000");

	if (gic_offset < 0)
		gic_offset = fdt_path_offset(fdt,
					     "/interrupt-controller@6000000");

	if (gic_offset > 0) {
		paddr = _fdt_reg_base_address(fdt, gic_offset);
		if (paddr == DT_INFO_INVALID_REG) {
			EMSG("GIC: Unable to get base addr from DT");
			return TEE_ERROR_ITEM_NOT_FOUND;
		}

		size = _fdt_reg_size(fdt, gic_offset);
		if (size == DT_INFO_INVALID_REG_SIZE) {
			EMSG("GIC: Unable to get size of base addr from DT");
			return TEE_ERROR_ITEM_NOT_FOUND;
		}
	} else {
		EMSG("Unable to get gic offset node");
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	/* make entry in page table */
	if (!core_mmu_add_mapping(MEM_AREA_IO_SEC, paddr, size)) {
		EMSG("GIC controller base MMU PA mapping failure");
		return TEE_ERROR_GENERIC;
	}

	*gic_addr = paddr;
	return TEE_SUCCESS;
}
#endif

void main_init_gic(void)
{
	vaddr_t gicc_base = 0;
	vaddr_t gicd_base = 0;

	paddr_t gic_base = 0;
	uint32_t gicc_offset = 0;
	uint32_t gicd_offset = 0;

#if defined(PLATFORM_FLAVOR_lx2160aqds) || defined(PLATFORM_FLAVOR_lx2160ardb)
	if (get_gic_base_addr_from_dt(&gic_base))
		EMSG("Failed to get GIC base addr from DT");
#else
	gic_base = GIC_BASE;
	gicc_offset = GICC_OFFSET;
	gicd_offset = GICD_OFFSET;
#endif

	gicc_base = (vaddr_t)phys_to_virt(gic_base + gicc_offset,
					  MEM_AREA_IO_SEC, 1);
	gicd_base = (vaddr_t)phys_to_virt(gic_base + gicd_offset,
					  MEM_AREA_IO_SEC, 1);
	if (!gicc_base || !gicd_base)
		panic();

#if defined(CFG_WITH_ARM_TRUSTED_FW)
	/* On ARMv8, GIC configuration is initialized in ARM-TF */
	gic_init_base_addr(&gic_data, gicc_base, gicd_base);
#else
	/* Initialize GIC */
	gic_init(&gic_data, gicc_base, gicd_base);
#endif
	itr_init(&gic_data.chip);
}

void main_secondary_init_gic(void)
{
	gic_cpu_init(&gic_data);
}
