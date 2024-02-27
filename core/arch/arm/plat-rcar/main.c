// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016, GlobalLogic
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
#include <crypto/crypto.h>
#include <kernel/boot.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <stdint.h>
#include <drivers/scif.h>
#include <drivers/gic.h>

register_phys_mem_pgdir(MEM_AREA_IO_SEC, CONSOLE_UART_BASE, SCIF_REG_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, GICD_BASE, GIC_DIST_REG_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, GICC_BASE, GIC_CPU_REG_SIZE);
#ifdef PRR_BASE
register_phys_mem_pgdir(MEM_AREA_IO_SEC, PRR_BASE, SMALL_PAGE_SIZE);
#endif

/* Legacy platforms */
#if defined(PLATFORM_FLAVOR_salvator_h3) || \
	defined(PLATFORM_FLAVOR_salvator_h3_4x2g) || \
	defined(PLATFORM_FLAVOR_salvator_m3) || \
	defined(PLATFORM_FLAVOR_salvator_m3_2x4g) || \
	defined(PLATFORM_FLAVOR_spider_s4)
register_ddr(NSEC_DDR_0_BASE, NSEC_DDR_0_SIZE);
register_ddr(NSEC_DDR_1_BASE, NSEC_DDR_1_SIZE);
#ifdef NSEC_DDR_2_BASE
register_ddr(NSEC_DDR_2_BASE, NSEC_DDR_2_SIZE);
#endif
#ifdef NSEC_DDR_3_BASE
register_ddr(NSEC_DDR_3_BASE, NSEC_DDR_3_SIZE);
#endif
#endif

static struct scif_uart_data console_data __nex_bss;

#ifdef PRR_BASE
uint32_t rcar_prr_value __nex_bss;
#endif

void plat_console_init(void)
{
	scif_uart_init(&console_data, CONSOLE_UART_BASE);
	register_serial_console(&console_data.chip);
}

#ifdef CFG_RCAR_ROMAPI
/* Should only seed from a hardware random number generator */
static_assert(!IS_ENABLED(CFG_WITH_SOFTWARE_PRNG));

unsigned long plat_get_aslr_seed(void)
{
	unsigned long seed = 0;

	/* On RCAR we can get hw random bytes on early boot stages */
	if (crypto_rng_read(&seed, sizeof(seed)))
		panic();

	return seed;
}
#endif

void boot_primary_init_intc(void)
{
	gic_init(GICC_BASE, GICD_BASE);
}

void boot_secondary_init_intc(void)
{
	gic_init_per_cpu();
}
