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
#include <kernel/boot.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <stdint.h>
#include <drivers/scif.h>
#include <drivers/gic.h>
#include <rng_support.h>

register_phys_mem_pgdir(MEM_AREA_IO_SEC, CONSOLE_UART_BASE, SCIF_REG_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, PRR_BASE, SMALL_PAGE_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, GICD_BASE, GIC_DIST_REG_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, GICC_BASE, GIC_DIST_REG_SIZE);

/* Legacy platforms */
#if defined(PLATFORM_FLAVOR_salvator_h3) || \
	defined(PLATFORM_FLAVOR_salvator_h3_4x2g) || \
	defined(PLATFORM_FLAVOR_salvator_m3) || \
	defined(PLATFORM_FLAVOR_salvator_m3_2x4g)
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
uint32_t rcar_prr_value __nex_bss;

void console_init(void)
{
	scif_uart_init(&console_data, CONSOLE_UART_BASE);
	register_serial_console(&console_data.chip);
}

unsigned long plat_get_aslr_seed(void)
{
	unsigned long seed = 0;
	size_t i;

	/* On RCAR we can call hw_get_random_byte() on early boot stages */
	for (i = 0; i < sizeof(seed); i++)
		seed = (seed << 8) | hw_get_random_byte();

	return seed;
}
