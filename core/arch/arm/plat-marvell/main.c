// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2017 Marvell International Ltd.
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

#include <arm.h>
#include <console.h>
#include <drivers/gic.h>
#if defined(PLATFORM_FLAVOR_armada7k8k)
#include <drivers/serial8250_uart.h>
#elif defined(PLATFORM_FLAVOR_armada3700)
#include <drivers/mvebu_uart.h>
#endif
#ifdef CFG_PL011
#include <drivers/pl011.h>
#endif
#include <io.h>
#include <keep.h>
#include <kernel/boot.h>
#include <kernel/interrupt.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <kernel/tee_common_otp.h>
#include <kernel/tee_time.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <stdint.h>
#include <string.h>

static struct gic_data gic_data;
#if defined(PLATFORM_FLAVOR_armada7k8k)
static struct serial8250_uart_data console_data;
#elif defined(PLATFORM_FLAVOR_armada3700)
static struct mvebu_uart_data console_data;
#elif CFG_PL011
static struct pl011_data console_data;
#endif

register_phys_mem_pgdir(MEM_AREA_IO_SEC, CONSOLE_UART_BASE,
			CORE_MMU_PGDIR_SIZE);
#ifdef CFG_HW_UNQ_KEY_SUPPORT
register_phys_mem(MEM_AREA_IO_SEC, PLAT_MARVELL_FUSF_FUSE_BASE,
		  SMALL_PAGE_SIZE);
#endif

#ifdef GIC_BASE
register_phys_mem_pgdir(MEM_AREA_IO_SEC, GICD_BASE, CORE_MMU_PGDIR_SIZE);
#ifdef GICC_BASE
register_phys_mem_pgdir(MEM_AREA_IO_SEC, GICC_BASE, CORE_MMU_PGDIR_SIZE);
#endif

void main_init_gic(void)
{
	vaddr_t gicd_base;
	vaddr_t gicc_base = 0;

#ifdef GICC_BASE
	gicc_base = (vaddr_t)phys_to_virt(GIC_BASE + GICC_OFFSET,
					  MEM_AREA_IO_SEC, 1);
	if (!gicc_base)
		panic();
#endif
	gicd_base = (vaddr_t)phys_to_virt(GIC_BASE + GICD_OFFSET,
					  MEM_AREA_IO_SEC, 1);
	if (!gicd_base)
		panic();

	gic_init_base_addr(&gic_data, gicc_base, gicd_base);

	itr_init(&gic_data.chip);
}
#endif

void itr_core_handler(void)
{
	gic_it_handle(&gic_data);
}

void console_init(void)
{
#if defined(PLATFORM_FLAVOR_armada7k8k)
	serial8250_uart_init(&console_data, CONSOLE_UART_BASE,
		CONSOLE_UART_CLK_IN_HZ, CONSOLE_BAUDRATE);
#elif defined(PLATFORM_FLAVOR_armada3700)
	mvebu_uart_init(&console_data, CONSOLE_UART_BASE,
		CONSOLE_UART_CLK_IN_HZ, CONSOLE_BAUDRATE);
#elif CFG_PL011
	pl011_init(&console_data, CONSOLE_UART_BASE, CONSOLE_UART_CLK_IN_HZ,
		   CONSOLE_BAUDRATE);
#endif
	register_serial_console(&console_data.chip);
}

#ifdef CFG_HW_UNQ_KEY_SUPPORT
TEE_Result tee_otp_get_hw_unique_key(struct tee_hw_unique_key *hwkey)
{
	void *huk = phys_to_virt(PLAT_MARVELL_FUSF_FUSE_BASE +
				 PLAT_MARVELL_FUSF_HUK_OFFSET,
				 MEM_AREA_IO_SEC, sizeof(hwkey->data));
	if (!huk) {
		EMSG("\nH/W Unique key is not fetched from the platform.");
		return TEE_ERROR_SECURITY;
	}

	memcpy(&hwkey->data[0], huk, sizeof(hwkey->data));
	return TEE_SUCCESS;
}
#endif
