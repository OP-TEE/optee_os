/*
 * Copyright (c) 2014-2016, STMicroelectronics International N.V.
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
#include <asc.h>
#include <console.h>
#include <drivers/pl011.h>
#include <io.h>
#include <kernel/generic_boot.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <kernel/pm_stubs.h>
#include <kernel/tz_ssvce_pl310.h>
#include <mm/core_mmu.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <stdint.h>
#include <tee/entry_std.h>
#include <tee/entry_fast.h>
#include <trace.h>

register_phys_mem(MEM_AREA_IO_SEC, CPU_IOMEM_BASE, CORE_MMU_DEVICE_SIZE);
register_phys_mem(MEM_AREA_IO_SEC, RNG_BASE, CORE_MMU_DEVICE_SIZE);
register_phys_mem(MEM_AREA_IO_NSEC, UART_CONSOLE_BASE, CORE_MMU_DEVICE_SIZE);

#if defined(PLATFORM_FLAVOR_b2260)
#define stm_tee_entry_std	tee_entry_std
static bool ns_resources_ready(void)
{
	return true;
}
#else
/* some nonsecure resource might not be ready (uart) */
static int boot_is_completed __early_bss;
static bool ns_resources_ready(void)
{
	return !!boot_is_completed;
}
static void stm_tee_entry_std(struct thread_smc_args *smc_args)
{
	boot_is_completed = 1;
	tee_entry_std(smc_args);
}
#endif

static void stm_fiq(void)
{
	panic();
}

static const struct thread_handlers handlers = {
	.std_smc = stm_tee_entry_std,
	.fast_smc = tee_entry_fast,
	.fiq = stm_fiq,
	.cpu_on = pm_panic,
	.cpu_off = pm_panic,
	.cpu_suspend = pm_panic,
	.cpu_resume = pm_panic,
	.system_off = pm_panic,
	.system_reset = pm_panic,
};

const struct thread_handlers *generic_boot_get_handlers(void)
{
	return &handlers;
}

static vaddr_t console_base(void)
{
	static void *va __early_bss;

	if (cpu_mmu_enabled()) {
		if (!va)
			va = phys_to_virt(UART_CONSOLE_BASE, MEM_AREA_IO_NSEC);
		return (vaddr_t)va;
	}
	return UART_CONSOLE_BASE;
}

void console_init(void)
{
}

void console_putc(int ch)
{
	if (ns_resources_ready()) {
		if (ch == '\n')
			__asc_xmit_char('\r', console_base());
		__asc_xmit_char((char)ch, console_base());
	}
}

void console_flush(void)
{
	if (ns_resources_ready())
		__asc_flush(console_base());
}

vaddr_t pl310_base(void)
{
	static void *va __early_bss;

	if (cpu_mmu_enabled()) {
		if (!va)
			va = phys_to_virt(PL310_BASE, MEM_AREA_IO_SEC);
		return (vaddr_t)va;
	}
	return PL310_BASE;
}

void arm_cl2_config(vaddr_t pl310)
{
	uint32_t v;
	/* pl310 off */
	write32(0, pl310 + PL310_CTRL);

	/*
	 * TAG RAM Control Register
	 *
	 * bit[10:8]:1 - 2 cycle of write accesses latency
	 * bit[6:4]:1 - 2 cycle of read accesses latency
	 * bit[2:0]:1 - 2 cycle of setup latency
	 */
	v = read32(pl310 + PL310_TAG_RAM_CTRL);
	v &= 0xFFFFF888;
	v |= 0xFFFFF999;
	write32(v, pl310 + PL310_TAG_RAM_CTRL);

	/*
	 * DATA RAM Control Register
	 *
	 * bit[10:8]:2 - 3 cycle of write accesses latency
	 * bit[6:4]:2 - 3 cycle of read accesses latency
	 * bit[2:0]:2 - 3 cycle of setup latency
	 */
	v = read32(pl310 + PL310_DATA_RAM_CTRL);
	v &= 0xFFFFF888;
	v |= 0xFFFFFAAA;
	write32(v, pl310 + PL310_DATA_RAM_CTRL);

	/*
	 * Auxiliary Control Register
	 *
	 * I/Dcache prefetch enabled (bit29:28=2b11)
	 * NS can access interrupts (bit27=1)
	 * NS can lockown cache lines (bit26=1)
	 * Pseudo-random replacement policy (bit25=0)
	 * Force write allocated (default)
	 * Shared attribute internally ignored (bit22=1, bit13=0)
	 * Parity disabled (bit21=0)
	 * Event monitor disabled (bit20=0)
	 * Set or preserved way config: size (bit19:17), ass (bit16)
	 * Store buffer device limitation enabled (bit11=1)
	 * Cacheable accesses have high prio (bit10=0)
	 * Full Line Zero (FLZ) disabled (bit0=0)
	 */
	v = PL310_AUX_CTRL_INIT;
	write32(v, pl310 + PL310_AUX_CTRL);

	/*
	 * Prefetch Control Register
	 *
	 * Double linefill disabled (bit30=0)
	 * I/D prefetch enabled (bit29:28=2b11)
	 * Prefetch drop enabled (bit24=1)
	 * Incr double linefill disable (bit23=0)
	 * Prefetch offset = 7 (bit4:0)
	 */
	write32(0x31000007, pl310 + PL310_PREFETCH_CTRL);

	/*
	 * Power Register
	 *
	 * Dynamic clock gating enabled
	 * Standby mode enabled
	 */
	write32(0x00000003, pl310 + PL310_POWER_CTRL);

	/* invalidate all pl310 cache ways */
	arm_cl2_invbyway(pl310);
}

void plat_cpu_reset_late(void)
{
	int i;

	assert(!cpu_mmu_enabled());

	/* Allow NSec to manage FIQ/Imprecise abort (SCR[FW]=1, SCR[AW]=1) */
	write_scr(SCR_AW | SCR_FW);

	if (get_core_pos())
		return;

	/* both secure CPU access SCU */
	write32(3, SCU_BASE + SCU_SAC);

	/* both nonsec cpu access SCU, private and global timer */
	write32(0x333, SCU_BASE + SCU_NSAC);

	/* SCU Filtering End Address register */
	write32(CPU_PORT_FILT_END, SCU_BASE + SCU_FILT_EA);
	write32(CPU_PORT_FILT_START, SCU_BASE + SCU_FILT_SA);

	/*
	 * SCU Control Register : CTRL = 0x00000065
	 * - ic stanby enable=1
	 * - scu standby enable=1
	 * - scu enable=1
	 */
	write32(0x0065, SCU_BASE + SCU_CTRL);

	/*
	 * - All external interrupts are NonSecure.
	 */
	for (i = 0; i < (31 * 4); i += 4)
		write32(0xFFFFFFFF, GIC_DIST_BASE + GIC_DIST_ISR1 + i);

	/* PL310 Memory Controller port filtering */
	write32(CPU_PORT_FILT_END, pl310_base() + PL310_ADDR_FILT_END);
	write32(CPU_PORT_FILT_START | 1, pl310_base() + PL310_ADDR_FILT_START);
}
